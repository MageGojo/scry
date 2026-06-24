//! Scry 内核被动抓包(libpcap/BPF,类 Wireshark)。
//!
//! **不依赖 Proxifier / 不占代理位**:直接在网卡上被动嗅探。对每条 TCP 连接做**简化重组**:
//! - **HTTP(:80)**:累积请求 / 响应字节,凑齐一对完整请求 + 响应(按 Content-Length / chunked
//!   判完整)后组成 [`HttpFlow`] 落盘。
//! - **HTTPS(:443)**:被动抓不到明文,只从 ClientHello 解出 **SNI 主机名**,记一条「加密」流,
//!   提示切到 MITM 代理模式解密。
//!
//! 权限:打开 BPF 设备通常需要权限(`sudo chmod o+r /dev/bpf*`,或把 app 以 root 跑)。打不开时
//! [`run`] 返回带提示的错误,调用方可引导用户授权或改用代理模式。
//!
//! 限制(MVP):重组按到达顺序累积(不处理乱序 / 重传 / SACK);每条连接只产**第一对**完整
//! 请求/响应(keep-alive 后续请求暂略);close-delimited(无 CL 无 chunked)响应暂不产出。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, Result};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Device, Linktype};
use scry_core::HttpFlow;
use scry_storage::Store;

pub mod pcapng;

/// 与 UI / 代理共享的存储句柄。
pub type SharedStore = Arc<Mutex<Store>>;

/// 解析出的请求部件:method / path / headers / body。
type ReqParts = (String, String, Vec<(String, String)>, Vec<u8>);
/// 解析出的响应部件:status / headers / body。
type RespParts = (u16, Vec<(String, String)>, Vec<u8>);

/// 单连接重组缓冲。
struct Conn {
    /// 客户端 → 服务端(请求方向)。
    req: Vec<u8>,
    /// 服务端 → 客户端(响应方向)。
    resp: Vec<u8>,
    /// 连接首次出现时刻(粗略估算耗时用)。
    started: Instant,
    /// 最近一次活动时刻(空闲 flush / 回收判定)。
    last: Instant,
    /// 服务端口为 443(HTTPS):只抓 SNI,不做 HTTP 重组。
    is_tls: bool,
    /// HTTPS 的 SNI 流已产出(每连接一条,避免重复)。
    tls_emitted: bool,
    /// 观察到 FIN / RST:连接将关闭,可做最终 flush。
    closed: bool,
}

/// 连接四元组(以 client / server 归一,方向无关)。
#[derive(Clone, PartialEq, Eq, Hash)]
struct ConnKey {
    c_ip: IpAddr,
    c_port: u16,
    s_ip: IpAddr,
    s_port: u16,
}

/// 默认网卡名(供 UI 显示 / 传参)。
///
/// **优先「默认路由网卡」**——挂 VPN / Shadowrocket / Quantumult X 等 TUN 代理时,真正过流量的是
/// `utunN`(默认路由指向它),而非 pcap `lookup()` 返回的 `en0`。先按路由表选,失败再退回 pcap。
pub fn default_device() -> Result<String> {
    if let Some(rt) = default_route_iface() {
        return Ok(rt);
    }
    let d = Device::lookup()
        .context("查找默认网卡失败")?
        .context("没有可用网卡")?;
    Ok(d.name)
}

/// 枚举所有可选网卡名(供设置页下拉)。**默认路由网卡置顶**(它才是真正过流量的那张)。
pub fn list_devices() -> Result<Vec<String>> {
    let mut names: Vec<String> = Device::list()
        .context("枚举网卡失败")?
        .into_iter()
        .map(|d| d.name)
        .collect();
    // 把默认路由网卡(VPN 下是 utunN)顶到最前,作为默认选中项。
    let preferred = default_route_iface().or_else(|| {
        Device::lookup()
            .ok()
            .flatten()
            .map(|d| d.name)
    });
    if let Some(def) = preferred {
        if let Some(pos) = names.iter().position(|n| *n == def) {
            names.swap(0, pos);
        }
    }
    Ok(names)
}

/// macOS:取默认路由所走的网卡名(`route -n get default` 的 `interface:` 行)。
/// VPN / TUN 代理(Shadowrocket / Quantumult X)场景下通常是 `utunN`。
#[cfg(target_os = "macos")]
fn default_route_iface() -> Option<String> {
    let out = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("interface:") {
            let name = rest.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

#[cfg(not(target_os = "macos"))]
fn default_route_iface() -> Option<String> {
    None
}

/// 快速校验是否能打开 BPF 抓包(权限 / 设备可用)。打不开时返回带指引的错误。
pub fn check_available() -> Result<()> {
    let dev = Device::lookup()
        .context("查找默认网卡失败")?
        .context("没有可用网卡")?;
    let _cap = Capture::from_device(dev)
        .context("准备抓包设备失败")?
        .immediate_mode(true)
        .timeout(50)
        .open()
        .context("无法打开 BPF 设备(需要权限:点「授权抓包」或 sudo chmod o+r /dev/bpf*,或改用代理模式)")?;
    Ok(())
}

/// 启动被动抓包,阻塞运行直到 `stop` 置位。
///
/// `pcapng_out` 为 `Some(path)` 时,在 HTTP 重组之外**同时**把每个原始链路帧落一份标准 pcapng
/// (Wireshark 可直接打开,保留 L2/L3);为 `None` 则只做重组(原行为)。
pub fn run(
    iface: Option<String>,
    store: SharedStore,
    stop: Arc<AtomicBool>,
    pcapng_out: Option<std::path::PathBuf>,
) -> Result<()> {
    let dev = match iface {
        Some(name) => Device::list()
            .context("枚举网卡失败")?
            .into_iter()
            .find(|d| d.name == name)
            .with_context(|| format!("找不到网卡 {name}"))?,
        None => Device::lookup()
            .context("查找默认网卡失败")?
            .context("没有可用网卡")?,
    };

    let mut cap = Capture::from_device(dev)
        .context("准备抓包设备失败")?
        .immediate_mode(true)
        .snaplen(65535)
        .timeout(200)
        .open()
        .context("打开 BPF 抓包设备失败(需要权限:sudo chmod o+r /dev/bpf*,或改用代理模式)")?;
    let _ = cap.filter("tcp port 80 or tcp port 443", true);
    let linktype = cap.get_datalink();

    // 可选 pcapng 落盘:用抓包设备真实的 DLT(libpcap DLT 与 pcapng linktype 同值)。
    let mut pcap_writer = pcapng_out.and_then(|path| match std::fs::File::create(&path) {
        Ok(file) => match pcapng::PcapngWriter::new(
            std::io::BufWriter::new(file),
            linktype.0 as u16,
            65535,
        ) {
            Ok(w) => Some(w),
            Err(e) => {
                eprintln!("pcapng 写文件头失败:{e}");
                None
            }
        },
        Err(e) => {
            eprintln!("创建 pcapng 文件失败:{e}");
            None
        }
    });

    let mut conns: HashMap<ConnKey, Conn> = HashMap::new();
    let mut last_sweep = Instant::now();

    while !stop.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                // 原始帧先落 pcapng(L2/L3 完整保留),再做 HTTP 重组。
                if let Some(w) = pcap_writer.as_mut() {
                    let ts = packet.header.ts;
                    let micros =
                        (ts.tv_sec as u64).wrapping_mul(1_000_000).wrapping_add(ts.tv_usec as u64);
                    let _ = w.write_packet(micros, packet.data);
                }
                if let Some(seg) = parse_segment(linktype, packet.data) {
                    handle_segment(&mut conns, &store, seg);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(_) => {} // 读包瞬时错误:忽略,继续
        }
        // 周期性清扫:对久未活动的连接做最终 flush(close-delimited 响应在此产出),并回收。
        if last_sweep.elapsed() >= SWEEP_EVERY {
            sweep(&mut conns, &store);
            if let Some(w) = pcap_writer.as_mut() {
                let _ = w.flush(); // 周期刷盘,Ctrl-C / 崩溃也尽量不丢
            }
            last_sweep = Instant::now();
        }
    }
    if let Some(mut w) = pcap_writer {
        let _ = w.flush();
    }
    Ok(())
}

/// 清扫间隔。
const SWEEP_EVERY: std::time::Duration = std::time::Duration::from_secs(2);
/// 连接空闲多久后做最终 flush + 回收(close-delimited 响应靠连接静默来判完)。
const IDLE_FLUSH: std::time::Duration = std::time::Duration::from_secs(15);

/// 对空闲 / 已关闭的连接做最终 flush(允许 close-delimited 响应产出)并回收。
fn sweep(conns: &mut HashMap<ConnKey, Conn>, store: &SharedStore) {
    for conn in conns.values_mut() {
        let idle = conn.last.elapsed() >= IDLE_FLUSH;
        if (conn.closed || idle) && !conn.is_tls {
            drain_http_pairs(conn, store, true); // force_close:允许 close-delimited 产出
        }
    }
    // 回收:已关闭、或空闲超阈值、或缓冲被清空且关闭的连接。
    conns.retain(|_, c| {
        let idle = c.last.elapsed() >= IDLE_FLUSH;
        !(c.closed || idle)
    });
    // 兜底:连接表异常膨胀时,丢最久未活动的。
    if conns.len() > 8192 {
        conns.retain(|_, c| c.last.elapsed().as_secs() < 30);
    }
}

/// 一个 TCP 段的关键信息。
struct Segment {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
    /// FIN / RST:对端将关闭连接(触发最终 flush)。
    fin_or_rst: bool,
}

/// 从链路帧解出 IP + TCP + 负载(支持以太网 / BSD loopback / 裸 IP)。
fn parse_segment(lt: Linktype, data: &[u8]) -> Option<Segment> {
    let sliced = if lt == Linktype::ETHERNET {
        SlicedPacket::from_ethernet(data).ok()?
    } else if lt == Linktype::NULL || lt == Linktype::LOOP {
        // BSD loopback:前 4 字节是地址族,之后是 IP 包。
        if data.len() < 4 {
            return None;
        }
        SlicedPacket::from_ip(&data[4..]).ok()?
    } else {
        SlicedPacket::from_ip(data).ok()?
    };

    let (src_ip, dst_ip) = match sliced.net? {
        NetSlice::Ipv4(ip) => {
            let h = ip.header();
            (
                IpAddr::V4(std::net::Ipv4Addr::from(h.source())),
                IpAddr::V4(std::net::Ipv4Addr::from(h.destination())),
            )
        }
        NetSlice::Ipv6(ip) => {
            let h = ip.header();
            (
                IpAddr::V6(std::net::Ipv6Addr::from(h.source())),
                IpAddr::V6(std::net::Ipv6Addr::from(h.destination())),
            )
        }
    };

    match sliced.transport? {
        TransportSlice::Tcp(tcp) => Some(Segment {
            src_ip,
            dst_ip,
            src_port: tcp.source_port(),
            dst_port: tcp.destination_port(),
            payload: tcp.payload().to_vec(),
            fin_or_rst: tcp.fin() || tcp.rst(),
        }),
        _ => None,
    }
}

/// 把一个 TCP 段并入对应连接缓冲;HTTP 连接尽量**连续产出多对**(支持 keep-alive)。
fn handle_segment(conns: &mut HashMap<ConnKey, Conn>, store: &SharedStore, seg: Segment) {
    // 用「服务端端口=80/443」判方向。
    let (key, to_server) = if seg.dst_port == 80 || seg.dst_port == 443 {
        (
            ConnKey {
                c_ip: seg.src_ip,
                c_port: seg.src_port,
                s_ip: seg.dst_ip,
                s_port: seg.dst_port,
            },
            true,
        )
    } else if seg.src_port == 80 || seg.src_port == 443 {
        (
            ConnKey {
                c_ip: seg.dst_ip,
                c_port: seg.dst_port,
                s_ip: seg.src_ip,
                s_port: seg.src_port,
            },
            false,
        )
    } else {
        return;
    };

    let s_port = key.s_port;
    let now = Instant::now();
    let conn = conns.entry(key).or_insert_with(|| Conn {
        req: Vec::new(),
        resp: Vec::new(),
        started: now,
        last: now,
        is_tls: s_port == 443,
        tls_emitted: false,
        closed: false,
    });
    conn.last = now;
    if seg.fin_or_rst {
        conn.closed = true;
    }
    if to_server {
        conn.req.extend_from_slice(&seg.payload);
    } else {
        conn.resp.extend_from_slice(&seg.payload);
    }
    // 单连接缓冲上限,防异常连接吃内存:超限即丢缓冲并标记关闭(待回收)。
    if conn.req.len() + conn.resp.len() > 8 * 1024 * 1024 {
        conn.req.clear();
        conn.resp.clear();
        conn.closed = true;
        return;
    }

    if conn.is_tls {
        // HTTPS:被动抓不到明文,每连接只产一条 SNI「加密」流。
        if !conn.tls_emitted {
            if let Some(host) = parse_sni(&conn.req) {
                emit_tls(conn, store, host);
                conn.tls_emitted = true;
            }
        }
    } else {
        let closed = conn.closed;
        drain_http_pairs(conn, store, closed);
    }
}

/// HTTPS:从 ClientHello 解 SNI,记一条「加密」流。
fn emit_tls(conn: &Conn, store: &SharedStore, host: String) {
    let flow = HttpFlow::request(
        "CONNECT",
        "https",
        host.clone(),
        443,
        "/",
        vec![("Host".to_string(), host)],
        Vec::new(),
    )
    .with_response(
        0,
        vec![("X-Scry-Note".to_string(), "TLS encrypted".to_string())],
        "(TLS 加密 — 切到 MITM 代理模式可解密明文)".as_bytes().to_vec(),
        conn.started.elapsed().as_millis() as u64,
    );
    save(store, &flow);
}

/// 从连接缓冲里**循环**取出「完整请求 + 完整响应」对并产出(keep-alive 复用连接的多请求都能抓到)。
///
/// `force_close` 为 true 时,允许 close-delimited(无 Content-Length 无 chunked)响应把已收到的
/// 全部字节当作完整 body 产出(用于 FIN / RST / 空闲 flush)。
fn drain_http_pairs(conn: &mut Conn, store: &SharedStore, force_close: bool) {
    while let Some((req_parts, req_used)) = parse_request(&conn.req) {
        let Some((resp_parts, resp_used)) = parse_response(&conn.resp, force_close) else {
            break;
        };
        if req_used == 0 && resp_used == 0 {
            break; // 防御:不应发生(完整消息必有长度)
        }
        let (method, path, req_headers, req_body) = req_parts;
        let (status, resp_headers, resp_body) = resp_parts;
        let host = header_get(&req_headers, "host")
            .map(|h| h.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let flow = HttpFlow::request(method, "http", host, 80, path, req_headers, req_body)
            .with_response(
                status,
                resp_headers,
                resp_body,
                conn.started.elapsed().as_millis() as u64,
            );
        save(store, &flow);
        conn.req.drain(..req_used);
        conn.resp.drain(..resp_used);
    }
}

/// 解析连接缓冲**最前面**的一条完整 HTTP 请求。返回 (部件, 已消费字节数);尚不完整 → None。
fn parse_request(buf: &[u8]) -> Option<(ReqParts, usize)> {
    let mut hbuf = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut hbuf);
    let head_len = match req.parse(buf).ok()? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return None,
    };
    let method = req.method?.to_string();
    let path = req.path?.to_string();
    let headers = collect_headers(req.headers);
    let cl = header_get(&headers, "content-length")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let body_avail = &buf[head_len..];
    if body_avail.len() < cl {
        return None; // body 还没收齐
    }
    Some(((method, path, headers, body_avail[..cl].to_vec()), head_len + cl))
}

/// 解析连接缓冲**最前面**的一条完整 HTTP 响应。返回 (部件, 已消费字节数);尚不完整 → None。
///
/// `force_close`:连接将关闭时,允许 close-delimited 响应把已到字节当完整 body。
fn parse_response(buf: &[u8], force_close: bool) -> Option<(RespParts, usize)> {
    let mut hbuf = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut hbuf);
    let head_len = match resp.parse(buf).ok()? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return None,
    };
    let status = resp.code?;
    let headers = collect_headers(resp.headers);
    let body = &buf[head_len..];

    // 1) Content-Length:body 收齐才算完整。
    if let Some(cl) = header_get(&headers, "content-length").and_then(|v| v.trim().parse::<usize>().ok())
    {
        if body.len() < cl {
            return None;
        }
        return Some(((status, headers, body[..cl].to_vec()), head_len + cl));
    }
    // 2) 明确无 body 的响应:1xx / 204 / 304 → 头完即完整(空 body)。
    if status == 204 || status == 304 || (100..200).contains(&status) {
        return Some(((status, headers, Vec::new()), head_len));
    }
    // 3) chunked:按块跳读求出完整长度(不再逐字节扫,去掉 O(n²))。落盘存**原始带框架字节**,
    //    展示层(scry_decode)再去框架。
    if header_get(&headers, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        let clen = chunked_len(body)?; // 不完整 → None
        return Some(((status, headers, body[..clen].to_vec()), head_len + clen));
    }
    // 4) close-delimited(无 CL 无 chunked):仅连接将关闭时,把已收到的全部 body 当完整。
    if force_close {
        return Some(((status, headers, body.to_vec()), head_len + body.len()));
    }
    None
}

/// 求 chunked body 的完整字节长度(含末块与终止 CRLF);不完整 / 非法 → None。按块跳读,高效。
fn chunked_len(body: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    loop {
        let rel = find_crlf(body.get(i..)?)?;
        let line_end = i + rel;
        let size_hex = std::str::from_utf8(&body[i..line_end])
            .ok()?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        if size_hex.is_empty() {
            return None;
        }
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        let data_start = line_end + 2;
        if size == 0 {
            // 末块后:跳过可能的 trailer,到终止 CRLF。
            let rel2 = find_crlf(body.get(data_start..)?)?;
            return Some(data_start + rel2 + 2);
        }
        let data_end = data_start.checked_add(size)?;
        if data_end + 2 > body.len() {
            return None; // 数据 + 尾随 CRLF 还没到齐
        }
        if &body[data_end..data_end + 2] != b"\r\n" {
            return None;
        }
        i = data_end + 2;
    }
}

/// 找 `\r\n` 的起始位置。
fn find_crlf(b: &[u8]) -> Option<usize> {
    b.windows(2).position(|w| w == b"\r\n")
}

fn collect_headers(hs: &[httparse::Header<'_>]) -> Vec<(String, String)> {
    hs.iter()
        .filter(|h| !h.name.is_empty())
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).to_string(),
            )
        })
        .collect()
}

fn header_get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn save(store: &SharedStore, flow: &HttpFlow) {
    if let Ok(s) = store.lock() {
        let _ = s.save(flow);
    }
}

/// 极简 TLS ClientHello SNI 解析:扫到 server_name 扩展取主机名。容错优先,失败回 None。
fn parse_sni(buf: &[u8]) -> Option<String> {
    // TLS record: type(0x16 handshake) ver(2) len(2)
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let rec = buf.get(5..5 + rec_len.min(buf.len().saturating_sub(5)))?;
    // Handshake: type(0x01 ClientHello) len(3)
    if rec.len() < 4 || rec[0] != 0x01 {
        return None;
    }
    let mut p = 4usize; // 跳过 handshake 头
    p += 2; // client_version
    p += 32; // random
    // session_id
    let sid_len = *rec.get(p)? as usize;
    p += 1 + sid_len;
    // cipher_suites
    let cs_len = u16::from_be_bytes([*rec.get(p)?, *rec.get(p + 1)?]) as usize;
    p += 2 + cs_len;
    // compression_methods
    let cm_len = *rec.get(p)? as usize;
    p += 1 + cm_len;
    // extensions
    if p + 2 > rec.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([rec[p], rec[p + 1]]) as usize;
    p += 2;
    let ext_end = (p + ext_total).min(rec.len());
    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([rec[p], rec[p + 1]]);
        let ext_len = u16::from_be_bytes([rec[p + 2], rec[p + 3]]) as usize;
        p += 4;
        if ext_type == 0x0000 {
            // server_name extension: list_len(2) name_type(1) name_len(2) name...
            let e = &rec.get(p..(p + ext_len).min(rec.len()))?;
            if e.len() >= 5 {
                let name_len = u16::from_be_bytes([e[3], e[4]]) as usize;
                let name = e.get(5..5 + name_len.min(e.len().saturating_sub(5)))?;
                return String::from_utf8(name.to_vec()).ok();
            }
            return None;
        }
        p += ext_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_parse_minimal_client_hello() {
        // 极简构造一个带 SNI=ab.com 的 ClientHello(够 parse_sni 走通)。
        let host = b"ab.com";
        let sni_ext_body = {
            let mut v = Vec::new();
            let name_len = host.len() as u16;
            let list_len = name_len + 3;
            v.extend_from_slice(&list_len.to_be_bytes());
            v.push(0); // name_type host_name
            v.extend_from_slice(&name_len.to_be_bytes());
            v.extend_from_slice(host);
            v
        };
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes()); // ext type server_name
        ext.extend_from_slice(&(sni_ext_body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_ext_body);

        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]); // version
        hs_body.extend_from_slice(&[0u8; 32]); // random
        hs_body.push(0); // session id len
        hs_body.extend_from_slice(&0u16.to_be_bytes()); // cipher suites len 0
        hs_body.push(0); // compression len 0
        hs_body.extend_from_slice(&(ext.len() as u16).to_be_bytes()); // extensions total
        hs_body.extend_from_slice(&ext);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let l = hs_body.len() as u32;
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&hs_body);

        let mut rec = Vec::new();
        rec.push(0x16); // handshake
        rec.extend_from_slice(&[0x03, 0x01]); // record version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        assert_eq!(parse_sni(&rec).as_deref(), Some("ab.com"));
    }

    #[test]
    fn reassemble_http_flow_end_to_end() {
        use std::net::Ipv4Addr;
        let store: SharedStore = Arc::new(Mutex::new(Store::open_memory().unwrap()));
        let mut conns = HashMap::new();
        let c = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let s = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        handle_segment(
            &mut conns,
            &store,
            Segment {
                src_ip: c,
                dst_ip: s,
                src_port: 50000,
                dst_port: 80,
                payload: b"GET /hi HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
                fin_or_rst: false,
            },
        );
        handle_segment(
            &mut conns,
            &store,
            Segment {
                src_ip: s,
                dst_ip: c,
                src_port: 80,
                dst_port: 50000,
                payload: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".to_vec(),
                fin_or_rst: false,
            },
        );
        let flows = store.lock().unwrap().recent(10).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].method, "GET");
        assert_eq!(flows[0].host, "example.com");
        assert_eq!(flows[0].status, 200);
        assert_eq!(flows[0].resp_body, b"hi");
    }

    #[test]
    fn reassemble_keepalive_two_pairs() {
        use std::net::Ipv4Addr;
        let store: SharedStore = Arc::new(Mutex::new(Store::open_memory().unwrap()));
        let mut conns = HashMap::new();
        let c = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let s = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let to_s = |payload: &[u8]| Segment {
            src_ip: c,
            dst_ip: s,
            src_port: 50001,
            dst_port: 80,
            payload: payload.to_vec(),
            fin_or_rst: false,
        };
        let to_c = |payload: &[u8]| Segment {
            src_ip: s,
            dst_ip: c,
            src_port: 80,
            dst_port: 50001,
            payload: payload.to_vec(),
            fin_or_rst: false,
        };
        // 同一连接上两个 keep-alive 请求 / 响应。
        handle_segment(&mut conns, &store, to_s(b"GET /a HTTP/1.1\r\nHost: ex.com\r\n\r\n"));
        handle_segment(&mut conns, &store, to_c(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"));
        handle_segment(&mut conns, &store, to_s(b"GET /b HTTP/1.1\r\nHost: ex.com\r\n\r\n"));
        handle_segment(&mut conns, &store, to_c(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB"));

        let flows = store.lock().unwrap().recent(10).unwrap();
        assert_eq!(flows.len(), 2, "keep-alive 两对都应抓到");
    }

    #[test]
    fn close_delimited_emitted_on_fin() {
        use std::net::Ipv4Addr;
        let store: SharedStore = Arc::new(Mutex::new(Store::open_memory().unwrap()));
        let mut conns = HashMap::new();
        let c = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let s = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        handle_segment(
            &mut conns,
            &store,
            Segment {
                src_ip: c,
                dst_ip: s,
                src_port: 50002,
                dst_port: 80,
                payload: b"GET /c HTTP/1.1\r\nHost: ex.com\r\n\r\n".to_vec(),
                fin_or_rst: false,
            },
        );
        // 无 Content-Length 无 chunked 的响应:未关闭前不产出。
        handle_segment(
            &mut conns,
            &store,
            Segment {
                src_ip: s,
                dst_ip: c,
                src_port: 80,
                dst_port: 50002,
                payload: b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nclose-body".to_vec(),
                fin_or_rst: false,
            },
        );
        assert_eq!(store.lock().unwrap().recent(10).unwrap().len(), 0);
        // 带 FIN 的尾包:触发最终 flush → close-delimited 产出。
        handle_segment(
            &mut conns,
            &store,
            Segment {
                src_ip: s,
                dst_ip: c,
                src_port: 80,
                dst_port: 50002,
                payload: Vec::new(),
                fin_or_rst: true,
            },
        );
        let flows = store.lock().unwrap().recent(10).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].resp_body, b"close-body");
    }

    #[test]
    fn reassemble_tls_sni_flow() {
        use std::net::Ipv4Addr;
        // 复用上面构造 ClientHello 的逻辑产 SNI=ab.com。
        let host = b"ab.com";
        let sni_ext_body = {
            let mut v = Vec::new();
            let name_len = host.len() as u16;
            v.extend_from_slice(&(name_len + 3).to_be_bytes());
            v.push(0);
            v.extend_from_slice(&name_len.to_be_bytes());
            v.extend_from_slice(host);
            v
        };
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&(sni_ext_body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_ext_body);
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]);
        hs_body.extend_from_slice(&[0u8; 32]);
        hs_body.push(0);
        hs_body.extend_from_slice(&0u16.to_be_bytes());
        hs_body.push(0);
        hs_body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs_body.extend_from_slice(&ext);
        let mut hs = vec![0x01];
        let l = hs_body.len() as u32;
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&hs_body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        let store: SharedStore = Arc::new(Mutex::new(Store::open_memory().unwrap()));
        let mut conns = HashMap::new();
        handle_segment(
            &mut conns,
            &store,
            Segment {
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                src_port: 51000,
                dst_port: 443,
                payload: rec,
                fin_or_rst: false,
            },
        );
        let flows = store.lock().unwrap().recent(10).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].scheme, "https");
        assert_eq!(flows[0].host, "ab.com");
        assert_eq!(flows[0].status, 0);
    }

    #[test]
    fn http_request_response_pair() {
        let req = b"GET /hello HTTP/1.1\r\nHost: x.com\r\n\r\n";
        let ((m, p, h, _b), req_used) = parse_request(req).unwrap();
        assert_eq!(m, "GET");
        assert_eq!(p, "/hello");
        assert_eq!(header_get(&h, "host"), Some("x.com"));
        assert_eq!(req_used, req.len());

        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        let ((s, _hh, body), resp_used) = parse_response(resp, false).unwrap();
        assert_eq!(s, 200);
        assert_eq!(body, b"hi");
        assert_eq!(resp_used, resp.len());

        // 半包响应:不产出。
        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi";
        assert!(parse_response(partial, false).is_none());
    }

    #[test]
    fn chunked_length_and_close_delimited() {
        // chunked:完整长度 = 整段(含末块)。
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let ((status, _h, body), used) = parse_response(resp, false).unwrap();
        assert_eq!(status, 200);
        assert_eq!(used, resp.len());
        // 落盘存原始带框架字节(展示层去框架)。
        assert!(body.windows(4).any(|w| w == b"Wiki"));

        // 未收齐的 chunked:不产出。
        let partial = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWi";
        assert!(parse_response(partial, false).is_none());

        // close-delimited:非强制不产出,强制(关闭)才产出。
        let cd = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nthe-body";
        assert!(parse_response(cd, false).is_none());
        let ((_s, _hh, b2), _u) = parse_response(cd, true).unwrap();
        assert_eq!(b2, b"the-body");
    }
}
