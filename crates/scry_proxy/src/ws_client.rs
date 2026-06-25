//! WebSocket 客户端 —— **WS 重放(Repeater)** 用:主动建立一条 WS 连接(`ws://` / `wss://`,
//! 可经上游代理),双向收发帧。区别于 [`crate::websocket`](被动抓包,只「看懂」转发字节):
//! 本模块**主动发起**握手 + 编码客户端帧(必须 mask)+ 持续收发,像 Postman/Reqable 的 WS 工具。
//!
//! 复用已有件:连接走 [`connect_via`](crate::upstream)(含上游),TLS 走
//! [`build_client_config`](crate::mitm) 同一套 rustls;帧解码 / 聚合复用 [`crate::websocket`]。
//!
//! 通信模型(配合 GUI):
//! - UI → 会话:`WsCommand`(发文本 / 二进制 / ping / 关闭),走 `tokio` 无界通道(非阻塞 `send`);
//! - 会话 → UI:`WsEvent`(已连接 / 收发到一条消息 / 关闭 / 错误),走 `std` 通道(UI 定时 `try_recv`)。

use crate::mitm::build_client_config;
use crate::upstream::{connect_via, UpstreamProxy};
use crate::websocket::{Assembler, FrameDecoder, OpCode};
use anyhow::{bail, Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

/// WS 重放会话配置。
#[derive(Debug, Clone)]
pub struct WsClientConfig {
    /// 目标 URL:`ws://host[:port]/path` 或 `wss://…`(也容忍 http/https)。
    pub url: String,
    /// 额外请求头(Cookie / Origin / Sec-WebSocket-Protocol 等);冲突的握手头会被忽略。
    pub headers: Vec<(String, String)>,
    /// 上游代理(与抓包 / 重放同源出网);None = 直连。
    pub upstream: Option<UpstreamProxy>,
    /// 建立 TCP 连接超时。
    pub connect_timeout: Duration,
}

impl Default for WsClientConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            headers: Vec::new(),
            upstream: None,
            connect_timeout: Duration::from_secs(15),
        }
    }
}

/// UI → 会话:待发送的命令。
#[derive(Debug, Clone)]
pub enum WsCommand {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    /// 主动关闭连接(发 Close 帧后结束会话)。
    Close,
}

/// 会话 → UI:事件。
#[derive(Debug, Clone)]
pub enum WsEvent {
    /// 握手成功(101)。
    Connected { status: u16 },
    /// 收发到一条消息:`outgoing=true` 为本端发出,`false` 为对端发来。
    Message {
        outgoing: bool,
        /// opcode 文本标签(Text/Binary/Ping/Pong/Close)。
        opcode: String,
        payload: Vec<u8>,
    },
    /// 连接已关闭(附原因)。
    Closed(String),
    /// 出错(握手失败 / 连接失败 / IO 错误)。
    Error(String),
}

/// WS 帧 GUID(RFC 6455 §1.3):算 `Sec-WebSocket-Accept` 用。
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// 解析 WS URL → `(secure, host, port, path)`。容忍 `ws/wss/http/https`;非法返回 `None`。
fn parse_ws_url(url: &str) -> Option<(bool, String, u16, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let secure = match scheme.to_ascii_lowercase().as_str() {
        "wss" | "https" => true,
        "ws" | "http" => false,
        _ => return None,
    };
    if rest.is_empty() {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let default_port = if secure { 443 } else { 80 };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (authority.to_string(), default_port),
    };
    if host.is_empty() {
        return None;
    }
    Some((secure, host, port, path))
}

/// 标准 Base64 编码(无换行)。WS key(16B→24)/ accept(20B→28)用。
fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// SHA-1 摘要(`Sec-WebSocket-Accept` 校验用)。
fn sha1(data: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(data);
    let r = h.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&r);
    out
}

/// 进程级随机字节(WS key / 帧 mask key 用;非密码学强度,只需每次不同)。
fn rand_bytes<const N: usize>() -> [u8; N] {
    use std::hash::{BuildHasher, Hasher};
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_usize(i);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let v = h.finish() ^ nanos.rotate_left(i as u32 * 8);
        for b in v.to_le_bytes() {
            if i < N {
                out[i] = b;
                i += 1;
            }
        }
    }
    out
}

/// 编码一个**客户端**帧(FIN=1,必须 mask,RFC 6455 §5.3)。
fn encode_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mask = rand_bytes::<4>();
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | (opcode & 0x0f)); // FIN=1
    let len = payload.len();
    if len <= 125 {
        out.push(0x80 | len as u8);
    } else if len <= 0xffff {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        out.push(b ^ mask[i % 4]);
    }
    out
}

/// 找 `\r\n\r\n`(握手响应头结束)。
fn find_double_crlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

/// 读握手响应头,返回 `(status, headers, leftover)`;leftover = 头之后多读到的字节(可能含首个 WS 帧)。
async fn read_handshake_response<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            bail!("握手期间连接被关闭");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_double_crlf(&buf) {
            let head = &buf[..pos + 4];
            let mut hb = [httparse::EMPTY_HEADER; 64];
            let mut resp = httparse::Response::new(&mut hb);
            resp.parse(head).context("解析 WS 握手响应失败")?;
            let status = resp.code.unwrap_or(0);
            let headers = resp
                .headers
                .iter()
                .filter(|h| !h.name.is_empty())
                .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).to_string()))
                .collect();
            let leftover = buf[pos + 4..].to_vec();
            return Ok((status, headers, leftover));
        }
        if buf.len() > 64 * 1024 {
            bail!("握手响应过大(无 \\r\\n\\r\\n)");
        }
    }
}

/// 排空解码器里的完整帧:聚合成消息上报 UI;ping 自动回 pong;遇 Close 上报并返回 `false`(应结束)。
async fn drain_frames<S: AsyncWrite + Unpin>(
    decoder: &mut FrameDecoder,
    assembler: &mut Assembler,
    stream: &mut S,
    evt_tx: &std::sync::mpsc::Sender<WsEvent>,
) -> Result<bool> {
    while let Some(frame) = decoder.next_frame() {
        let is_ping = frame.opcode == OpCode::Ping;
        let ping_payload = if is_ping { frame.payload.clone() } else { Vec::new() };
        if let Some(msg) = assembler.push(frame) {
            let is_close = msg.opcode == OpCode::Close;
            let _ = evt_tx.send(WsEvent::Message {
                outgoing: false,
                opcode: msg.opcode.label().to_string(),
                payload: msg.payload,
            });
            if is_close {
                let _ = stream.write_all(&encode_frame(0x8, &[])).await;
                let _ = stream.flush().await;
                let _ = evt_tx.send(WsEvent::Closed("对端发送 Close".into()));
                return Ok(false);
            }
        }
        if is_ping {
            // 自动回 pong 保活(RFC 6455 §5.5.2)。
            stream.write_all(&encode_frame(0xA, &ping_payload)).await?;
            stream.flush().await?;
        }
    }
    Ok(true)
}

/// 在已建立的流上跑完整 WS 会话:握手 → 双向收发循环。错误以 [`WsEvent::Error`] 上报。
#[allow(clippy::too_many_arguments)]
async fn run_ws<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    secure: bool,
    host: String,
    port: u16,
    path: String,
    headers: Vec<(String, String)>,
    mut cmd_rx: UnboundedReceiver<WsCommand>,
    evt_tx: std::sync::mpsc::Sender<WsEvent>,
) {
    if let Err(e) =
        run_ws_inner(&mut stream, secure, &host, port, &path, &headers, &mut cmd_rx, &evt_tx).await
    {
        let _ = evt_tx.send(WsEvent::Error(format!("{e:#}")));
    }
    let _ = stream.shutdown().await;
}

#[allow(clippy::too_many_arguments)]
async fn run_ws_inner<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    secure: bool,
    host: &str,
    port: u16,
    path: &str,
    headers: &[(String, String)],
    cmd_rx: &mut UnboundedReceiver<WsCommand>,
    evt_tx: &std::sync::mpsc::Sender<WsEvent>,
) -> Result<()> {
    // ── 握手 ──
    let key = b64_encode(&rand_bytes::<16>());
    let host_hdr = if (secure && port == 443) || (!secure && port == 80) {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_hdr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
    );
    for (k, v) in headers {
        let kl = k.to_ascii_lowercase();
        if matches!(
            kl.as_str(),
            "host"
                | "upgrade"
                | "connection"
                | "sec-websocket-key"
                | "sec-websocket-version"
                | "content-length"
        ) {
            continue; // 握手必备头由本函数掌控,忽略用户重复 / 冲突项
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let (status, resp_headers, leftover) = read_handshake_response(stream).await?;
    if status != 101 {
        bail!("WS 握手失败:服务器回 {status}(期望 101 Switching Protocols)");
    }
    // 若服务器回了 Accept 则校验(防错连;缺省则容忍)。
    if let Some(acc) = resp_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-accept"))
        .map(|(_, v)| v)
    {
        let expect = b64_encode(&sha1(format!("{key}{WS_GUID}").as_bytes()));
        if acc.trim() != expect {
            bail!("Sec-WebSocket-Accept 校验失败(握手被篡改 / 非 WS 服务器)");
        }
    }
    let _ = evt_tx.send(WsEvent::Connected { status });

    // ── 收发循环 ──
    let mut decoder = FrameDecoder::new();
    let mut assembler = Assembler::new();
    decoder.feed(&leftover);
    if !drain_frames(&mut decoder, &mut assembler, stream, evt_tx).await? {
        return Ok(());
    }

    let mut rbuf = [0u8; 16384];
    loop {
        tokio::select! {
            biased;
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(WsCommand::Text(s)) => {
                        stream.write_all(&encode_frame(0x1, s.as_bytes())).await?;
                        stream.flush().await?;
                        let _ = evt_tx.send(WsEvent::Message { outgoing: true, opcode: "Text".into(), payload: s.into_bytes() });
                    }
                    Some(WsCommand::Binary(b)) => {
                        stream.write_all(&encode_frame(0x2, &b)).await?;
                        stream.flush().await?;
                        let _ = evt_tx.send(WsEvent::Message { outgoing: true, opcode: "Binary".into(), payload: b });
                    }
                    Some(WsCommand::Ping(b)) => {
                        stream.write_all(&encode_frame(0x9, &b)).await?;
                        stream.flush().await?;
                        let _ = evt_tx.send(WsEvent::Message { outgoing: true, opcode: "Ping".into(), payload: b });
                    }
                    Some(WsCommand::Close) | None => {
                        stream.write_all(&encode_frame(0x8, &[])).await?;
                        stream.flush().await?;
                        let _ = evt_tx.send(WsEvent::Closed("已主动断开".into()));
                        return Ok(());
                    }
                }
            }
            r = stream.read(&mut rbuf) => {
                let n = r?;
                if n == 0 {
                    let _ = evt_tx.send(WsEvent::Closed("服务器关闭了连接".into()));
                    return Ok(());
                }
                decoder.feed(&rbuf[..n]);
                if !drain_frames(&mut decoder, &mut assembler, stream, evt_tx).await? {
                    return Ok(());
                }
            }
        }
    }
}

/// 跑一条 WS 重放会话:解析 URL → 连接(可经上游 / TLS)→ 握手 → 双向收发。**阻塞至会话结束**。
///
/// 在后台 tokio 运行时里调用;`cmd_rx` 收 UI 指令,`evt_tx` 把事件推给 UI(UI 端 `try_recv` 轮询)。
pub async fn run_session(
    cfg: WsClientConfig,
    cmd_rx: UnboundedReceiver<WsCommand>,
    evt_tx: std::sync::mpsc::Sender<WsEvent>,
) {
    let (secure, host, port, path) = match parse_ws_url(&cfg.url) {
        Some(x) => x,
        None => {
            let _ = evt_tx.send(WsEvent::Error(format!(
                "无效 WS URL:{}(应以 ws:// 或 wss:// 开头)",
                cfg.url
            )));
            return;
        }
    };

    let tcp = match tokio::time::timeout(
        cfg.connect_timeout,
        connect_via(&host, port, cfg.upstream.as_ref()),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let _ = evt_tx.send(WsEvent::Error(format!("连接 {host}:{port} 失败:{e:#}")));
            return;
        }
        Err(_) => {
            let _ = evt_tx.send(WsEvent::Error(format!("连接 {host}:{port} 超时")));
            return;
        }
    };

    if secure {
        let cfg_tls = match build_client_config() {
            Ok(c) => c,
            Err(e) => {
                let _ = evt_tx.send(WsEvent::Error(format!("TLS 配置失败:{e:#}")));
                return;
            }
        };
        let server_name = match ServerName::try_from(host.clone()) {
            Ok(n) => n,
            Err(_) => {
                let _ = evt_tx.send(WsEvent::Error(format!("无效 SNI:{host}")));
                return;
            }
        };
        let tls = match TlsConnector::from(Arc::new(cfg_tls)).connect(server_name, tcp).await {
            Ok(s) => s,
            Err(e) => {
                let _ = evt_tx.send(WsEvent::Error(format!("TLS 握手失败:{e:#}")));
                return;
            }
        };
        run_ws(tls, secure, host, port, path, cfg.headers, cmd_rx, evt_tx).await;
    } else {
        run_ws(tcp, secure, host, port, path, cfg.headers, cmd_rx, evt_tx).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[test]
    fn parse_url_variants() {
        assert_eq!(
            parse_ws_url("ws://h/chat"),
            Some((false, "h".into(), 80, "/chat".into()))
        );
        assert_eq!(
            parse_ws_url("wss://h:9000/x?a=1"),
            Some((true, "h".into(), 9000, "/x?a=1".into()))
        );
        assert_eq!(
            parse_ws_url("wss://h"),
            Some((true, "h".into(), 443, "/".into()))
        );
        assert!(parse_ws_url("ftp://h").is_none());
        assert!(parse_ws_url("not-a-url").is_none());
    }

    /// RFC 6455 §1.3 官方向量:key + GUID → Accept。
    #[test]
    fn rfc6455_accept_vector() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = b64_encode(&sha1(format!("{key}{WS_GUID}").as_bytes()));
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn b64_known_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
    }

    /// 编码的客户端帧应被 [`FrameDecoder`] 正确解回(且确为 masked)。
    #[test]
    fn encode_frame_roundtrips_via_decoder() {
        let bytes = encode_frame(0x1, b"hello ws");
        assert_eq!(bytes[1] & 0x80, 0x80, "客户端帧必须 mask");
        let mut d = FrameDecoder::new();
        d.feed(&bytes);
        let f = d.next_frame().unwrap();
        assert_eq!(f.opcode, OpCode::Text);
        assert_eq!(f.payload, b"hello ws");
    }

    fn server_text_frame(p: &[u8]) -> Vec<u8> {
        let mut o = vec![0x81u8, p.len() as u8]; // FIN+Text, unmasked, len<=125
        o.extend_from_slice(p);
        o
    }

    /// 端到端:本地假 WS 服务器完成握手 + 下发一帧 + 收一帧,验证 `run_session` 双向链路。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ws_session_handshake_and_echo() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // 读握手头,取出 client key。
            let mut buf = [0u8; 1024];
            let mut got = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                got.extend_from_slice(&buf[..n]);
                if find_double_crlf(&got).is_some() {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&got);
            let key = text
                .lines()
                .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
                .unwrap()
                .trim()
                .to_string();
            let accept = b64_encode(&sha1(format!("{key}{WS_GUID}").as_bytes()));
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.write_all(&server_text_frame(b"hi")).await.unwrap();
            sock.flush().await.unwrap();
            // 读客户端发来的一帧(masked),解码返回其 payload。
            let n = sock.read(&mut buf).await.unwrap();
            let mut d = FrameDecoder::new();
            d.feed(&buf[..n]);
            d.next_frame().unwrap().payload
        });

        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let (evt_tx, evt_rx) = std::sync::mpsc::channel::<WsEvent>();
        let cfg = WsClientConfig {
            url: format!("ws://{addr}/chat"),
            ..Default::default()
        };
        let sess = tokio::spawn(run_session(cfg, cmd_rx, evt_tx));

        let recv = |rx: &std::sync::mpsc::Receiver<WsEvent>| {
            rx.recv_timeout(Duration::from_secs(3)).expect("等待事件超时")
        };
        assert!(matches!(recv(&evt_rx), WsEvent::Connected { status: 101 }));
        match recv(&evt_rx) {
            WsEvent::Message { outgoing: false, opcode, payload } => {
                assert_eq!(opcode, "Text");
                assert_eq!(payload, b"hi");
            }
            other => panic!("期望服务器消息,得到 {other:?}"),
        }

        cmd_tx.send(WsCommand::Text("yo".into())).unwrap();
        let server_got = srv.await.unwrap();
        assert_eq!(server_got, b"yo", "服务器应收到客户端 masked 帧解出的 yo");

        cmd_tx.send(WsCommand::Close).ok();
        let _ = sess.await;
    }
}
