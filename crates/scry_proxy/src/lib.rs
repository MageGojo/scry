//! Scry 代理层 —— **抓包内核**:HTTP/S TLS 终止式 MITM 代理(对标 Burp / mitmproxy)。
//!
//! 这是 Scry 唯一的抓包内核:谁把流量送进来不关心(scry 自启的内置浏览器 / 托管程序、
//! 手动设代理的客户端、sing-box/QX 上游链式、Proxifier 等),本层只负责**终止 TLS + 解密 +
//! 落盘(save-first)+ 交上游出网**。被动嗅探(`scry_sniff`)是看不到明文时的辅助降级路径,非内核。
//!
//! 行为:
//! - `CONNECT host:port`:回 `200`,peek 首字节;`0x16`(TLS)→ [`mitm`] 解密;否则当隧道内明文 HTTP 抓取。
//! - 明文 HTTP 代理请求(绝对 URI):转发到目标(可经上游)→**先落盘**→ 回传客户端。
//! - 上游([`upstream`]):解密后把「到目标的连接」交回 sing-box/QX 出网(墙内),目标交上游远程解析。

use anyhow::{Context, Result};
use scry_ca::Ca;
use scry_core::HttpFlow;
use scry_ext_api::{ExtensionHost, HookAction, SynthResponse};
use scry_storage::Store;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub mod fingerprint;
pub mod http2;
pub mod mitm;
pub mod replay;
pub mod tls_profile;
pub mod upstream;
pub mod websocket;

/// 多任务共享的存储句柄(rusqlite Connection 非 Sync,用 Mutex 包裹;落盘是短同步操作,不跨 await 持锁)。
pub type SharedStore = Arc<Mutex<Store>>;

/// 扩展钩子句柄:包一层 [`scry_ext_api::ExtensionHost`],给 [`ProxyConfig`] 保留 `#[derive(Debug, Clone)]`。
///
/// `ProxyConfig.hooks == None` 时代理行为与无扩展时**完全一致**(零开销 / 零行为变化)。
#[derive(Clone)]
pub struct ExtHooks(pub Arc<dyn ExtensionHost>);

impl std::fmt::Debug for ExtHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExtHooks(..)")
    }
}

/// 代理配置。
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub addr: SocketAddr,
    /// 上游读响应的超时(防 keep-alive 不关导致挂死)。
    pub upstream_timeout: Duration,
    /// CONNECT 时是否 TLS MITM 解密(true);false = 仅隧道透传(不解密)。
    pub mitm: bool,
    /// 上游代理:解密后把「到目标的连接」交给它出网(sing-box/QX 链式抓包);None = 直连。
    pub upstream: Option<upstream::UpstreamProxy>,
    /// 扩展钩子(on_request / on_flow_complete …);None = 无扩展。
    pub hooks: Option<ExtHooks>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:8888".parse().unwrap(),
            upstream_timeout: Duration::from_secs(30),
            mitm: true,
            upstream: None,
            hooks: None,
        }
    }
}

/// 启动代理并阻塞运行(在 tokio 运行时内)。
///
/// 说明:此处的「代理」只作为**本地测试 / 接入入口**(curl -x、或 Proxifier 指过来),
/// 真正的后端核心是 [`mitm`] 解密引擎;生产抓包前端(透明拦截)会复用同一个引擎。
pub async fn run(config: ProxyConfig, store: SharedStore, ca: Arc<Ca>) -> Result<()> {
    let listener = TcpListener::bind(config.addr)
        .await
        .with_context(|| format!("绑定 {} 失败", config.addr))?;
    tracing::info!(
        "scry_proxy 监听 {}(MITM={})",
        config.addr,
        config.mitm
    );
    loop {
        let (client, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("accept 失败:{e}");
                continue;
            }
        };
        let store = store.clone();
        let ca = ca.clone();
        let cfg = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(client, store, ca, cfg).await {
                tracing::debug!("连接 {peer} 处理结束:{e}");
            }
        });
    }
}

/// 处理一个客户端连接(MVP:每连接一请求)。
async fn handle_conn(
    mut client: TcpStream,
    store: SharedStore,
    ca: Arc<Ca>,
    cfg: ProxyConfig,
) -> Result<()> {
    let (head, _head_len, leftover) = read_head(&mut client).await?;

    // 解析请求行 + 头。
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let status = req
        .parse(&head)
        .context("解析 HTTP 请求失败")?;
    if status.is_partial() {
        anyhow::bail!("请求头不完整");
    }
    let method = req.method.unwrap_or("").to_string();
    let target = req.path.unwrap_or("").to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(&target, 443);
        // 先回 200,客户端(curl / Proxifier 等)才会在隧道里发后续字节。
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        // 偷看隧道内首字节(MSG_PEEK,不消费):0x16 = TLS 握手记录 → HTTPS;否则按明文 HTTP。
        // 这样 CONNECT 到 443(TLS)或 80(明文,Proxifier HTTPS 类型对 80 也走 CONNECT)都能正确处理,
        // 不再因「对明文强行 TLS 握手」而断连 —— 这正是单用一个标准 CONNECT 代理就够的关键。
        let mut peek = [0u8; 1];
        let looks_tls = matches!(client.peek(&mut peek).await, Ok(n) if n >= 1 && peek[0] == 0x16);
        if looks_tls {
            if cfg.mitm {
                // TLS MITM 解密(后端核心);200 已发,故 send_connect_ok=false。
                return mitm::intercept_https(client, host, port, false, store, ca, cfg).await;
            }
            // 不解密:纯隧道透传(200 已发)。
            return tunnel_passthrough(client, &host, port, cfg.upstream.as_ref()).await;
        }
        // 隧道内是明文 HTTP(origin-form):host/port 取自 CONNECT,按明文抓取。
        return capture_tunneled_http(client, host, port, store, cfg).await;
    }

    // 明文 HTTP 代理请求:target 是绝对 URI。
    let parsed = parse_absolute(&target)
        .with_context(|| format!("非绝对 URI 的代理请求:{target}"))?;
    proxy_plain(
        client,
        &method,
        parsed.scheme,
        parsed.host,
        parsed.port,
        parsed.path,
        &head,
        leftover,
        store,
        cfg,
    )
    .await
}

/// CONNECT 隧道纯透传(200 已由调用方发送):连目标(可经上游),双向拷贝(不解密)。
async fn tunnel_passthrough(
    mut client: TcpStream,
    host: &str,
    port: u16,
    upstream_proxy: Option<&upstream::UpstreamProxy>,
) -> Result<()> {
    let mut upstream_tcp = upstream::connect_via(host, port, upstream_proxy)
        .await
        .with_context(|| format!("连接目标 {host}:{port} 失败"))?;
    tracing::debug!("CONNECT 隧道透传 → {host}:{port}");
    tokio::io::copy_bidirectional(&mut client, &mut upstream_tcp)
        .await
        .ok();
    Ok(())
}

/// 隧道内明文 HTTP(典型:Proxifier HTTPS 类型把 80 端口也走 CONNECT)。
///
/// 200 已发、首字节已判定非 TLS。这里读隧道里的 **origin-form** HTTP 请求,host/port 取自 CONNECT,
/// 当明文 HTTP 抓取(save-first)。
async fn capture_tunneled_http(
    mut client: TcpStream,
    host: String,
    port: u16,
    store: SharedStore,
    cfg: ProxyConfig,
) -> Result<()> {
    let (head, _head_len, leftover) = read_head(&mut client).await?;
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    req.parse(&head).context("解析隧道内 HTTP 请求失败")?;
    let method = req.method.unwrap_or("").to_string();
    let path = req.path.unwrap_or("/").to_string();
    proxy_plain(
        client,
        &method,
        "http".to_string(),
        host,
        port,
        path,
        &head,
        leftover,
        store,
        cfg,
    )
    .await
}

/// 明文 HTTP 转发抓取(绝对 URI 代理请求 / 隧道内 origin-form 共用)。
///
/// host/port/scheme/path 由调用方给定;读齐 body → 连上游发 origin-form(强制 `Connection: close`)→
/// 读完整响应 → **先落盘** → 回传客户端。
#[allow(clippy::too_many_arguments)]
async fn proxy_plain(
    mut client: TcpStream,
    method: &str,
    scheme: String,
    host: String,
    port: u16,
    path: String,
    head: &[u8],
    leftover: Vec<u8>,
    store: SharedStore,
    cfg: ProxyConfig,
) -> Result<()> {
    // 重新解析头以提取请求头列表 + content-length。
    let mut hbuf = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut hbuf);
    req.parse(head).ok();
    let req_headers: Vec<(String, String)> = req
        .headers
        .iter()
        .filter(|h| !h.name.is_empty())
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).to_string(),
            )
        })
        .collect();
    let content_length = header_value(&req_headers, "content-length")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);

    // 收齐请求体。
    let mut body = leftover;
    while body.len() < content_length {
        let mut tmp = [0u8; 8192];
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }

    // 组请求侧 flow,交扩展 on_request(转发前:可改写 / 丢弃 / 短路)。
    let mut flow = HttpFlow::request(method, scheme, host.clone(), port, path, req_headers, body);
    if let Some(hooks) = cfg.hooks.as_ref() {
        match hooks.0.on_request(&mut flow) {
            HookAction::Drop => return Ok(()),
            HookAction::Respond(r) => {
                client.write_all(&build_synth_response(&r)).await?;
                client.flush().await?;
                // 仍守 save-first:记录这条被扩展短路的请求 + 合成响应。
                let f = flow.with_response(r.status, r.headers, r.body, 0);
                save_flow(&store, &f);
                hooks.0.on_flow_complete(&f);
                return Ok(());
            }
            _ => {}
        }
    }

    // 连接目标并发送 origin-form 请求(用钩子可能改过的请求部件;强制 Connection: close 逼上游 EOF)。
    let started = Instant::now();
    let mut upstream_tcp = upstream::connect_via(flow.host.as_str(), port, cfg.upstream.as_ref())
        .await
        .with_context(|| format!("连接目标 {}:{} 失败", flow.host, port))?;
    let outbound = build_origin_request(&flow.method, &flow.path, &flow.req_headers, &flow.req_body);
    upstream_tcp.write_all(&outbound).await?;
    upstream_tcp.flush().await?;

    // 读完整响应(带超时)。
    let resp_bytes = tokio::time::timeout(cfg.upstream_timeout, read_to_end(&mut upstream_tcp))
        .await
        .context("读上游响应超时")??;

    // 解析响应头 → 填入 flow → 先落盘 → 被动钩子 on_flow_complete。
    let (status_code, resp_headers, resp_body) = parse_response(&resp_bytes);
    flow.status = status_code;
    flow.resp_headers = resp_headers;
    flow.resp_body = resp_body;
    flow.duration_ms = started.elapsed().as_millis() as u64;
    save_flow(&store, &flow);
    if let Some(hooks) = cfg.hooks.as_ref() {
        hooks.0.on_flow_complete(&flow);
    }

    // 回传客户端。
    client.write_all(&resp_bytes).await?;
    client.flush().await?;
    Ok(())
}

/// 把扩展短路返回的 [`SynthResponse`] 序列化成 HTTP/1.1 响应字节。
pub(crate) fn build_synth_response(r: &SynthResponse) -> Vec<u8> {
    build_http_response(r.status, &r.headers, &r.body)
}

/// 由 (status, headers, body) 重建 HTTP/1.1 响应字节(用于扩展改写后回传)。
///
/// `body` 须为**已解 chunked、按 `Content-Encoding` 原样**的字节(= [`mitm::Msg::body`])。
/// 丢弃 `Transfer-Encoding`/`Content-Length`/`Connection`,按 body 长度重算 `Content-Length`,
/// 末尾强制 `Connection: close`(配合本代理每连接一请求)。
pub(crate) fn build_http_response(
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let reason = reason_phrase(status);
    let mut out = if reason.is_empty() {
        format!("HTTP/1.1 {status}\r\n").into_bytes()
    } else {
        format!("HTTP/1.1 {status} {reason}\r\n").into_bytes()
    };
    for (k, v) in headers {
        let lk = k.to_ascii_lowercase();
        if lk == "transfer-encoding" || lk == "content-length" || lk == "connection" {
            continue;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(body);
    out
}

/// 常见状态码原因短语(缺失返回空串,客户端可容忍无 reason)。
pub(crate) fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

/// save-first:抓到即落盘(去重由存储层负责)。
pub(crate) fn save_flow(store: &SharedStore, flow: &HttpFlow) {
    match store.lock() {
        Ok(s) => match s.save(flow) {
            Ok(true) => tracing::info!("{} {} → {}", flow.method, flow.url(), flow.status),
            Ok(false) => tracing::debug!("去重命中:{} {}", flow.method, flow.url()),
            Err(e) => tracing::warn!("落盘失败:{e}"),
        },
        Err(e) => tracing::warn!("存储锁中毒:{e}"),
    }
}

// ---------- 解析 / 读写辅助 ----------

/// 读取直到 `\r\n\r\n`,返回 (头部字节, 头长度, 头之后已读到的剩余字节)。
pub(crate) async fn read_head(stream: &mut TcpStream) -> Result<(Vec<u8>, usize, Vec<u8>)> {
    let mut buf = Vec::with_capacity(8192);
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        if let httparse::Status::Complete(n) = req.parse(&buf)? {
            let leftover = buf[n..].to_vec();
            buf.truncate(n);
            return Ok((buf, n, leftover));
        }
        let mut tmp = [0u8; 8192];
        let read = stream.read(&mut tmp).await?;
        if read == 0 {
            anyhow::bail!("连接在读到完整请求头前关闭");
        }
        buf.extend_from_slice(&tmp[..read]);
        if buf.len() > 1024 * 1024 {
            anyhow::bail!("请求头过大");
        }
    }
}

/// 读到 EOF(配合上游 Connection: close)。
pub(crate) async fn read_to_end(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8192);
    let mut tmp = [0u8; 16384];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
    }
    Ok(out)
}

/// 用解析出的部件重建 origin-form 请求字节(剔除 proxy 头,强制 Connection: close)。
pub(crate) fn build_origin_request(
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut out = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
    for (k, v) in headers {
        let lk = k.to_ascii_lowercase();
        if lk == "proxy-connection" || lk == "connection" {
            continue;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(body);
    out
}

/// 解析响应字节为 (status, headers, body)。
pub(crate) fn parse_response(bytes: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut hbuf = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut hbuf);
    match resp.parse(bytes) {
        Ok(httparse::Status::Complete(head_len)) => {
            let status = resp.code.unwrap_or(0);
            let headers = resp
                .headers
                .iter()
                .filter(|h| !h.name.is_empty())
                .map(|h| {
                    (
                        h.name.to_string(),
                        String::from_utf8_lossy(h.value).to_string(),
                    )
                })
                .collect();
            (status, headers, bytes[head_len..].to_vec())
        }
        _ => (0, Vec::new(), bytes.to_vec()),
    }
}

/// 解析出的绝对 URI 部件。
struct ParsedUri {
    scheme: String,
    host: String,
    port: u16,
    path: String,
}

/// 解析 `http://host[:port]/path?query` 形态的绝对 URI。
fn parse_absolute(uri: &str) -> Option<ParsedUri> {
    let (scheme, rest) = uri.split_once("://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let default_port = if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        80
    };
    let (host, port) = split_host_port(authority, default_port);
    Some(ParsedUri {
        scheme: scheme.to_string(),
        host,
        port,
        path,
    })
}

/// 拆 `host:port`(无端口时用默认)。
fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (authority.to_string(), default_port),
    }
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_absolute_uri() {
        let p = parse_absolute("http://example.com/a?b=1").unwrap();
        assert_eq!(p.scheme, "http");
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, 80);
        assert_eq!(p.path, "/a?b=1");

        let p2 = parse_absolute("http://h:8080/x").unwrap();
        assert_eq!(p2.port, 8080);
    }

    #[test]
    fn origin_request_strips_proxy_headers() {
        let h = vec![
            ("Host".to_string(), "h".to_string()),
            ("Proxy-Connection".to_string(), "keep-alive".to_string()),
        ];
        let out = build_origin_request("GET", "/x", &h, b"");
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("GET /x HTTP/1.1\r\n"));
        assert!(!s.to_lowercase().contains("proxy-connection"));
        assert!(s.contains("Connection: close"));
    }

    #[test]
    fn default_config_has_no_hooks() {
        let cfg = ProxyConfig::default();
        assert!(cfg.hooks.is_none());
        // Debug 仍可用(ExtHooks 手写 Debug 保住 derive)。
        assert!(format!("{cfg:?}").contains("hooks"));
    }

    #[test]
    fn ext_hooks_wraps_host_and_is_debuggable() {
        struct Noop;
        impl ExtensionHost for Noop {}
        let cfg = ProxyConfig {
            hooks: Some(ExtHooks(Arc::new(Noop))),
            ..ProxyConfig::default()
        };
        assert!(cfg.hooks.is_some());
        assert!(format!("{:?}", cfg.hooks.unwrap()).contains("ExtHooks"));
    }

    #[test]
    fn synth_response_sets_content_length_and_close() {
        let r = SynthResponse {
            status: 200,
            headers: vec![("X-Demo".into(), "1".into())],
            body: b"hi".to_vec(),
        };
        let bytes = build_synth_response(&r);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("X-Demo: 1\r\n"));
        assert!(s.contains("Content-Length: 2\r\n"));
        assert!(s.contains("Connection: close\r\n"));
        assert!(s.ends_with("\r\n\r\nhi"));
    }

    #[test]
    fn http_response_drops_chunked_and_recomputes_length() {
        // 模拟改写后:body 已 dechunk,原 headers 仍带 Transfer-Encoding + 过期 Content-Length。
        let headers = vec![
            ("Content-Type".into(), "text/plain".into()),
            ("Transfer-Encoding".into(), "chunked".into()),
            ("Content-Length".into(), "999".into()),
        ];
        let bytes = build_http_response(200, &headers, b"hello");
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Type: text/plain\r\n"));
        assert!(!s.to_lowercase().contains("transfer-encoding"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(!s.contains("999"));
        assert!(s.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn unknown_status_has_no_reason() {
        let bytes = build_http_response(799, &[], b"");
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("HTTP/1.1 799\r\n"));
        assert!(s.contains("Content-Length: 0\r\n"));
    }
}
