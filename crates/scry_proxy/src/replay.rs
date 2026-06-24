//! Repeater 重放骨架 —— 把一个(可编辑的)HTTP 请求重新发往目标,拿回响应组成新的 [`HttpFlow`]。
//!
//! 复用 MITM 引擎已落地的能力,不重复造轮子:
//! - 请求构造:[`build_origin_request`](crate::build_origin_request)(剔除 proxy 头、强制 `Connection: close` 逼上游 EOF);
//! - 响应读取:[`mitm::read_message`](crate::mitm)(Content-Length / chunked / close-delimited 都支持);
//! - HTTPS:[`mitm::build_client_config`](crate::mitm) 的 rustls 客户端(webpki 根校验),与 MITM 上游侧同一套。
//!
//! 与代理 / 透明抓包不同,Repeater 是**用户主动发起**的单次重放(可反复改包重发),因此本模块只负责
//! 「发送 → 收响应 → 组 HttpFlow」;是否落盘 / 推 UI 由调用方决定([`send`] 不落盘,[`send_and_save`] 落盘)。

use crate::mitm::{build_client_config, read_message};
use crate::upstream::{connect_via, UpstreamProxy};
use crate::{build_origin_request, save_flow, SharedStore};
use anyhow::{Context, Result};
use scry_core::{Header, HttpFlow};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

/// 一次可重放的请求 —— Repeater 的编辑单元(改完任意字段即可重发)。
#[derive(Debug, Clone)]
pub struct ReplayRequest {
    pub method: String,
    /// "http" | "https"。
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// origin-form 路径 + 查询串(如 `/api?x=1`)。
    pub path: String,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

impl ReplayRequest {
    /// 取一条已抓到的流的**请求部分**作为重放模板(随后可逐字段编辑后重发)。
    pub fn from_flow(flow: &HttpFlow) -> Self {
        Self {
            method: flow.method.clone(),
            scheme: flow.scheme.clone(),
            host: flow.host.clone(),
            port: flow.port,
            path: flow.path.clone(),
            headers: flow.req_headers.clone(),
            body: flow.req_body.clone(),
        }
    }

    /// 由完整 URL 构造重放请求(供扩展 `send_request` 用)。
    ///
    /// 解析 `scheme://host[:port]/path?query`;无 path 补 `/`,无端口按 scheme 取 80/443。
    pub fn from_url(method: &str, url: &str, headers: Vec<Header>, body: Vec<u8>) -> Option<Self> {
        let (scheme, rest) = url.split_once("://")?;
        if scheme.is_empty() || rest.is_empty() {
            return None;
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        let default_port = if scheme.eq_ignore_ascii_case("https") {
            443
        } else {
            80
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
            None => (authority.to_string(), default_port),
        };
        if host.is_empty() {
            return None;
        }
        Some(Self {
            method: method.to_string(),
            scheme: scheme.to_string(),
            host,
            port,
            path,
            headers,
            body,
        })
    }

    /// 是否 HTTPS(决定是否走 TLS)。
    pub fn is_https(&self) -> bool {
        self.scheme.eq_ignore_ascii_case("https")
    }

    /// 序列化为真正发往上游的 origin-form 请求字节(预览 / 测试用;真正发送在 [`send`] 内)。
    pub fn to_wire(&self) -> Vec<u8> {
        build_origin_request(&self.method, &self.path, &self.headers, &self.body)
    }
}

/// 重放配置(超时 + 上游代理)。
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// 建立 TCP 连接的超时。
    pub connect_timeout: Duration,
    /// 读完整响应的超时(防上游不关连接挂死)。
    pub read_timeout: Duration,
    /// 上游代理:重放也经它出网(与抓包同源,墙内才出得去);None = 直连。
    pub upstream: Option<UpstreamProxy>,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(15),
            read_timeout: Duration::from_secs(30),
            upstream: None,
        }
    }
}

/// 发送一次重放请求,返回组装好的 [`HttpFlow`](含响应)。**不落盘**(交调用方决定)。
pub async fn send(req: &ReplayRequest, cfg: &ReplayConfig) -> Result<HttpFlow> {
    let started = Instant::now();
    let outbound = req.to_wire();

    let tcp = tokio::time::timeout(
        cfg.connect_timeout,
        connect_via(req.host.as_str(), req.port, cfg.upstream.as_ref()),
    )
    .await
    .with_context(|| format!("连接 {}:{} 超时", req.host, req.port))?
    .with_context(|| format!("连接 {}:{} 失败", req.host, req.port))?;

    let resp = if req.is_https() {
        let connector = TlsConnector::from(Arc::new(build_client_config()?));
        let server_name = ServerName::try_from(req.host.clone()).context("无效 SNI(host)")?;
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .context("对上游 TLS 握手失败")?;
        tls.write_all(&outbound).await?;
        tls.flush().await?;
        tokio::time::timeout(cfg.read_timeout, read_message(&mut tls, true))
            .await
            .context("读重放响应超时")??
    } else {
        let mut tcp = tcp;
        tcp.write_all(&outbound).await?;
        tcp.flush().await?;
        tokio::time::timeout(cfg.read_timeout, read_message(&mut tcp, true))
            .await
            .context("读重放响应超时")??
    };

    Ok(HttpFlow::request(
        &req.method,
        &req.scheme,
        req.host.clone(),
        req.port,
        req.path.clone(),
        req.headers.clone(),
        req.body.clone(),
    )
    .with_response(
        resp.status,
        resp.headers.clone(),
        resp.body.clone(),
        started.elapsed().as_millis() as u64,
    ))
}

/// 发送并**落盘**(与抓包 save-first 语义一致),返回组装好的 [`HttpFlow`]。
pub async fn send_and_save(
    req: &ReplayRequest,
    cfg: &ReplayConfig,
    store: &SharedStore,
) -> Result<HttpFlow> {
    let flow = send(req, cfg).await?;
    save_flow(store, &flow);
    Ok(flow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[test]
    fn from_flow_copies_request_part() {
        let f = HttpFlow::request(
            "POST",
            "https",
            "h",
            443,
            "/x?q=1",
            vec![("Content-Type".into(), "application/json".into())],
            b"{}".to_vec(),
        )
        .with_response(200, vec![], b"resp".to_vec(), 5);
        let r = ReplayRequest::from_flow(&f);
        assert_eq!(r.method, "POST");
        assert!(r.is_https());
        assert_eq!(r.host, "h");
        assert_eq!(r.path, "/x?q=1");
        assert_eq!(r.body, b"{}");
        // 不携带响应,只取请求部分。
    }

    #[test]
    fn from_url_parses_scheme_host_port_path() {
        let r = ReplayRequest::from_url("GET", "https://example.com/a?x=1", vec![], vec![]).unwrap();
        assert_eq!(r.scheme, "https");
        assert_eq!(r.host, "example.com");
        assert_eq!(r.port, 443);
        assert_eq!(r.path, "/a?x=1");
        assert!(r.is_https());

        let r2 = ReplayRequest::from_url("POST", "http://h:8080", vec![], b"x".to_vec()).unwrap();
        assert_eq!(r2.port, 8080);
        assert_eq!(r2.path, "/");
        assert!(!r2.is_https());

        assert!(ReplayRequest::from_url("GET", "not-a-url", vec![], vec![]).is_none());
        assert!(ReplayRequest::from_url("GET", "https://", vec![], vec![]).is_none());
    }

    #[test]
    fn to_wire_is_origin_form_with_close() {
        let r = ReplayRequest {
            method: "GET".into(),
            scheme: "http".into(),
            host: "h".into(),
            port: 80,
            path: "/a".into(),
            headers: vec![("Proxy-Connection".into(), "keep-alive".into())],
            body: vec![],
        };
        let s = String::from_utf8(r.to_wire()).unwrap();
        assert!(s.starts_with("GET /a HTTP/1.1\r\n"));
        assert!(!s.to_lowercase().contains("proxy-connection"));
        assert!(s.contains("Connection: close"));
    }

    /// 用本地一次性 HTTP server 验证重放链路:发请求 → 收响应 → 组 HttpFlow。
    #[tokio::test]
    async fn replay_over_plain_http_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // 服务端:读请求头,回固定响应(Content-Length),并回显收到的方法。
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut got = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                if got.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let body = b"hello-from-server";
            let resp = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.write_all(body).await.unwrap();
            sock.flush().await.unwrap();
            String::from_utf8_lossy(&got).into_owned()
        });

        let req = ReplayRequest {
            method: "GET".into(),
            scheme: "http".into(),
            host: addr.ip().to_string(),
            port: addr.port(),
            path: "/ping".into(),
            headers: vec![("Host".into(), addr.ip().to_string())],
            body: vec![],
        };
        let flow = send(&req, &ReplayConfig::default()).await.unwrap();

        assert_eq!(flow.status, 201);
        assert_eq!(flow.method, "GET");
        assert_eq!(flow.scheme, "http");
        assert_eq!(flow.path, "/ping");
        assert_eq!(flow.resp_body, b"hello-from-server");
        assert_eq!(flow.content_type(), Some("text/plain"));

        let server_saw = server.await.unwrap();
        assert!(server_saw.starts_with("GET /ping HTTP/1.1\r\n"));
        assert!(server_saw.contains("Connection: close"));
    }
}
