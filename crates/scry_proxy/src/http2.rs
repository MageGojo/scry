//! HTTP/2 MITM 转发(h2 多路复用)。
//!
//! 触发条件:[`crate::mitm::intercept_https`] 在 TLS 握手后发现**上游协商成 h2**。由于 server 端
//! ALPN 跟随上游(见 mitm 握手顺序),此时**两端同为 h2**,故只需 h2↔h2,无需 h1/h2 跨协议桥接。
//!
//! 做法:用 [`h2`] 同时做 h2 服务端(对客户端)与 h2 客户端(对上游),把每个 stream 的请求/响应
//! 转成一条 [`HttpFlow`] **先落盘**(save-first)再转发。h2 多路复用 = 一个 TCP 连接并发多条 stream,
//! 每条 stream 一条 flow,各自 `tokio::spawn` 处理。
//!
//! 限制(初版):h2 路径只做**抓取 + 被动钩子**(`on_flow_complete`);改包(`on_request`)与 h2 内的
//! WebSocket(Extended CONNECT)留待后续。

use crate::{save_flow, ProxyConfig, SharedStore};
use anyhow::{Context, Result};
use bytes::Bytes;
use scry_ext_api::HookAction;
use scry_core::HttpFlow;
use std::time::Instant;

/// 接管一对已协商成 h2 的连接(对客户端做 h2 服务端、对上游做 h2 客户端),做 h2↔h2 多路复用代理。
///
/// 连接类型泛型化:生产用 `tokio_rustls` 的 TLS 流;单测用 `tokio::io::duplex` 内存双工流直连验证。
pub(crate) async fn handle_h2<C, U>(
    client_io: C,
    upstream_io: U,
    host: String,
    port: u16,
    store: SharedStore,
    cfg: ProxyConfig,
) -> Result<()>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // 上游:h2 客户端握手 + 后台驱动连接(读写帧、流控、ping)。
    let (send_req, connection) = h2::client::handshake(upstream_io)
        .await
        .context("上游 h2 握手失败")?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    // 客户端:h2 服务端握手。
    let mut server = h2::server::handshake(client_io)
        .await
        .context("客户端 h2 握手失败")?;

    // 逐 stream 接收(并发多条,各自 spawn)。
    while let Some(accepted) = server.accept().await {
        let (request, respond) = match accepted {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("h2 accept stream 失败:{e}");
                break;
            }
        };
        let send_req = send_req.clone();
        let store = store.clone();
        let hooks = cfg.hooks.clone();
        let host = host.clone();
        tokio::spawn(async move {
            if let Err(e) = proxy_h2_stream(request, respond, send_req, host, port, store, hooks).await
            {
                tracing::debug!("h2 stream 处理结束:{e}");
            }
        });
    }
    Ok(())
}

/// 处理单条 h2 stream:读请求 →(on_request 改包/丢弃/短路)→ 转上游 → 读响应 →(on_response 改写/丢弃)→ 落盘 → 回客户端。
///
/// 钩子语义与 h1 路径([`crate::mitm::intercept_https`])完全对齐:扩展(及基于扩展的拦截改包)对 h2 同样生效。
async fn proxy_h2_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    send_req: h2::client::SendRequest<Bytes>,
    host: String,
    port: u16,
    store: SharedStore,
    hooks: Option<crate::ExtHooks>,
) -> Result<()> {
    let started = Instant::now();
    let (parts, mut body) = request.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // 收齐请求体(h2 流式 + 流控:每读一块归还窗口让对端继续发)。
    let mut req_body = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.context("读 h2 请求体失败")?;
        req_body.extend_from_slice(&chunk);
        let _ = body.flow_control().release_capacity(chunk.len());
    }

    // 请求侧 flow + on_request 钩子(改包 / 丢弃 / 短路),与 h1 路径语义一致。
    let req_headers = headermap_to_vec(&parts.headers);
    let mut flow = HttpFlow::request(
        parts.method.as_str(),
        "https",
        host.clone(),
        port,
        path,
        req_headers,
        req_body,
    );
    if let Some(h) = hooks.as_ref() {
        match h.0.on_request(&mut flow) {
            HookAction::Drop => {
                respond.send_reset(h2::Reason::CANCEL);
                return Ok(());
            }
            HookAction::Respond(r) => {
                send_synth_h2(&mut respond, r.status, &r.headers, &r.body)?;
                let dur = started.elapsed().as_millis() as u64;
                let f = flow.with_response(r.status, r.headers, r.body, dur);
                save_flow(&store, &f);
                h.0.on_flow_complete(&f);
                return Ok(());
            }
            _ => {}
        }
    }

    // 用(可能被钩子改过的)flow 字段构造上游 h2 请求。
    let method = http::Method::from_bytes(flow.method.as_bytes()).unwrap_or(http::Method::GET);
    let authority = if port == 443 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let uri = http::Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query(flow.path.clone())
        .build()
        .context("构造上游 URI 失败")?;
    let mut up_req = http::Request::builder()
        .method(method)
        .uri(uri)
        .version(http::Version::HTTP_2);
    if let Some(hm) = up_req.headers_mut() {
        vec_to_headermap(&flow.req_headers, hm, true);
    }
    let up_req = up_req.body(()).context("构造上游 h2 请求失败")?;

    // 发上游(请求体随后流式发出)。
    let mut send_req = send_req.ready().await.context("上游 h2 send 未就绪")?;
    let eos = flow.req_body.is_empty();
    let (resp_fut, mut up_body) = send_req
        .send_request(up_req, eos)
        .context("发上游 h2 请求失败")?;
    if !eos {
        up_body
            .send_data(Bytes::from(flow.req_body.clone()), true)
            .context("发上游 h2 请求体失败")?;
    }

    // 读上游响应(头 + 流式体)。
    let response = resp_fut.await.context("等上游 h2 响应失败")?;
    let (resp_parts, mut resp_body_stream) = response.into_parts();
    let mut resp_body = Vec::new();
    while let Some(chunk) = resp_body_stream.data().await {
        let chunk = chunk.context("读上游 h2 响应体失败")?;
        resp_body.extend_from_slice(&chunk);
        let _ = resp_body_stream
            .flow_control()
            .release_capacity(chunk.len());
    }
    flow.status = resp_parts.status.as_u16();
    flow.resp_headers = headermap_to_vec(&resp_parts.headers);
    flow.resp_body = resp_body;
    flow.duration_ms = started.elapsed().as_millis() as u64;

    // on_response 钩子(门控:仅声明该钩子的扩展)——可改写 / 丢弃,与 h1 路径对齐。
    if let Some(h) = hooks.as_ref() {
        if h.0.wants_response_hook() {
            match h.0.on_response(&mut flow) {
                HookAction::Drop => {
                    respond.send_reset(h2::Reason::CANCEL);
                    save_flow(&store, &flow);
                    h.0.on_flow_complete(&flow);
                    return Ok(());
                }
                HookAction::Respond(r) => {
                    flow.status = r.status;
                    flow.resp_headers = r.headers;
                    flow.resp_body = r.body;
                }
                _ => {}
            }
        }
    }

    // 落盘(save-first,钩子改写后的最终态)+ 被动钩子。
    save_flow(&store, &flow);
    if let Some(h) = hooks.as_ref() {
        h.0.on_flow_complete(&flow);
    }

    // 回客户端(可能被钩子改过的 status / headers / body)。
    send_synth_h2(&mut respond, flow.status, &flow.resp_headers, &flow.resp_body)?;
    Ok(())
}

/// `http::HeaderMap` → `Vec<(String,String)>`(落盘 / 展示用)。
fn headermap_to_vec(h: &http::HeaderMap) -> Vec<(String, String)> {
    h.iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).to_string(),
            )
        })
        .collect()
}

/// `Vec<(String,String)>` → `http::HeaderMap`(跳过逐跳头;请求侧额外跳过 `host`,因 `:authority` 由 URI 提供)。
/// 非法的头名 / 值被跳过(防御:钩子改包后可能产生不合法字符)。
fn vec_to_headermap(src: &[(String, String)], dst: &mut http::HeaderMap, is_request: bool) {
    for (k, v) in src {
        let lk = k.to_ascii_lowercase();
        // content-length 一并跳过:h2 用 DATA 帧 + END_STREAM 界定长度,钩子改写 body 后保留旧值会不符。
        if is_hop_by_hop(&lk) || lk == "content-length" || (is_request && lk == "host") {
            continue;
        }
        if let (Ok(name), Ok(val)) = (
            http::header::HeaderName::from_bytes(k.as_bytes()),
            http::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            dst.append(name, val);
        }
    }
}

/// 用 (status, headers, body) 给客户端发一个 h2 响应(短路 / 改写共用)。
fn send_synth_h2(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<()> {
    let mut resp = http::Response::builder()
        .status(status)
        .version(http::Version::HTTP_2);
    if let Some(hm) = resp.headers_mut() {
        vec_to_headermap(headers, hm, false);
    }
    let resp = resp.body(()).context("构造 h2 响应失败")?;
    let empty = body.is_empty();
    let mut send = respond
        .send_response(resp, empty)
        .context("发 h2 响应头失败")?;
    if !empty {
        send.send_data(Bytes::from(body.to_vec()), true)
            .context("发 h2 响应体失败")?;
    }
    Ok(())
}

/// 逐跳头(h2 不允许 / 不应转发)。
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "upgrade"
            | "te"
            | "trailer"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use scry_storage::Store;
    use std::sync::{Arc, Mutex};

    #[test]
    fn hop_by_hop_filtered() {
        assert!(is_hop_by_hop("connection"));
        assert!(is_hop_by_hop("transfer-encoding"));
        assert!(!is_hop_by_hop("content-type"));
    }

    /// h2↔h2 端到端:假客户端 ─h2→ `handle_h2` ─h2→ 假上游;断言响应回传 + 落盘一条 flow。
    /// 用 `tokio::io::duplex` 内存双工流,**不依赖 TLS / 外网**,确定性可重复。
    #[tokio::test]
    async fn h2_end_to_end_capture_and_forward() {
        let (up_scry, up_srv) = tokio::io::duplex(64 * 1024);
        let (cli, cli_scry) = tokio::io::duplex(64 * 1024);

        let store = Arc::new(Mutex::new(Store::open_memory().unwrap()));
        let store_h = store.clone();

        // 假上游:h2 服务端,持续 accept 以驱动连接(h2 server 须被 poll 才能刷出响应帧),收到请求回 200 + "pong"。
        let upstream = tokio::spawn(async move {
            let mut srv = h2::server::handshake(up_srv).await.unwrap();
            while let Some(accepted) = srv.accept().await {
                let (_req, mut respond) = accepted.unwrap();
                let resp = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(resp, false).unwrap();
                send.send_data(Bytes::from_static(b"pong"), true).unwrap();
            }
        });

        // 被测:scry h2↔h2 转发。
        let scry = tokio::spawn(async move {
            let _ = handle_h2(
                cli_scry,
                up_scry,
                "example.com".to_string(),
                443,
                store_h,
                ProxyConfig::default(),
            )
            .await;
        });

        // 假客户端:h2 发 GET /test,断言收到 200 + pong。
        let (send_req, conn) = h2::client::handshake(cli).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut send_req = send_req.ready().await.unwrap();
        let req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/test")
            .body(())
            .unwrap();
        let (resp_fut, _body) = send_req.send_request(req, true).unwrap();
        let resp = resp_fut.await.unwrap();
        assert_eq!(resp.status(), 200);
        let mut rbody = resp.into_body();
        let mut data = Vec::new();
        while let Some(chunk) = rbody.data().await {
            let chunk = chunk.unwrap();
            data.extend_from_slice(&chunk);
            let _ = rbody.flow_control().release_capacity(chunk.len());
        }
        assert_eq!(&data, b"pong");

        // proxy_h2_stream 在回客户端前已 save_flow,故此处必能读到。
        // save_flow 在回客户端前已发生;给跨 task 提交留一点时间防极端调度竞争。
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let recent = store.lock().unwrap().recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].status, 200);
        assert_eq!(recent[0].path, "/test");
        assert_eq!(recent[0].host, "example.com");
        assert_eq!(recent[0].resp_body, b"pong");

        scry.abort();
        upstream.abort();
    }

    /// h2 + on_response 钩子:扩展把响应体改写 → 断言客户端收到的是改写后的内容(验证 h2 改包生效)。
    #[tokio::test]
    async fn h2_response_rewrite_via_hook() {
        use crate::ExtHooks;
        struct RewriteHost;
        impl scry_ext_api::ExtensionHost for RewriteHost {
            fn wants_response_hook(&self) -> bool {
                true
            }
            fn on_response(&self, flow: &mut HttpFlow) -> HookAction {
                flow.resp_body = b"REWRITTEN".to_vec();
                HookAction::Continue
            }
        }

        let (up_scry, up_srv) = tokio::io::duplex(64 * 1024);
        let (cli, cli_scry) = tokio::io::duplex(64 * 1024);
        let store = Arc::new(Mutex::new(Store::open_memory().unwrap()));
        let store_h = store.clone();

        let upstream = tokio::spawn(async move {
            let mut srv = h2::server::handshake(up_srv).await.unwrap();
            while let Some(accepted) = srv.accept().await {
                let (_req, mut respond) = accepted.unwrap();
                let resp = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(resp, false).unwrap();
                send.send_data(Bytes::from_static(b"pong"), true).unwrap();
            }
        });

        let cfg = ProxyConfig {
            hooks: Some(ExtHooks(Arc::new(RewriteHost))),
            ..ProxyConfig::default()
        };
        let scry = tokio::spawn(async move {
            let _ =
                handle_h2(cli_scry, up_scry, "example.com".to_string(), 443, store_h, cfg).await;
        });

        let (send_req, conn) = h2::client::handshake(cli).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut send_req = send_req.ready().await.unwrap();
        let req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/x")
            .body(())
            .unwrap();
        let (resp_fut, _b) = send_req.send_request(req, true).unwrap();
        let resp = resp_fut.await.unwrap();
        let mut rbody = resp.into_body();
        let mut data = Vec::new();
        while let Some(chunk) = rbody.data().await {
            let chunk = chunk.unwrap();
            data.extend_from_slice(&chunk);
            let _ = rbody.flow_control().release_capacity(chunk.len());
        }
        // 客户端收到的应是钩子改写后的内容,而非上游原始 "pong"。
        assert_eq!(&data, b"REWRITTEN");

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let recent = store.lock().unwrap().recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].resp_body, b"REWRITTEN");

        scry.abort();
        upstream.abort();
    }
}
