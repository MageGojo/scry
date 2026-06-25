//! TLS MITM 解密引擎 —— Scry「像 Burp 那样」看到 HTTPS 明文的核心。
//!
//! **与流量来源解耦**:无论连接是来自(测试用的)代理 CONNECT,还是后续的透明抓包前端,
//! 只要给定「已接管的客户端 TCP + 目标 host:port」,本引擎就:
//! 1. 用 [`scry_ca`] 为目标域名**动态签发叶子证书**,作为 TLS 服务端与客户端握手;
//! 2. 作为 TLS 客户端与真实上游握手(用 webpki 根校验);
//! 3. 读出**解密后的明文** HTTP 请求 / 响应 → **先落盘**(save-first)→ 原样转发。
//!
//! 关键:这一步不设置任何系统 / 应用代理,因此**不抢占代理位**。

use crate::upstream::connect_via;
use crate::{
    build_http_response, build_origin_request, build_synth_response, save_flow, ProxyConfig,
    SharedStore,
};
use anyhow::{Context, Result};
use scry_ca::{Ca, CertPem};
use scry_core::{HttpFlow, WsDirection, WsMessage};
use scry_ext_api::HookAction;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// 接管一个 HTTPS 连接并 MITM 解密(目标 host:port 已知)。
///
/// `client` 是与目标 App 的原始 TCP(代理 CONNECT 或 pf 透明重定向)。与流量来源解耦:
/// 走 CONNECT 时需本函数先回 200(由 `send_connect_ok` 控制)。
pub async fn intercept_https(
    mut client: TcpStream,
    host: String,
    port: u16,
    send_connect_ok: bool,
    store: SharedStore,
    ca: Arc<Ca>,
    cfg: ProxyConfig,
) -> Result<()> {
    if send_connect_ok {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    }

    // Map Remote:连上游前询问扩展/规则是否把目标重定向到别处(叶子证书仍按**原** host 签发,
    // 客户端无感知;flow 记录也保留原 host 便于历史展示)。
    let (target_host, target_port) = cfg
        .hooks
        .as_ref()
        .and_then(|h| h.0.remap_target(&host, port))
        .unwrap_or_else(|| (host.clone(), port));

    // ── 先对上游握手:拿到 ALPN 协商结果,据此决定给客户端提议什么协议 ──
    // 顺序很关键:server ALPN **跟随上游** → 两端永远同协议(h2↔h2 / h1↔h1),免去 h1/h2 跨协议桥接。
    let upstream_tcp = connect_via(target_host.as_str(), target_port, cfg.upstream.as_ref())
        .await
        .with_context(|| format!("连接上游 {target_host}:{target_port} 失败"))?;
    let connector = TlsConnector::from(Arc::new(build_client_config()?));
    let server_name = ServerName::try_from(target_host.clone()).context("无效 SNI")?;
    let upstream_tls = connector
        .connect(server_name, upstream_tcp)
        .await
        .context("对上游 TLS 握手失败")?;
    let upstream_is_h2 = upstream_tls.get_ref().1.alpn_protocol() == Some(b"h2".as_ref());

    // ── 再对客户端握手:用为该域名签发的叶子证书做 TLS 服务端,**ALPN 跟随上游** ──
    // 握手链同时附带 **CA 证书**:既让信任了 CA 的客户端能正常建链,也让内置浏览器(T1)的
    // `--ignore-certificate-errors-spki-list=<CA SPKI>` 命中链中的 CA → 免装系统 CA、连 pinning 都过。
    let leaf = ca.sign_leaf(&host).context("签发叶子证书失败")?;
    let server_alpn = if upstream_is_h2 {
        vec![b"h2".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    let acceptor =
        TlsAcceptor::from(Arc::new(build_server_config(&leaf, &ca.cert_pem(), server_alpn)?));
    let mut client_tls = acceptor
        .accept(client)
        .await
        .context("对客户端 TLS 握手失败(客户端是否信任 Scry 根 CA?)")?;

    // ── HTTP/2:两端协商成 h2 → 走 h2 多路复用代理(每 stream 一条 flow)──
    if upstream_is_h2 {
        return crate::http2::handle_h2(client_tls, upstream_tls, host, port, store, cfg).await;
    }

    // ── HTTP/1.1:读明文请求 → 转发 → 读明文响应 → 落盘 → 回传 ──
    let mut upstream_tls = upstream_tls;
    let started = Instant::now();
    let req = read_message(&mut client_tls, false).await?;
    if req.raw.is_empty() {
        return Ok(());
    }

    // 组请求侧 flow,交扩展 on_request(转发前:可改写 / 丢弃 / 短路)。
    let mut flow = HttpFlow::request(
        &req.method,
        "https",
        host.clone(),
        port,
        req.path.clone(),
        req.headers.clone(),
        req.body.clone(),
    );
    if let Some(hooks) = cfg.hooks.as_ref() {
        match hooks.0.on_request(&mut flow) {
            HookAction::Drop => return Ok(()),
            HookAction::Respond(r) => {
                client_tls.write_all(&build_synth_response(&r)).await?;
                client_tls.flush().await?;
                let f = flow.with_response(r.status, r.headers, r.body, 0);
                save_flow(&store, &f);
                hooks.0.on_flow_complete(&f);
                return Ok(());
            }
            _ => {}
        }
    }

    // WebSocket 升级:走专用双向抓取路径。普通 HTTP 的「读一个响应」模型遇到 101 + 长连接帧流会卡死到超时。
    if crate::websocket::is_upgrade_request(&flow.req_headers) {
        return handle_websocket(
            client_tls,
            upstream_tls,
            flow,
            started,
            store,
            cfg.ws_rewrite.clone(),
        )
        .await;
    }

    let outbound =
        build_origin_request(&flow.method, &flow.path, &flow.req_headers, &flow.req_body);
    upstream_tls.write_all(&outbound).await?;
    upstream_tls.flush().await?;

    let resp = tokio::time::timeout(cfg.upstream_timeout, read_message(&mut upstream_tls, true))
        .await
        .context("读上游响应超时")??;

    flow.status = resp.status;
    flow.resp_headers = resp.headers.clone();
    flow.resp_body = resp.body.clone();
    flow.duration_ms = started.elapsed().as_millis() as u64;

    // 扩展 on_response(仅当有扩展声明该钩子;否则按原貌转发 raw,零保真损失)。
    // body 已 dechunk,重建时丢 chunked 框架 + 重算 Content-Length(见 build_http_response)。
    let mut rebuilt: Option<Vec<u8>> = None;
    if let Some(hooks) = cfg.hooks.as_ref() {
        if hooks.0.wants_response_hook() {
            match hooks.0.on_response(&mut flow) {
                HookAction::Drop => return Ok(()),
                HookAction::Respond(r) => {
                    client_tls.write_all(&build_synth_response(&r)).await?;
                    client_tls.flush().await?;
                    flow.status = r.status;
                    flow.resp_headers = r.headers;
                    flow.resp_body = r.body;
                    save_flow(&store, &flow);
                    hooks.0.on_flow_complete(&flow);
                    return Ok(());
                }
                _ => {
                    rebuilt = Some(build_http_response(
                        flow.status,
                        &flow.resp_headers,
                        &flow.resp_body,
                    ));
                }
            }
        }
    }

    // 落盘(改写后的最终内容)+ 被动钩子。
    save_flow(&store, &flow);
    if let Some(hooks) = cfg.hooks.as_ref() {
        hooks.0.on_flow_complete(&flow);
    }

    let out = rebuilt.as_deref().unwrap_or(&resp.raw);
    // 按弱网/限速档注入延迟 + 带宽上限回写客户端(无档 = 直发,零开销)。
    crate::throttle::write_throttled(&mut client_tls, out, cfg.throttle.as_ref()).await?;
    Ok(())
}

// ───────── rustls 配置 ─────────

fn build_server_config(
    leaf: &CertPem,
    ca_cert_pem: &str,
    alpn: Vec<Vec<u8>>,
) -> Result<ServerConfig> {
    // 链 = [叶子证书, 根 CA]:end-entity 在前,根在后(客户端按需建链;附带 CA 供 SPKI 白名单命中)。
    let mut chain = rustls_pemfile::certs(&mut leaf.cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("解析叶子证书 PEM 失败")?;
    let ca_certs = rustls_pemfile::certs(&mut ca_cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("解析 CA 证书 PEM 失败")?;
    chain.extend(ca_certs);
    let key = rustls_pemfile::private_key(&mut leaf.key_pem.as_bytes())
        .context("解析叶子私钥 PEM 失败")?
        .context("叶子私钥为空")?;
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("构造 TLS 服务端配置失败")?;
    // ALPN 跟随上游协商结果(h2 / http/1.1)→ 两端同协议,客户端不会选出内核处理不了的协议。
    cfg.alpn_protocols = alpn;
    Ok(cfg)
}

pub(crate) fn build_client_config() -> Result<ClientConfig> {
    build_client_config_for(crate::tls_profile::active())
}

/// 按**指定** TLS 指纹 profile 构造上游 rustls 客户端配置。
///
/// 单一构造入口:MITM 上游(`build_client_config` → 取当前档)、Repeater 重放、以及
/// [`fingerprint`](crate::fingerprint) 计算指纹**共用同一份逻辑** → 显示的指纹与线上握手必然一致。
pub(crate) fn build_client_config_for(profile: crate::tls_profile::TlsProfile) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // TLS 指纹伪装:按 profile 重排密码套件 + 椭圆曲线 + 设 ALPN(rustls 可控范围)。
    let provider = Arc::new(crate::tls_profile::provider_for(profile));
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("TLS 协议版本配置失败")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = profile.alpn();
    Ok(cfg)
}

// ───────── WebSocket(升级后双向抓取) ─────────

/// WS 连接序号(关联同一连接的所有消息)。
static WS_CONN_SEQ: AtomicI64 = AtomicI64::new(1);

/// 重建 WebSocket 握手请求字节:保留 `Upgrade` / `Connection: Upgrade` / `Sec-WebSocket-*`,
/// 仅剔 `proxy-connection`,**不强制 `Connection: close`**(那会破坏升级)。
fn build_upgrade_request(
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut out = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// 把解码出的帧聚合成消息并落盘(两个方向复用)。
fn drain_and_save(
    decoder: &mut crate::websocket::FrameDecoder,
    assembler: &mut crate::websocket::Assembler,
    store: &SharedStore,
    conn_id: i64,
    host: &str,
    path: &str,
    direction: WsDirection,
) {
    while let Some(frame) = decoder.next_frame() {
        if let Some(msg) = assembler.push(frame) {
            let wm = WsMessage::new(conn_id, host, path, direction, msg.opcode.label(), msg.payload);
            if let Ok(s) = store.lock() {
                let _ = s.save_ws(&wm);
            }
        }
    }
}

/// 单方向泵:读字节 →【立即原样转发对端】→ 旁路喂帧解析器记录消息。
///
/// 转发是**字节透传**(不等帧完整,零破坏、零延迟);记录是 best-effort 的旁路解析。
#[allow(clippy::too_many_arguments)]
async fn pump_ws<R, W>(
    mut rd: R,
    mut wr: W,
    direction: WsDirection,
    initial: Vec<u8>,
    store: SharedStore,
    conn_id: i64,
    host: String,
    path: String,
) -> Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut decoder = crate::websocket::FrameDecoder::new();
    let mut assembler = crate::websocket::Assembler::new();

    if !initial.is_empty() {
        wr.write_all(&initial).await?;
        wr.flush().await?;
        decoder.feed(&initial);
        drain_and_save(&mut decoder, &mut assembler, &store, conn_id, &host, &path, direction);
    }

    let mut tmp = [0u8; 16384];
    loop {
        let n = match rd.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if wr.write_all(&tmp[..n]).await.is_err() {
            break;
        }
        let _ = wr.flush().await;
        decoder.feed(&tmp[..n]);
        drain_and_save(&mut decoder, &mut assembler, &store, conn_id, &host, &path, direction);
    }
    Ok(())
}

/// WebSocket 升级:转发握手 → 读 101 响应头回灌客户端 → 双向「字节透传 + 旁路抓取」。
///
/// `ws_rewrite` 非空(且该方向有规则)时,该方向改走「解帧 → 文本帧改写 → 重编码 → 转发」模式
/// (对标 Burp WebSockets intercept);否则仍是零破坏的字节透传。
async fn handle_websocket(
    mut client_tls: tokio_rustls::server::TlsStream<TcpStream>,
    mut upstream_tls: tokio_rustls::client::TlsStream<TcpStream>,
    mut flow: HttpFlow,
    started: Instant,
    store: SharedStore,
    ws_rewrite: Option<Arc<Vec<crate::websocket::WsRewriteRule>>>,
) -> Result<()> {
    // 原样转发握手请求(保留升级头)。
    let handshake =
        build_upgrade_request(&flow.method, &flow.path, &flow.req_headers, &flow.req_body);
    upstream_tls.write_all(&handshake).await?;
    upstream_tls.flush().await?;

    // 只读上游响应头(101 之后是 WS 帧,不能按 body 读)。
    let (buf, head_len) = read_headers(&mut upstream_tls).await?;
    if buf.is_empty() {
        return Ok(());
    }
    let head_len = head_len.min(buf.len());
    let mut hbuf = [httparse::EMPTY_HEADER; 96];
    let mut resp = httparse::Response::new(&mut hbuf);
    resp.parse(&buf).context("解析 WS 握手响应失败")?;
    let status = resp.code.unwrap_or(0);
    let resp_headers = collect_headers(resp.headers);

    // 响应头原样回灌客户端。
    client_tls.write_all(&buf[..head_len]).await?;
    client_tls.flush().await?;

    flow.status = status;
    flow.resp_headers = resp_headers.clone();
    flow.duration_ms = started.elapsed().as_millis() as u64;
    save_flow(&store, &flow);

    let leftover = buf[head_len..].to_vec();

    if !crate::websocket::is_switching_response(status, &resp_headers) {
        // 升级被拒(非 101):把剩余响应转发给客户端后收尾,不进入帧抓取。
        if !leftover.is_empty() {
            client_tls.write_all(&leftover).await?;
            client_tls.flush().await?;
        }
        tokio::io::copy(&mut upstream_tls, &mut client_tls).await.ok();
        return Ok(());
    }

    // 101:双向并发泵,任一方向结束即收尾(drop 另一半 → 关连接)。
    let conn_id = WS_CONN_SEQ.fetch_add(1, Ordering::Relaxed);
    let host = flow.host.clone();
    let path = flow.path.clone();
    let (cr, cw) = tokio::io::split(client_tls);
    let (ur, uw) = tokio::io::split(upstream_tls);
    // 无规则 = 空 Arc → 各方向走零破坏的字节透传(行为与改动前完全一致)。
    let rewrite = ws_rewrite.unwrap_or_default();

    // 客户端 → 服务端(出站,重编码需 mask)。
    let r1 = rewrite.clone();
    let (h1, p1, s1) = (host.clone(), path.clone(), store.clone());
    let c2s = async move {
        if crate::websocket::has_rules_for(crate::websocket::WsRuleDir::ToServer, &r1) {
            pump_ws_rewrite(
                cr, uw, WsDirection::ClientToServer, Vec::new(), s1, conn_id, h1, p1, r1,
                crate::websocket::WsRuleDir::ToServer, true,
            )
            .await
        } else {
            pump_ws(cr, uw, WsDirection::ClientToServer, Vec::new(), s1, conn_id, h1, p1).await
        }
    };

    // 服务端 → 客户端(入站,不 mask)。
    let r2 = rewrite;
    let s2c = async move {
        if crate::websocket::has_rules_for(crate::websocket::WsRuleDir::ToClient, &r2) {
            pump_ws_rewrite(
                ur, cw, WsDirection::ServerToClient, leftover, store, conn_id, host, path, r2,
                crate::websocket::WsRuleDir::ToClient, false,
            )
            .await
        } else {
            pump_ws(ur, cw, WsDirection::ServerToClient, leftover, store, conn_id, host, path).await
        }
    };

    tokio::select! {
        _ = c2s => {}
        _ = s2c => {}
    }
    Ok(())
}

/// 单方向泵(**帧改写模式**):解帧 → 完整文本帧按规则字面量替换 → 重编码(按方向 mask)→ 转发,
/// 并记录改写后的消息。分片 / 二进制 / 控制帧原样重编码转发(不改内容)。
///
/// 与透传 [`pump_ws`] 互斥:仅当该方向配置了改写规则时启用(见 [`handle_websocket`])。
#[allow(clippy::too_many_arguments)]
async fn pump_ws_rewrite<R, W>(
    mut rd: R,
    mut wr: W,
    direction: WsDirection,
    initial: Vec<u8>,
    store: SharedStore,
    conn_id: i64,
    host: String,
    path: String,
    rules: Arc<Vec<crate::websocket::WsRewriteRule>>,
    ws_dir: crate::websocket::WsRuleDir,
    mask_out: bool,
) -> Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut decoder = crate::websocket::FrameDecoder::new();
    let mut assembler = crate::websocket::Assembler::new();

    if !initial.is_empty()
        && forward_frames(
            &mut decoder, &mut assembler, &initial, &mut wr, &store, conn_id, &host, &path,
            direction, &rules, ws_dir, mask_out,
        )
        .await
        .is_err()
    {
        return Ok(());
    }

    let mut tmp = [0u8; 16384];
    loop {
        let n = match rd.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if forward_frames(
            &mut decoder, &mut assembler, &tmp[..n], &mut wr, &store, conn_id, &host, &path,
            direction, &rules, ws_dir, mask_out,
        )
        .await
        .is_err()
        {
            break;
        }
    }
    Ok(())
}

/// 喂新字节 → 逐完整帧改写 + 重编码转发 + 记录(帧改写模式的核心)。
#[allow(clippy::too_many_arguments)]
async fn forward_frames<W>(
    decoder: &mut crate::websocket::FrameDecoder,
    assembler: &mut crate::websocket::Assembler,
    new_bytes: &[u8],
    wr: &mut W,
    store: &SharedStore,
    conn_id: i64,
    host: &str,
    path: &str,
    direction: WsDirection,
    rules: &[crate::websocket::WsRewriteRule],
    ws_dir: crate::websocket::WsRuleDir,
    mask_out: bool,
) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    decoder.feed(new_bytes);
    while let Some(frame) = decoder.next_frame() {
        // 仅对**完整文本帧**应用改写(分片可能切断 find 串,故只在 FIN=1 文本帧上改);其余原样转发。
        let payload = if frame.fin && frame.opcode == crate::websocket::OpCode::Text {
            crate::websocket::rewrite_text(ws_dir, &frame.payload, rules)
                .unwrap_or_else(|| frame.payload.clone())
        } else {
            frame.payload.clone()
        };
        let out = crate::websocket::encode_frame(frame.fin, frame.opcode, &payload, mask_out);
        wr.write_all(&out).await?;
        wr.flush().await?;
        // 记录改写后的帧(历史里看到的是改后内容)。
        let rec = crate::websocket::Frame {
            fin: frame.fin,
            opcode: frame.opcode,
            payload,
        };
        if let Some(msg) = assembler.push(rec) {
            let wm = WsMessage::new(conn_id, host, path, direction, msg.opcode.label(), msg.payload);
            if let Ok(s) = store.lock() {
                let _ = s.save_ws(&wm);
            }
        }
    }
    Ok(())
}

// ───────── 明文 HTTP/1.1 消息读取(请求 / 响应通用) ─────────

/// 一条解析后的 HTTP 消息(请求 / 响应通用)。
///
/// 复用面:除了 MITM 主路径,[`replay`](crate::replay) 也用它读重放响应。
pub(crate) struct Msg {
    /// 原始字节(头 + 原样 body,用于按原貌转发)。
    pub(crate) raw: Vec<u8>,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) status: u16,
    /// 解码后的 body(chunked 已去框架),用于落盘 / 展示。
    pub(crate) body: Vec<u8>,
}

pub(crate) async fn read_message<S>(s: &mut S, is_response: bool) -> Result<Msg>
where
    S: AsyncReadExt + Unpin,
{
    let (mut buf, head_len) = read_headers(s).await?;
    if buf.is_empty() {
        return Ok(Msg {
            raw: Vec::new(),
            headers: Vec::new(),
            method: String::new(),
            path: String::new(),
            status: 0,
            body: Vec::new(),
        });
    }

    let mut hbuf = [httparse::EMPTY_HEADER; 96];
    let (headers, method, path, status) = if is_response {
        let mut r = httparse::Response::new(&mut hbuf);
        r.parse(&buf).context("解析响应头失败")?;
        (collect_headers(r.headers), String::new(), String::new(), r.code.unwrap_or(0))
    } else {
        let mut r = httparse::Request::new(&mut hbuf);
        r.parse(&buf).context("解析请求头失败")?;
        (
            collect_headers(r.headers),
            r.method.unwrap_or("").to_string(),
            r.path.unwrap_or("").to_string(),
            0u16,
        )
    };

    let pre = buf.split_off(head_len); // 头之后已读到的字节
    let head = buf; // 头(含结尾 \r\n\r\n)
    let (raw_body, decoded) = read_body(s, pre, &headers, is_response).await?;
    let mut raw = head;
    raw.extend_from_slice(&raw_body);
    Ok(Msg {
        raw,
        headers,
        method,
        path,
        status,
        body: decoded,
    })
}

/// 读到 `\r\n\r\n`,返回 (已读全部字节, 头长度)。
async fn read_headers<S>(s: &mut S) -> Result<(Vec<u8>, usize)>
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = Vec::with_capacity(8192);
    loop {
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            return Ok((buf, p + 4));
        }
        if !fill(s, &mut buf).await? {
            // EOF:没有更多数据。
            if buf.is_empty() {
                return Ok((buf, 0));
            }
            let len = buf.len();
            return Ok((buf, len));
        }
        if buf.len() > 1024 * 1024 {
            anyhow::bail!("HTTP 头过大");
        }
    }
}

/// 按头部决定 body 长度并读取,返回 (原样字节, 解码后字节)。
async fn read_body<S>(
    s: &mut S,
    pre: Vec<u8>,
    headers: &[(String, String)],
    is_response: bool,
) -> Result<(Vec<u8>, Vec<u8>)>
where
    S: AsyncReadExt + Unpin,
{
    if is_chunked(headers) {
        return read_chunked(s, pre).await;
    }
    if let Some(cl) = content_length(headers) {
        let mut buf = pre;
        while buf.len() < cl {
            if !fill(s, &mut buf).await? {
                break;
            }
        }
        buf.truncate(cl.min(buf.len()));
        let body = buf.clone();
        return Ok((buf, body));
    }
    if is_response {
        // 无 CL / chunked 的响应:读到连接关闭(配合强制 Connection: close)。
        let mut buf = pre;
        while fill(s, &mut buf).await? {}
        let body = buf.clone();
        return Ok((buf, body));
    }
    // 请求且无 body。
    Ok((Vec::new(), Vec::new()))
}

/// 读取 chunked 编码:返回 (原样 chunk 字节, 解码后 body)。
async fn read_chunked<S>(s: &mut S, mut buf: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>)>
where
    S: AsyncReadExt + Unpin,
{
    let mut decoded = Vec::new();
    let mut idx = 0usize;
    loop {
        // 取一行 chunk-size。
        let line_end = loop {
            if let Some(p) = find(&buf[idx..], b"\r\n") {
                break idx + p;
            }
            if !fill(s, &mut buf).await? {
                anyhow::bail!("chunk 大小行处 EOF");
            }
        };
        let size_line = std::str::from_utf8(&buf[idx..line_end]).unwrap_or("");
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).unwrap_or(0);
        let data_start = line_end + 2;

        if size == 0 {
            // 末尾:消费可能的 trailer + 终止 \r\n。
            while find(&buf[data_start.min(buf.len())..], b"\r\n").is_none() {
                if !fill(s, &mut buf).await? {
                    break;
                }
            }
            let end = match find(&buf[data_start.min(buf.len())..], b"\r\n") {
                Some(p) => data_start + p + 2,
                None => buf.len(),
            };
            buf.truncate(end);
            return Ok((buf, decoded));
        }

        while buf.len() < data_start + size + 2 {
            if !fill(s, &mut buf).await? {
                anyhow::bail!("chunk 数据处 EOF");
            }
        }
        decoded.extend_from_slice(&buf[data_start..data_start + size]);
        idx = data_start + size + 2;
    }
}

/// 从流读一段追加到 buf;返回 false 表示 EOF。
async fn fill<S>(s: &mut S, buf: &mut Vec<u8>) -> Result<bool>
where
    S: AsyncReadExt + Unpin,
{
    let mut tmp = [0u8; 16384];
    let n = s.read(&mut tmp).await?;
    if n == 0 {
        return Ok(false);
    }
    buf.extend_from_slice(&tmp[..n]);
    Ok(true)
}

fn collect_headers(headers: &[httparse::Header<'_>]) -> Vec<(String, String)> {
    headers
        .iter()
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

fn content_length(headers: &[(String, String)]) -> Option<usize> {
    header_get(headers, "content-length").and_then(|v| v.trim().parse().ok())
}

fn is_chunked(headers: &[(String, String)]) -> bool {
    header_get(headers, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
}

/// 在 `hay` 中查找子序列 `needle` 的起始位置。
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn reads_content_length_body() {
        let raw = b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello".to_vec();
        let mut s = Cursor::new(raw);
        let msg = read_message(&mut s, false).await.unwrap();
        assert_eq!(msg.method, "POST");
        assert_eq!(msg.path, "/x");
        assert_eq!(msg.body, b"hello");
    }

    #[tokio::test]
    async fn decodes_chunked_response() {
        // "Wiki" + "pedia" 两块。
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
                .to_vec();
        let mut s = Cursor::new(raw);
        let msg = read_message(&mut s, true).await.unwrap();
        assert_eq!(msg.status, 200);
        assert_eq!(msg.body, b"Wikipedia");
    }
}
