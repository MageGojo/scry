//! 端到端冒烟:用一个**把参数原样反射进 HTML 文本**的本地站点,验证
//! `build_probe → replay::send → reflections → detect_context → abusable_chars → synthesize → 验证 proof`
//! 整条 XSS 链路打通(含 query 的百分号编码 / 解码往返)。

use scry_core::HttpFlow;
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};
use scry_xss::{
    abusable_chars, build_probe, canary, detect_context, injection_points, reflections, synthesize,
    HtmlContext, REFLECT_MARK,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 模拟反射型 XSS 站点:把 `q` 原样(不编码)拼进 HTML 文本上下文。
async fn serve(listener: TcpListener) {
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            break;
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let mut got = Vec::new();
            loop {
                let Ok(n) = sock.read(&mut buf).await else {
                    return;
                };
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                if got.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&got);
            let path = req
                .lines()
                .next()
                .unwrap_or("")
                .split_whitespace()
                .nth(1)
                .unwrap_or("");
            let q = path
                .split_once('?')
                .map(|(_, q)| q)
                .and_then(|qs| qs.split('&').find_map(|p| p.strip_prefix("q=")))
                .unwrap_or("");
            let reflected = pct_decode(q);
            // 漏洞点:原样拼进 HTML 文本,不做任何编码。
            let body = format!("<html><body><h1>Results for {reflected}</h1></body></html>");
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
        });
    }
}

async fn fetch(base: &HttpFlow, point: &scry_xss::InjectionPoint, value: &str, cfg: &ReplayConfig) -> String {
    let probe = build_probe(base, point, value);
    let resp = replay::send(&ReplayRequest::from_flow(&probe), cfg)
        .await
        .unwrap();
    String::from_utf8_lossy(&resp.resp_body).into_owned()
}

#[tokio::test]
async fn reflected_xss_detect_and_confirm_end_to_end() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener));

    let host = addr.ip().to_string();
    let port = addr.port();
    let base = HttpFlow::request(
        "GET",
        "http",
        host.clone(),
        port,
        "/s?q=hello",
        vec![("Host".into(), format!("{host}:{port}"))],
        vec![],
    );
    let cfg = ReplayConfig::default();

    let points = injection_points(&base);
    assert_eq!(points.len(), 1);
    let point = &points[0];

    // 1) 反射 + 上下文:标记反射进 HTML 文本。
    let plain = fetch(&base, point, REFLECT_MARK, &cfg).await;
    let offs = reflections(&plain, REFLECT_MARK);
    assert!(!offs.is_empty(), "标记应被反射");
    let ctx = detect_context(&plain, offs[0]);
    assert_eq!(ctx, HtmlContext::HtmlText);

    // 2) 可利用字符:本站不编码 → 尖括号 / 引号 / 括号全可用。
    let canary_resp = fetch(&base, point, &canary(), &cfg).await;
    let ab = abusable_chars(&canary_resp);
    assert!(ab.lt && ab.gt && ab.paren() && ab.eq);

    // 3) 合成候选载荷,逐个验证执行片段未被编码地回显 = 确认可利用。
    let candidates = synthesize(ctx, ab);
    assert!(!candidates.is_empty());
    assert_eq!(candidates[0].value, "<svg/onload=alert(13371337)>");
    let mut confirmed = false;
    for p in &candidates {
        let body = fetch(&base, point, &p.value, &cfg).await;
        if body.contains(&p.proof) {
            confirmed = true;
            break;
        }
    }
    assert!(confirmed, "应有至少一个候选载荷被未编码地回显");
}
