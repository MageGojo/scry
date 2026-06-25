//! 端到端冒烟:用真实 [`scry_proxy::replay::send`] 跑「登录宏 → 捕获会话 → 注入到后续请求」
//! 整条链路,验证未带会话被拒、带会话放行。

use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};
use scry_session::{build_session, inject_headers, looks_logged_out, ApplySpec, CaptureSpec, LoggedOutSpec, Part, Resp};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// mock:`/login` 发 Set-Cookie + CSRF;`/secure` 需带 session cookie,否则 401。
async fn spawn_mock() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut got = Vec::new();
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
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
                let has_session = req.to_lowercase().contains("cookie:")
                    && req.contains("session=GOODSESSION");
                let resp = if path == "/login" {
                    let body = r#"<input name="csrf_token" value="CSRF-1234">"#;
                    format!(
                        "HTTP/1.1 200 OK\r\nSet-Cookie: session=GOODSESSION; Path=/; HttpOnly\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                } else if path == "/secure" && has_session {
                    let body = "authorized: secret-data";
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                } else {
                    let body = "unauthorized";
                    format!(
                        "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    format!("{}", addr)
}

#[tokio::test]
async fn login_macro_captures_and_injects_session() {
    let addr = spawn_mock().await;
    let cfg = ReplayConfig::default();

    // 1) 未带会话访问 /secure → 401 → 判定掉登录。
    let bare = ReplayRequest {
        method: "GET".into(),
        scheme: "http".into(),
        host: addr.split(':').next().unwrap().into(),
        port: addr.split(':').nth(1).unwrap().parse().unwrap(),
        path: "/secure".into(),
        headers: vec![("Host".into(), addr.clone())],
        body: vec![],
    };
    let bare_flow = replay::send(&bare, &cfg).await.unwrap();
    assert_eq!(bare_flow.status, 401);
    assert!(looks_logged_out(
        &Resp::new(bare_flow.status, &bare_flow.resp_headers, &bare_flow.resp_body),
        &LoggedOutSpec::default()
    ));

    // 2) 跑登录宏 → 捕获 cookie + CSRF 令牌。
    let login = ReplayRequest {
        method: "POST".into(),
        scheme: "http".into(),
        host: bare.host.clone(),
        port: bare.port,
        path: "/login".into(),
        headers: vec![("Host".into(), addr.clone())],
        body: b"user=admin&pass=x".to_vec(),
    };
    let login_flow = replay::send(&login, &cfg).await.unwrap();
    let cap = CaptureSpec {
        capture_cookies: true,
        token_regex: Some(r#"csrf_token"\s+value="([^"]+)""#.into()),
        token_part: Part::Body,
    };
    let session = build_session(
        &Resp::new(login_flow.status, &login_flow.resp_headers, &login_flow.resp_body),
        &cap,
    );
    assert_eq!(
        session.cookies,
        vec![("session".to_string(), "GOODSESSION".to_string())]
    );
    assert_eq!(session.token.as_deref(), Some("CSRF-1234"));

    // 3) 把会话注入 /secure 请求 → 200 已认证。
    let apply = ApplySpec {
        apply_cookies: true,
        token_header: Some("X-CSRF-Token".into()),
    };
    let injected_headers = inject_headers(&bare.headers, &session, &apply);
    assert!(injected_headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("cookie") && v.contains("session=GOODSESSION")));
    let authed = ReplayRequest {
        headers: injected_headers,
        ..bare.clone()
    };
    let authed_flow = replay::send(&authed, &cfg).await.unwrap();
    assert_eq!(authed_flow.status, 200);
    assert!(String::from_utf8_lossy(&authed_flow.resp_body).contains("authorized"));
    assert!(!looks_logged_out(
        &Resp::new(authed_flow.status, &authed_flow.resp_headers, &authed_flow.resp_body),
        &LoggedOutSpec::default()
    ));
}
