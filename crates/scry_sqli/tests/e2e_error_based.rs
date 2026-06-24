//! 端到端冒烟:用一个**模拟有报错型 SQLi 的本地 HTTP 服务**,验证
//! `build_probe → replay::send → match_error_dbms → error_extract_value → parse_exfil`
//! 整条链路真的打通(含 query 的百分号编码 / 解码往返),不只是纯函数单测。

use scry_core::HttpFlow;
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};
use scry_sqli::{
    build_probe, error_extract_value, error_probe_values, injection_points, match_error_dbms,
    parse_exfil, Dbms, Scalar, BOUNDARIES,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const FAKE_VERSION: &str = "8.0.34-fakedb";

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 极简百分号解码(服务端用,把 `build_probe` 编码过的 query 还原成 SQL 载荷)。
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

/// 模拟漏洞站点 `GET /item?id=…`:
/// - `id` 里出现 `EXTRACTVALUE` + 外带标记 → 回显 `~标记<版本>标记`(报错外带);
/// - `id` 里出现裸单引号 → 回显 MySQL 语法报错;
/// - 否则正常页。
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
            let line = req.lines().next().unwrap_or("");
            let path = line.split_whitespace().nth(1).unwrap_or("");
            let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            let dec = pct_decode(query);
            let body = if dec.to_uppercase().contains("EXTRACTVALUE") && dec.contains("qScRyQ") {
                format!("<html>DB error: XPATH syntax error: '~qScRyQ{FAKE_VERSION}qScRyQ'</html>")
            } else if dec.contains('\'') {
                "<html>You have an error in your SQL syntax; check the manual near ''</html>"
                    .to_string()
            } else {
                "<html>welcome</html>".to_string()
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
        });
    }
}

#[tokio::test]
async fn error_based_detect_and_extract_end_to_end() {
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
        "/item?id=1",
        vec![("Host".into(), format!("{host}:{port}"))],
        vec![],
    );
    let cfg = ReplayConfig::default();

    // 注入点发现:应只有 query 参数 id。
    let points = injection_points(&base);
    assert_eq!(points.len(), 1);
    let point = &points[0];
    assert_eq!(point.name, "id");

    // 报错型检测:某个破坏字符触发 MySQL 报错 → 指纹 MySQL。
    let mut detected = None;
    for v in error_probe_values(&point.value) {
        let probe = build_probe(&base, point, &v);
        let resp = replay::send(&ReplayRequest::from_flow(&probe), &cfg)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&resp.resp_body);
        if let Some(db) = match_error_dbms(&body) {
            detected = Some(db);
            break;
        }
    }
    assert_eq!(detected, Some(Dbms::MySql));

    // 报错外带取版本:EXTRACTVALUE 把 version() 挤进报错回显 → parse_exfil 切出。
    let payload =
        error_extract_value(&point.value, BOUNDARIES[0], Dbms::MySql, Scalar::Version).unwrap();
    let probe = build_probe(&base, point, &payload);
    let resp = replay::send(&ReplayRequest::from_flow(&probe), &cfg)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&resp.resp_body);
    assert_eq!(parse_exfil(&body).as_deref(), Some(FAKE_VERSION));
}
