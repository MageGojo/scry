//! 端到端冒烟:用真实 [`scry_proxy::replay::send`] 打一个本地 mock 站点,验证
//! 「内置模板 → 构造请求 → 发送 → matcher 命中 → extractor 抽值」整条链路。

use scry_nuclei::{build_block_requests, evaluate_request, load_builtins, RespData, Target};
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// 起一个一直在线的本地 HTTP mock:按路径回不同响应(复用同一监听口,每连接一应)。
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
                let (status, body): (u16, String) = match path {
                    "/.git/config" => (
                        200,
                        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n".into(),
                    ),
                    "/swagger.json" => (200, r#"{"swagger":"2.0","info":{"title":"x"}}"#.into()),
                    _ => (404, "not found".into()),
                };
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    format!("http://{addr}")
}

/// 跑一个模板对目标的所有请求,返回 (是否命中, 抽取值列表)。
async fn run_template(t: &scry_nuclei::Template, target: &Target) -> (bool, Vec<String>) {
    let mut hit = false;
    let mut extracted = Vec::new();
    for block in &t.requests {
        for built in build_block_requests(block, target) {
            let req = ReplayRequest {
                method: built.method,
                scheme: built.scheme,
                host: built.host,
                port: built.port,
                path: built.path,
                headers: built.headers,
                body: built.body,
            };
            let Ok(flow) = replay::send(&req, &ReplayConfig::default()).await else {
                continue;
            };
            let resp = RespData::new(
                flow.status,
                &flow.resp_headers,
                &flow.resp_body,
                flow.duration_ms,
            );
            let res = evaluate_request(block, &resp);
            if res.matched {
                hit = true;
                extracted.extend(res.extracted.into_iter().map(|(_, v)| v));
            }
        }
    }
    (hit, extracted)
}

#[tokio::test]
async fn builtin_templates_match_and_extract() {
    let url = spawn_mock().await;
    let target = Target::parse(&url).unwrap();
    let templates = load_builtins();

    // git-config:服务返回真实 git 配置 → 命中(word and + status 200)。
    let git = templates.iter().find(|t| t.id == "scry-git-config").unwrap();
    let (git_hit, _) = run_template(git, &target).await;
    assert!(git_hit, "git-config 模板应命中本地 mock");

    // dotenv:服务对 /.env 返回 404 → 不命中。
    let dotenv = templates.iter().find(|t| t.id == "scry-dotenv").unwrap();
    let (env_hit, _) = run_template(dotenv, &target).await;
    assert!(!env_hit, "dotenv 模板不应在无 .env 的服务上命中");

    // swagger:服务返回 swagger.json → 命中 + extractor 抽出版本 "2.0"。
    let swagger = templates.iter().find(|t| t.id == "scry-swagger-api").unwrap();
    let (sw_hit, sw_ext) = run_template(swagger, &target).await;
    assert!(sw_hit, "swagger 模板应命中");
    assert!(
        sw_ext.contains(&"2.0".to_string()),
        "应抽出 swagger 版本 2.0,实际:{sw_ext:?}"
    );
}
