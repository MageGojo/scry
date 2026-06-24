//! 用 **scry 越权/访问控制引擎**(对标 Burp Autorize)对一批 URL 做多身份重放比对:
//! 同一请求用「高权限 / 低权限 / 匿名」分别发,谁不该拿到却拿到了 = Broken Access Control。
//!
//! 走 `scry_scan::authz`(身份套用 + 判定)+ `scry_proxy::replay::send`(真发包)。
//!
//! 用法:
//! ```text
//! # 高权限基准必填;低权限可选;匿名总会测。身份值是 "Header: value"(可分号多条)。
//! SCRY_ID_HIGH='X-Api-Key: ADMINKEY' \
//! SCRY_ID_LOW='X-Api-Key: USERKEY' \
//! cargo run -p scry_proxy --example authz -- "https://target/api/order/1001" @urls.txt
//! # 墙内经 QX/sing-box: 另加 SCRY_UPSTREAM=http://127.0.0.1:20122
//! ```

use std::time::Duration;

use scry_core::HttpFlow;
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};
use scry_proxy::upstream::UpstreamProxy;
use scry_scan::authz::{self, Identity};

fn collect_urls() -> Vec<String> {
    let mut urls = Vec::new();
    for arg in std::env::args().skip(1) {
        if let Some(path) = arg.strip_prefix('@') {
            match std::fs::read_to_string(path) {
                Ok(text) => urls.extend(
                    text.lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .map(str::to_string),
                ),
                Err(e) => eprintln!("读取 {path} 失败: {e}"),
            }
        } else {
            urls.push(arg);
        }
    }
    urls
}

fn base_flow(url: &str) -> Option<HttpFlow> {
    let rr = ReplayRequest::from_url("GET", url, vec![], vec![])?;
    let host_hdr = if (rr.scheme == "https" && rr.port == 443) || (rr.scheme == "http" && rr.port == 80) {
        rr.host.clone()
    } else {
        format!("{}:{}", rr.host, rr.port)
    };
    Some(HttpFlow::request(
        "GET",
        rr.scheme.clone(),
        rr.host.clone(),
        rr.port,
        rr.path.clone(),
        vec![
            ("Host".to_string(), host_hdr),
            (
                "User-Agent".to_string(),
                "Mozilla/5.0 (compatible; ScryScanner/1.0)".to_string(),
            ),
            ("Accept".to_string(), "*/*".to_string()),
        ],
        vec![],
    ))
}

fn main() {
    let urls = collect_urls();
    let Some(high_spec) = std::env::var("SCRY_ID_HIGH").ok().filter(|s| !s.trim().is_empty()) else {
        eprintln!("缺少 SCRY_ID_HIGH(高权限基准身份,如 'X-Api-Key: ADMINKEY')");
        return;
    };
    if urls.is_empty() {
        eprintln!("用法: cargo run -p scry_proxy --example authz -- <url> [@urls.txt ...]");
        return;
    }
    let high = Identity::parse("high", &high_spec);
    let mut tests = Vec::new();
    if let Some(low_spec) = std::env::var("SCRY_ID_LOW").ok().filter(|s| !s.trim().is_empty()) {
        tests.push(Identity::parse("low", &low_spec));
    }
    tests.push(Identity::anonymous());

    let upstream = UpstreamProxy::from_env();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    rt.block_on(run(urls, high, tests, upstream));
}

async fn run(urls: Vec<String>, high: Identity, tests: Vec<Identity>, upstream: Option<UpstreamProxy>) {
    let cfg = ReplayConfig {
        upstream,
        ..Default::default()
    };
    eprintln!(
        "[scry authz] {} 个 URL · 基准身份=high · 测试身份={:?} · 出网 {}",
        urls.len(),
        tests.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(),
        if cfg.upstream.is_some() { "SCRY_UPSTREAM" } else { "直连" }
    );

    let mut findings = Vec::new();
    for url in &urls {
        let Some(base) = base_flow(url) else {
            eprintln!("跳过无效 URL: {url}");
            continue;
        };
        // 高权限基准。
        let priv_req = ReplayRequest::from_flow(&authz::apply_identity(&base, &high));
        let privileged = match replay::send(&priv_req, &cfg).await {
            Ok(r) => r,
            Err(e) => {
                println!("\n# {url}\n  基准请求失败: {e}");
                continue;
            }
        };
        println!("\n# {url}\n  high  → {} ({} B)", privileged.status, privileged.resp_body.len());
        if !(200..300).contains(&privileged.status) {
            println!("  (基准非 2xx,跳过越权比对)");
            continue;
        }
        for id in &tests {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let req = ReplayRequest::from_flow(&authz::apply_identity(&base, id));
            match replay::send(&req, &cfg).await {
                Ok(resp) => {
                    let verdict = authz::compare(&privileged, &resp);
                    println!(
                        "  {:<9} → {} ({} B)  {:?}",
                        id.name,
                        resp.status,
                        resp.resp_body.len(),
                        verdict
                    );
                    if let Some(f) = authz::evaluate(url, id, &privileged, &resp) {
                        findings.push(f);
                    }
                }
                Err(e) => println!("  {:<9} → 失败: {e}", id.name),
            }
        }
    }

    println!("\n==== FINDINGS ({}) ====", findings.len());
    for f in &findings {
        println!(
            "[{:?}] {} :: {}\n        {}",
            f.severity, f.title, f.url, f.detail
        );
    }
}
