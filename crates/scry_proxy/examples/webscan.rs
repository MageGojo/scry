//! 用 **scry 主动扫描引擎**对带参 URL 做 Web 漏洞注入探测(报错 SQLi / 反射 XSS / 路径穿越)。
//!
//! 走的是 GUI 扫描器页「主动扫描」同一引擎:`scry_scan::generate_probes` 造变异请求 →
//! `scry_proxy::replay::send` 真发包 → `scry_scan::evaluate` 命中判定。非破坏(仅检测级 payload)。
//!
//! 用法:
//! ```text
//! cargo run -p scry_proxy --example webscan -- "https://t.com/api?id=1" ["https://t.com/x?q=1" ...]
//! # 带鉴权(把 key 放进 X-Api-Key 头随每个探测发送):
//! SCRY_APIKEY=<your-key> cargo run -p scry_proxy --example webscan -- "https://apizero.cn/api/whois?domain=example.com"
//! # 墙内经 QX/sing-box: 另加 SCRY_UPSTREAM=http://127.0.0.1:20122
//! ```

use std::time::Duration;

use scry_core::HttpFlow;
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};
use scry_proxy::upstream::UpstreamProxy;
use scry_scan::{evaluate, generate_probes};

/// 把命令行参数展开成 URL 列表:`@文件` 读取文件每行一个 URL(忽略空行 / `#` 注释)。
fn collect_urls() -> Vec<String> {
    let mut urls = Vec::new();
    for arg in std::env::args().skip(1) {
        if let Some(path) = arg.strip_prefix('@') {
            match std::fs::read_to_string(path) {
                Ok(text) => {
                    for line in text.lines() {
                        let l = line.trim();
                        if !l.is_empty() && !l.starts_with('#') {
                            urls.push(l.to_string());
                        }
                    }
                }
                Err(e) => eprintln!("读取 {path} 失败: {e}"),
            }
        } else {
            urls.push(arg);
        }
    }
    urls
}

fn main() {
    let urls = collect_urls();
    if urls.is_empty() {
        eprintln!("用法: cargo run -p scry_proxy --example webscan -- <url-with-?params> [更多url...]");
        eprintln!("鉴权(可选): 设 SCRY_APIKEY=<key> 作为 X-Api-Key 头随每个探测发送");
        return;
    }
    let upstream = UpstreamProxy::from_env();
    let apikey = std::env::var("SCRY_APIKEY").ok().filter(|s| !s.trim().is_empty());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    rt.block_on(run(urls, upstream, apikey));
}

async fn run(urls: Vec<String>, upstream: Option<UpstreamProxy>, apikey: Option<String>) {
    let cfg = ReplayConfig {
        upstream,
        ..Default::default()
    };
    eprintln!(
        "[scry active] {} 个目标 · 鉴权 {} · 出网 {}",
        urls.len(),
        if apikey.is_some() { "X-Api-Key" } else { "无(可能 401)" },
        if cfg.upstream.is_some() { "SCRY_UPSTREAM" } else { "直连" }
    );

    let mut findings = Vec::new();
    for url in &urls {
        let Some(rr) = ReplayRequest::from_url("GET", url, vec![], vec![]) else {
            eprintln!("跳过无效 URL: {url}");
            continue;
        };
        let host_hdr = if (rr.scheme == "https" && rr.port == 443)
            || (rr.scheme == "http" && rr.port == 80)
        {
            rr.host.clone()
        } else {
            format!("{}:{}", rr.host, rr.port)
        };
        let mut headers = vec![
            ("Host".to_string(), host_hdr),
            (
                "User-Agent".to_string(),
                "Mozilla/5.0 (compatible; ScryScanner/1.0)".to_string(),
            ),
            ("Accept".to_string(), "*/*".to_string()),
        ];
        if let Some(k) = &apikey {
            headers.push(("X-Api-Key".to_string(), k.clone()));
        }
        let base = HttpFlow::request(
            "GET",
            rr.scheme.clone(),
            rr.host.clone(),
            rr.port,
            rr.path.clone(),
            headers,
            vec![],
        );
        let probes = generate_probes(&base);
        println!("\n# {url}  → {} 个探测", probes.len());
        for p in &probes {
            // 礼貌限速,避免把目标 API 打到限流。
            tokio::time::sleep(Duration::from_millis(100)).await;
            let req = ReplayRequest::from_flow(&p.flow);
            match replay::send(&req, &cfg).await {
                Ok(resp) => {
                    let f = evaluate(p, &resp);
                    println!(
                        "  {:>4}  {:<13}  param={:<10} {}",
                        resp.status,
                        format!("{:?}", p.kind),
                        p.param,
                        if f.is_some() { "<<< HIT" } else { "" }
                    );
                    if let Some(f) = f {
                        findings.push(f);
                    }
                }
                Err(e) => println!("  ERR   {:?}  param={}  ({e})", p.kind, p.param),
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
