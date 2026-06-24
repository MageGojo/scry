//! 用 **scry 自身引擎**跑「敏感文件 / 路径发现」(Nikto 式)的命令行入口。
//!
//! 这就是 GUI 扫描器页点「敏感文件」走的同一条路径:
//! `scry_scan::discovery`(路径库 + soft-404 基线 + 命中判定)+ `scry_proxy::replay::send`(真发包)。
//!
//! 用法:
//! ```text
//! cargo run -p scry_proxy --example discover -- https://target.com
//! # 墙内经 QX/sing-box 出网(QX mixed 入站常见 127.0.0.1:20122):
//! SCRY_UPSTREAM=http://127.0.0.1:20122 cargo run -p scry_proxy --example discover -- https://target.com
//! ```

use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};
use scry_proxy::upstream::UpstreamProxy;
use scry_scan::discovery::{self, Sig};
use scry_scan::Severity;

fn main() {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://apizero.cn".to_string());
    let upstream = UpstreamProxy::from_env();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    rt.block_on(run(&target, upstream));
}

async fn run(target: &str, upstream: Option<UpstreamProxy>) {
    let url = format!("{}/", target.trim_end_matches('/'));
    let Some(probe) = ReplayRequest::from_url("GET", &url, vec![], vec![]) else {
        eprintln!("无效目标 URL: {target}");
        return;
    };
    let origin = discovery::Origin {
        scheme: probe.scheme.clone(),
        host: probe.host.clone(),
        port: probe.port,
    };
    let cfg = ReplayConfig {
        upstream,
        ..Default::default()
    };

    eprintln!(
        "[scry discovery] 目标 {} · 路径库 {} 条 · 出网 {}",
        origin.base_url(),
        discovery::PATHS.len(),
        if cfg.upstream.is_some() {
            "SCRY_UPSTREAM"
        } else {
            "直连"
        }
    );

    // soft-404 基线:对必不存在的随机路径取一份响应特征,后面压 SPA / 自定义 404 误报。
    let bflow = discovery::probe_flow(&origin, discovery::baseline_path());
    let baseline = match replay::send(&ReplayRequest::from_flow(&bflow), &cfg).await {
        Ok(r) => {
            eprintln!("[baseline] code={} bytes={}", r.status, r.resp_body.len());
            Some(discovery::build_baseline(&r))
        }
        Err(e) => {
            eprintln!("[baseline] 失败(本次不做基线压制): {e}");
            None
        }
    };

    println!("code     bytes  hit  kind    path");
    let mut findings = Vec::new();
    for entry in discovery::PATHS {
        let req = ReplayRequest::from_flow(&discovery::probe_flow(&origin, entry.path));
        match replay::send(&req, &cfg).await {
            Ok(resp) => {
                let f = discovery::evaluate_path(entry, &resp, baseline.as_ref());
                let kind = match entry.sig {
                    Sig::Exists => "exists",
                    Sig::BodyAny(_) => "sig",
                    Sig::Magic(_) => "magic",
                };
                println!(
                    "{:>4}  {:>8}  {:<3}  {:<6}  {}",
                    resp.status,
                    resp.resp_body.len(),
                    if f.is_some() { "HIT" } else { "-" },
                    kind,
                    entry.path
                );
                if let Some(f) = f {
                    findings.push(f);
                }
            }
            Err(e) => println!("ERR          -  -    -       {}  ({e})", entry.path),
        }
    }

    println!("\n==== FINDINGS ({}) ====", findings.len());
    for f in &findings {
        let sev = match f.severity {
            Severity::Critical => "CRIT",
            Severity::High => "HIGH",
            Severity::Medium => "MED ",
            Severity::Low => "LOW ",
            Severity::Info => "INFO",
        };
        println!("[{sev}] {}\n       {}\n       {}", f.title, f.url, f.detail);
    }
}
