//! 通用 Repeater CLI —— 直接驱动 scry 的发包内核 [`scry_proxy::replay`]
//! (与 GUI「重放 / Repeater」页同一条发送路径)对任意 HTTP(S) 端点发送
//! **可完全自定义**的请求。黑盒打靶 / 调试用。
//!
//! 用法:
//! ```text
//! cargo run -p scry_proxy --example req -- [选项] <URL>
//! ```
//! 选项:
//! - `-X, --method <M>`       HTTP 方法(默认 GET)
//! - `-H, --header "K: V"`    追加请求头(可多次;给出 Host 会覆盖默认补全)
//! - `-d, --data <BODY>`      请求体(字符串)
//! - `    --data-file <PATH>` 从文件读取请求体
//! - `    --race <N>`         并发发 N 个完全相同的请求(竞态条件题用)
//! - `-i, --head`             只打印状态行 + 响应头
//! - `-s, --silent`           只打印响应体
//!
//! 自动行为:未自定义时补 Host / User-Agent / Accept;body 非空时补 Content-Length;
//! **不跟随重定向**(原样返回 3xx + Location);每次请求按指纹去重落盘到
//! `/tmp/scry_lab/flows/`(save-first)。

use scry_core::{Header, HttpFlow};
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};

struct Args {
    method: String,
    url: String,
    headers: Vec<Header>,
    body: Vec<u8>,
    race: usize,
    head_only: bool,
    silent: bool,
}

fn parse_args() -> Option<Args> {
    let mut a = Args {
        method: "GET".into(),
        url: String::new(),
        headers: Vec::new(),
        body: Vec::new(),
        race: 1,
        head_only: false,
        silent: false,
    };
    let mut url = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-X" | "--method" => a.method = it.next()?,
            "-H" | "--header" => {
                let h = it.next()?;
                if let Some((k, v)) = h.split_once(':') {
                    a.headers.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
            "-d" | "--data" => a.body = it.next()?.into_bytes(),
            "--data-file" => a.body = std::fs::read(it.next()?).ok()?,
            "--race" => a.race = it.next()?.parse().ok()?,
            "-i" | "--head" => a.head_only = true,
            "-s" | "--silent" => a.silent = true,
            other => url = Some(other.to_string()),
        }
    }
    a.url = url?;
    Some(a)
}

/// 未显式给出时补齐 Host / UA / Accept / Content-Length。
fn apply_defaults(rr: &mut ReplayRequest, body: &[u8]) {
    let has = |hs: &[Header], name: &str| hs.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
    if !has(&rr.headers, "host") {
        let host = if (rr.scheme == "https" && rr.port == 443)
            || (rr.scheme == "http" && rr.port == 80)
        {
            rr.host.clone()
        } else {
            format!("{}:{}", rr.host, rr.port)
        };
        rr.headers.insert(0, ("Host".into(), host));
    }
    if !has(&rr.headers, "user-agent") {
        rr.headers.push(("User-Agent".into(), "scry-repeater/1.0".into()));
    }
    if !has(&rr.headers, "accept") {
        rr.headers.push(("Accept".into(), "*/*".into()));
    }
    if !body.is_empty() && !has(&rr.headers, "content-length") {
        rr.headers.push(("Content-Length".into(), body.len().to_string()));
    }
}

/// save-first:每条往返按指纹落一个文件(同指纹覆盖 = 去重)。
fn save_flow(f: &HttpFlow) {
    let dir = "/tmp/scry_lab/flows";
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let fp = f.fingerprint();
    let short = &fp[..fp.len().min(12)];
    let path = format!("{dir}/{}_{}.txt", f.method, short);
    let mut out = String::new();
    out.push_str(&format!("# {} {}\n# status {} ({} ms)\n\n", f.method, f.url(), f.status, f.duration_ms));
    for (k, v) in &f.resp_headers {
        out.push_str(&format!("{k}: {v}\n"));
    }
    out.push('\n');
    out.push_str(&String::from_utf8_lossy(&f.resp_body));
    let _ = std::fs::write(path, out);
}

fn print_flow(f: &HttpFlow, head_only: bool, silent: bool) {
    if !silent {
        println!("HTTP {} ({} ms)", f.status, f.duration_ms);
        for (k, v) in &f.resp_headers {
            println!("{k}: {v}");
        }
        println!();
    }
    if !head_only {
        println!("{}", String::from_utf8_lossy(&f.resp_body));
    }
}

fn main() {
    let Some(args) = parse_args() else {
        eprintln!("用法: cargo run -p scry_proxy --example req -- [-X M] [-H \"K: V\"]... [-d BODY] [--race N] <URL>");
        std::process::exit(2);
    };
    let Some(mut rr) =
        ReplayRequest::from_url(&args.method, &args.url, Vec::new(), args.body.clone())
    else {
        eprintln!("无效 URL: {}", args.url);
        std::process::exit(2);
    };
    rr.headers = args.headers.clone();
    apply_defaults(&mut rr, &args.body);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("build tokio runtime");
    let cfg = ReplayConfig::default();

    if args.race > 1 {
        rt.block_on(async {
            let mut handles = Vec::new();
            for _ in 0..args.race {
                let rr = rr.clone();
                let cfg = cfg.clone();
                handles.push(tokio::spawn(async move { replay::send(&rr, &cfg).await }));
            }
            let mut statuses = Vec::new();
            for (i, h) in handles.into_iter().enumerate() {
                match h.await.expect("join") {
                    Ok(f) => {
                        save_flow(&f);
                        statuses.push(f.status);
                        println!("=== race #{i} ===");
                        print_flow(&f, args.head_only, args.silent);
                    }
                    Err(e) => eprintln!("race #{i} ERR: {e}"),
                }
            }
            eprintln!("[race x{}] statuses = {:?}", args.race, statuses);
        });
    } else {
        rt.block_on(async {
            match replay::send(&rr, &cfg).await {
                Ok(f) => {
                    save_flow(&f);
                    print_flow(&f, args.head_only, args.silent);
                }
                Err(e) => {
                    eprintln!("ERR: {e}");
                    std::process::exit(1);
                }
            }
        });
    }
}
