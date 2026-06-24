//! Scry 代理 CLI —— 本地 MITM 抓包内核入口(测试 / headless 用)。
//!
//! 用法:`scry_proxy [--upstream <url>]` —— 监听 `127.0.0.1:8888`,把 curl `-x` /
//! 客户端 / sing-box·QX 上游 / Proxifier 指过来即可抓。`--upstream` 指定解密后回流的上游代理
//! (sing-box/QX 本地入站,墙内出网),如 `--upstream socks5://127.0.0.1:8899`。
//!
//! GUI(`scry_app`)是主入口:仪表盘按「抓什么」一键抓(内置浏览器 / 托管程序 / 对接代理客户端 / 被动嗅探)。

use anyhow::Result;
use scry_proxy::{run, ProxyConfig};
use scry_storage::Store;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "scry_proxy=info".into()),
        )
        .init();

    // 安装 rustls 加密后端(ring),与 rcgen 一致。
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    // 根 CA(TLS MITM 用;首次在 ~/.scry/ 生成,需导入系统信任才能解密)。
    let ca = Arc::new(scry_ca::Ca::load_or_create_default()?);
    tracing::info!(
        "根 CA 就绪:{}/ca.pem(HTTPS 解密前请导入系统信任)",
        scry_ca::default_ca_dir().display()
    );

    // 存储:请求先保存(save-first)。
    let store = Arc::new(Mutex::new(Store::open_default()?));
    tracing::info!("落盘:{}", scry_storage::default_db_path().display());

    let args: Vec<String> = std::env::args().collect();
    let mut config = ProxyConfig::default();
    if let Some(u) = arg_value(&args, "--upstream") {
        let up = scry_proxy::upstream::UpstreamProxy::parse(&u)?;
        tracing::info!("上游代理:{}://{}", up.kind(), up.addr());
        config.upstream = Some(up);
    }
    tracing::info!(
        "MITM 抓包内核监听 {}(把客户端 / curl -x / 上游指过来)",
        config.addr
    );
    run(config, store, ca).await
}

/// 取 `--key value` 形式参数的值。
fn arg_value(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
