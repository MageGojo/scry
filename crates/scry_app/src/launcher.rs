//! 流量源启动器 —— **scry 自管流量源**(Burp 的杀手锏:不改系统代理,而是 scry 自己拉起客户端)。
//!
//! - **T1 内置浏览器**:拉起 Chromium 系浏览器,喂 `--proxy-server`(指向 MITM 内核)+
//!   `--ignore-certificate-errors-spki-list`(scry CA 的 SPKI → 免装系统 CA、连 pinning 都过)+
//!   独立 `--user-data-dir`(隔离日常浏览器)。走 HTTP 代理时 QUIC 自动失效,不会绕过。
//!
//! 纯逻辑(参数 / 环境 / 分词)做成可单测的自由函数;`impl ScryApp` 只做接线(起内核 + 拉起 + 记账)。

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::{anyhow, Context as _, Result};
use mage_ui::prelude::*;

use crate::logger::LogLevel;
use crate::state::{CaptureMode, ScryApp, Tab};

/// 一个被 scry 拉起的子进程(内置浏览器 / 托管程序)的记账。
///
/// 生命周期由 scry 掌控:停止抓包 / 退出时统一收掉;退出的进程由 [`ScryApp::reap_finished`]
/// 周期回收(`try_wait` 防僵尸句柄堆积);内置浏览器**去重**(已在运行则复用,不再拉起第二个)。
pub struct Launched {
    pub child: Child,
    /// 是否为内置浏览器(用于去重 / 单独关闭)。
    pub is_browser: bool,
}

/// scry 内置浏览器专用的独立用户数据目录(隔离日常浏览器;此目录在,SPKI 白名单才生效)。
pub fn browser_profile_dir() -> PathBuf {
    scry_ca::default_ca_dir().join("chrome-profile")
}

/// 候选 Chromium 系浏览器(macOS,按优先级:Chrome → Chromium → Edge → Brave)。
#[cfg(target_os = "macos")]
fn browser_candidates() -> Vec<(&'static str, PathBuf)> {
    [
        (
            "Google Chrome",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        ),
        ("Chromium", "/Applications/Chromium.app/Contents/MacOS/Chromium"),
        (
            "Microsoft Edge",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ),
        (
            "Brave",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        ),
    ]
    .into_iter()
    .map(|(n, p)| (n, PathBuf::from(p)))
    .collect()
}

#[cfg(not(target_os = "macos"))]
fn browser_candidates() -> Vec<(&'static str, PathBuf)> {
    Vec::new()
}

/// Chrome for Testing 可执行文件名(zip 内 `*.app/Contents/MacOS/` 下)。
const CFT_BIN_NAME: &str = "Google Chrome for Testing";

/// 运行时下载的 Chromium 存放目录 `~/.scry/chromium/`(零环境:目标机没装 Chrome 时下到这)。
pub fn chrome_for_testing_dir() -> PathBuf {
    scry_ca::default_ca_dir().join("chromium")
}

/// `.app` 内置 Chromium 目录(`Scry.app/Contents/Resources/chromium`,由 `build_mac.sh` 打包进去)。
fn bundled_chromium_dir() -> Option<PathBuf> {
    // 可执行文件在 .../Contents/MacOS/scry_app → 资源在 .../Contents/Resources/chromium
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?.parent()?.join("Resources").join("chromium");
    dir.is_dir().then_some(dir)
}

/// 在给定目录里找 Chrome for Testing 可执行文件(直接布局 + 解压常见的一层子目录,如 `chrome-mac-arm64/`)。
fn chromium_binary_in(dir: &Path) -> Option<PathBuf> {
    let app_rel = |base: &Path| {
        base.join(format!("{CFT_BIN_NAME}.app"))
            .join("Contents")
            .join("MacOS")
            .join(CFT_BIN_NAME)
    };
    let direct = app_rel(dir);
    if direct.exists() {
        return Some(direct);
    }
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let cand = app_rel(&p);
            if cand.exists() {
                return Some(cand);
            }
        }
    }
    None
}

/// 找一个可用的 Chromium 系浏览器,优先级:**`.app` 内置 → `~/.scry/chromium` 已下载 → 系统安装**。
/// 这让零环境出包(自带 Chromium)/ 首启自动下载 / 复用日常 Chrome 三种情况都能命中。
pub fn find_browser() -> Option<(String, PathBuf)> {
    if let Some(bin) = bundled_chromium_dir().as_deref().and_then(chromium_binary_in) {
        return Some(("Chrome for Testing(内置)".to_string(), bin));
    }
    if let Some(bin) = chromium_binary_in(&chrome_for_testing_dir()) {
        return Some(("Chrome for Testing".to_string(), bin));
    }
    browser_candidates()
        .into_iter()
        .find(|(_, p)| p.exists())
        .map(|(n, p)| (n.to_string(), p))
}

/// 当前平台对应的 Chrome for Testing 下载标识(macOS 按 CPU 架构区分)。
pub fn cft_platform() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "mac-arm64"
    } else {
        "mac-x64"
    }
}

/// 从 Chrome for Testing 版本清单 JSON 里取出指定平台的 Stable 版 chrome 下载地址(纯函数,可单测)。
pub fn parse_cft_download_url(json: &str, platform: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let arr = v
        .get("channels")?
        .get("Stable")?
        .get("downloads")?
        .get("chrome")?
        .as_array()?;
    arr.iter()
        .find(|item| item.get("platform").and_then(|p| p.as_str()) == Some(platform))
        .and_then(|item| item.get("url").and_then(|u| u.as_str()))
        .map(|s| s.to_string())
}

/// Chrome for Testing 版本清单地址(含各平台下载 URL)。
const CFT_VERSIONS_URL: &str =
    "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json";

/// 用 curl 取一段文本(版本清单很小)。
fn curl_text(url: &str) -> Result<String> {
    let out = Command::new("curl")
        .arg("-fsSL")
        .arg("--max-time")
        .arg("30")
        .arg(url)
        .output()
        .context("执行 curl 失败(系统缺 curl?)")?;
    if !out.status.success() {
        anyhow::bail!("curl 取版本清单失败(退出码 {:?})", out.status.code());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// 下载大文件到指定路径(终端机一定有 curl;`-fL` 跟随重定向、失败即报)。
fn download_file(url: &str, dest: &Path) -> Result<()> {
    let status = Command::new("curl")
        .arg("-fL")
        .arg("--retry")
        .arg("3")
        .arg("-o")
        .arg(dest)
        .arg(url)
        .status()
        .context("执行 curl 下载失败")?;
    if !status.success() || !dest.exists() {
        anyhow::bail!("下载失败(退出码 {:?})", status.code());
    }
    Ok(())
}

/// 运行时下载 Chrome for Testing 到 `~/.scry/chromium/` 并解压,返回可执行文件路径。**阻塞**,放后台线程调。
/// 已存在则直接复用,不重复下载。
pub fn download_chromium_blocking() -> Result<PathBuf> {
    let dir = chrome_for_testing_dir();
    if let Some(bin) = chromium_binary_in(&dir) {
        return Ok(bin); // 已下载过
    }
    std::fs::create_dir_all(&dir).context("创建 chromium 目录失败")?;
    let platform = cft_platform();
    let json = curl_text(CFT_VERSIONS_URL)
        .context("获取 Chrome for Testing 版本清单失败(需联网 / 科学上网)")?;
    let url = parse_cft_download_url(&json, platform)
        .ok_or_else(|| anyhow!("版本清单里找不到 {platform} 的 Chrome 下载地址"))?;
    let zip = dir.join("chrome.zip");
    download_file(&url, &zip).context("下载 Chrome for Testing 失败")?;
    // ditto 解压 macOS zip(正确还原 .app 结构与权限)。
    let status = Command::new("ditto")
        .arg("-x")
        .arg("-k")
        .arg(&zip)
        .arg(&dir)
        .status()
        .context("解压失败(ditto)")?;
    let _ = std::fs::remove_file(&zip);
    if !status.success() {
        anyhow::bail!("解压 Chrome for Testing 失败");
    }
    let bin = chromium_binary_in(&dir).ok_or_else(|| anyhow!("解压后未找到 Chrome 可执行文件"))?;
    // 去隔离属性,免首启被 Gatekeeper 拦(它是我们自己下的,非分发物)。
    if let Some(app) = bin
        .ancestors()
        .find(|p| p.extension().is_some_and(|e| e == "app"))
    {
        let _ = Command::new("xattr")
            .arg("-dr")
            .arg("com.apple.quarantine")
            .arg(app)
            .status();
    }
    Ok(bin)
}

/// 内置浏览器启动参数(纯函数,可单测)。
pub fn browser_args(proxy_port: u16, spki: &str, profile_dir: &Path) -> Vec<String> {
    vec![
        format!("--proxy-server=http://127.0.0.1:{proxy_port}"),
        format!("--ignore-certificate-errors-spki-list={spki}"),
        format!("--user-data-dir={}", profile_dir.display()),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
    ]
}

/// 启动内置浏览器,返回 (浏览器名, 子进程句柄)。
pub fn launch_browser(proxy_port: u16, spki: &str) -> Result<(String, Child)> {
    let (name, bin) = find_browser().ok_or_else(|| {
        anyhow!("未找到 Chromium 系浏览器,请先安装 Google Chrome / Chromium / Edge / Brave")
    })?;
    let dir = browser_profile_dir();
    std::fs::create_dir_all(&dir).ok();
    let child = Command::new(&bin)
        .args(browser_args(proxy_port, spki, &dir))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("启动 {name} 失败"))?;
    Ok((name, child))
}

/// 爬虫专用:启动**无头** Chrome 并开 CDP 调试端口,供 drission `connect` 接管驱动。
/// 进程句柄交回调用方(scry)纳入受控生命周期(停止 / 爬完 / 关软件统一 kill);返回 (子进程, 调试端口)。
pub fn launch_headless_browser_debug(proxy_port: u16, spki: &str) -> Result<(Child, u16)> {
    let (_, bin) = find_browser().ok_or_else(|| {
        anyhow!("未找到 Chromium 系浏览器,请先安装 Google Chrome / Chromium / Edge / Brave")
    })?;
    // 取一个空闲端口给 CDP(bind 后立即释放,交给 Chrome 用)。
    let debug_port = std::net::TcpListener::bind("127.0.0.1:0")
        .context("分配 CDP 调试端口失败")?
        .local_addr()
        .context("读取调试端口失败")?
        .port();
    // 爬虫独立 profile(隔离日常浏览器;SPKI 白名单也要求独立 user-data-dir 才生效)。
    let dir = scry_ca::default_ca_dir().join("spider-profile");
    std::fs::create_dir_all(&dir).ok();
    // 清上次残留的单例锁,避免新实例被判 profile 占用而秒退。
    for stale in ["SingletonLock", "SingletonCookie", "SingletonSocket", "DevToolsActivePort"] {
        let _ = std::fs::remove_file(dir.join(stale));
    }
    let child = Command::new(&bin)
        .arg(format!("--remote-debugging-port={debug_port}"))
        .arg("--headless=new")
        .arg(format!("--proxy-server=http://127.0.0.1:{proxy_port}"))
        .arg(format!("--ignore-certificate-errors-spki-list={spki}"))
        .arg(format!("--user-data-dir={}", dir.display()))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-background-networking")
        .arg("--disable-gpu")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("启动爬虫浏览器失败")?;
    Ok((child, debug_port))
}

/// MITM 内核监听端口(8888)。
fn proxy_port() -> u16 {
    scry_proxy::ProxyConfig::default().addr.port()
}

impl ScryApp {
    /// 确保 MITM 抓包内核在跑(T1/T2 都要经它)。返回 true 表示已就绪。
    ///
    /// - 未抓包 → 切到代理模式并启动;
    /// - 已在代理模式抓包 → 直接复用;
    /// - 正在被动嗅探 → 提示先停止(嗅探无 8888 代理可用)。
    pub(crate) fn ensure_proxy_running(&mut self, cx: &mut Context<Self>) -> bool {
        if self.capturing {
            if self.capture_mode == CaptureMode::Proxy {
                return true;
            }
            self.cert_msg = Some(if self.lang.is_zh() {
                "请先停止被动嗅探:内置浏览器 / 托管启动走 MITM 代理内核".to_string()
            } else {
                "Stop passive sniffing first: launchers use the MITM proxy core".to_string()
            });
            cx.notify();
            return false;
        }
        self.capture_mode = CaptureMode::Proxy;
        self.start_capture(cx);
        self.capturing
    }

    /// 回收已退出的子进程(防僵尸句柄堆积):`try_wait` 命中退出即移出记账表。
    /// 周期调用(抓包推流每拍)+ 启动前调用,确保「浏览器是否在运行」判断准确。
    pub fn reap_finished(&mut self) {
        self.launched
            .retain_mut(|l| matches!(l.child.try_wait(), Ok(None)));
    }

    /// 是否有 scry 拉起的内置浏览器仍在运行(只读,不回收;回收在 [`Self::reap_finished`])。
    pub fn has_browser(&self) -> bool {
        self.launched.iter().any(|l| l.is_browser)
    }

    /// 单独关闭 scry 拉起的内置浏览器(不停止抓包)。
    pub fn close_browser(&mut self, cx: &mut Context<Self>) {
        let mut closed = 0usize;
        self.launched.retain_mut(|l| {
            if l.is_browser {
                let _ = l.child.kill();
                let _ = l.child.wait();
                closed += 1;
                false
            } else {
                true
            }
        });
        if closed > 0 {
            self.push_log(LogLevel::Info, "launch", "已关闭内置浏览器");
            self.cert_msg = Some(if self.lang.is_zh() {
                "已关闭内置浏览器".to_string()
            } else {
                "Built-in browser closed".to_string()
            });
        }
        cx.notify();
    }

    /// T1:启动内置浏览器抓包(起内核 → 算 CA SPKI → 拉起浏览器)。**去重**:已在运行则复用,不再拉起第二个。
    pub fn launch_browser_capture(&mut self, cx: &mut Context<Self>) {
        self.reap_finished();
        if self.has_browser() {
            self.cert_msg = Some(if self.lang.is_zh() {
                "内置浏览器已在运行 —— 在它里面访问目标即可(或点「关闭浏览器」)".to_string()
            } else {
                "Built-in browser is already running — browse in it (or click Close browser)".to_string()
            });
            cx.notify();
            return;
        }
        if !self.ensure_proxy_running(cx) {
            return;
        }
        let spki = match scry_ca::Ca::load_or_create_default().and_then(|ca| ca.spki_sha256_base64())
        {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("计算 CA 指纹失败:{e:#}");
                self.push_log(LogLevel::Error, "launch", msg.clone());
                self.cert_msg = Some(msg);
                cx.notify();
                return;
            }
        };
        match launch_browser(proxy_port(), &spki) {
            Ok((name, child)) => {
                self.launched.push(Launched {
                    child,
                    is_browser: true,
                });
                self.push_log(
                    LogLevel::Success,
                    "launch",
                    format!("已启动内置浏览器 {name} · 解密抓包中(免装系统 CA、过 pinning)"),
                );
                self.cert_msg = Some(if self.lang.is_zh() {
                    format!("已启动内置浏览器 {name},在它里面访问目标即可看到解密流量")
                } else {
                    format!("Launched {name}. Browse your target in it to see decrypted traffic")
                });
                // 跳到 Proxy 页,让用户立刻看到解密流量进来(否则停在仪表盘易以为没生效)。
                self.tab = Tab::Proxy;
            }
            Err(e) => {
                let msg = format!("{e:#}");
                self.push_log(LogLevel::Error, "launch", msg.clone());
                self.cert_msg = Some(msg);
            }
        }
        cx.notify();
    }

    /// 下载内置浏览器(Chrome for Testing → `~/.scry/chromium/`),供目标机没装 Chrome 时一键抓网站。
    /// 后台跑 curl + ditto,完成后回主线程提示;下完即可点「启动浏览器抓包」。
    pub fn download_chromium(&mut self, cx: &mut Context<Self>) {
        if self.chromium_downloading {
            return;
        }
        self.chromium_downloading = true;
        self.cert_msg = Some(if self.lang.is_zh() {
            "正在下载内置浏览器 Chrome for Testing(约 150–200MB,需联网)…".to_string()
        } else {
            "Downloading built-in Chrome for Testing (~150–200MB)…".to_string()
        });
        self.push_log(LogLevel::Info, "launch", "开始下载内置浏览器 Chrome for Testing");
        cx.notify();

        let task = cx
            .background_executor()
            .spawn(async move { download_chromium_blocking().map_err(|e| format!("{e:#}")) });
        cx.spawn(async move |this, cx| {
            let res = task.await;
            let _ = this.update(cx, |this, cx| {
                this.chromium_downloading = false;
                match res {
                    Ok(_) => {
                        let msg = if this.lang.is_zh() {
                            "内置浏览器已就绪 —— 点「启动浏览器抓包」即可".to_string()
                        } else {
                            "Built-in browser ready — click Launch browser capture".to_string()
                        };
                        this.push_log(LogLevel::Success, "launch", msg.clone());
                        this.cert_msg = Some(msg);
                    }
                    Err(e) => {
                        this.push_log(LogLevel::Error, "launch", format!("下载内置浏览器失败:{e}"));
                        this.cert_msg = Some(if this.lang.is_zh() {
                            format!("下载内置浏览器失败:{e}")
                        } else {
                            format!("Download built-in browser failed: {e}")
                        });
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// 仅启动 MITM 抓包内核(供「对接 Proxifier」:把 Proxifier 代理指向 8888,按进程喂流量)。
    pub fn start_core_capture(&mut self, cx: &mut Context<Self>) {
        if self.ensure_proxy_running(cx) {
            self.cert_msg = Some(if self.lang.is_zh() {
                "MITM 内核已就绪 127.0.0.1:8888 — 把客户端代理 / sing-box 上游指向它即可".to_string()
            } else {
                "MITM core ready on 127.0.0.1:8888 — point your client / sing-box upstream here".to_string()
            });
            cx.notify();
        }
    }

    /// 收掉所有被 scry 拉起的子进程(停止抓包时调用)。
    pub fn kill_launched(&mut self) {
        for mut l in self.launched.drain(..) {
            let _ = l.child.kill();
            let _ = l.child.wait();
        }
    }

    /// 收掉爬虫的无头浏览器(停止 / 爬完 / 关软件时调用),杜绝孤儿 Chrome。
    pub fn kill_crawl_browser(&mut self) {
        if let Some(mut c) = self.crawl_child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// 兜底:scry 视图析构(窗口关闭 / 退出)时收掉拉起的进程,避免内置浏览器变孤儿残留。
/// (硬崩溃不走 Drop;正常退出 / 停止抓包仍是主清理路径。)
impl Drop for ScryApp {
    fn drop(&mut self) {
        for l in &mut self.launched {
            let _ = l.child.kill();
            let _ = l.child.wait();
        }
        // 爬虫的无头浏览器一并收掉,避免关软件后 Chrome 残留(孤儿)。
        if let Some(c) = &mut self.crawl_child {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_args_have_proxy_spki_profile() {
        let args = browser_args(8888, "ABC=", Path::new("/tmp/p"));
        assert!(args.iter().any(|a| a == "--proxy-server=http://127.0.0.1:8888"));
        assert!(args
            .iter()
            .any(|a| a == "--ignore-certificate-errors-spki-list=ABC="));
        assert!(args.iter().any(|a| a == "--user-data-dir=/tmp/p"));
        assert!(args.iter().any(|a| a == "--no-first-run"));
    }

    #[test]
    fn cft_platform_is_a_mac_target() {
        assert!(matches!(cft_platform(), "mac-arm64" | "mac-x64"));
    }

    #[test]
    fn parse_cft_url_picks_right_platform() {
        let json = r#"{
            "channels": {
                "Stable": {
                    "version": "120.0.0.0",
                    "downloads": {
                        "chrome": [
                            {"platform": "linux64", "url": "https://x/linux64/chrome-linux64.zip"},
                            {"platform": "mac-arm64", "url": "https://x/mac-arm64/chrome-mac-arm64.zip"},
                            {"platform": "mac-x64", "url": "https://x/mac-x64/chrome-mac-x64.zip"}
                        ]
                    }
                }
            }
        }"#;
        assert_eq!(
            parse_cft_download_url(json, "mac-arm64").as_deref(),
            Some("https://x/mac-arm64/chrome-mac-arm64.zip")
        );
        assert_eq!(
            parse_cft_download_url(json, "mac-x64").as_deref(),
            Some("https://x/mac-x64/chrome-mac-x64.zip")
        );
        assert_eq!(parse_cft_download_url(json, "win64"), None);
        assert_eq!(parse_cft_download_url("not json", "mac-arm64"), None);
    }
}
