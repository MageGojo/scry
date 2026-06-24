//! 流量源启动器 —— **scry 自管流量源**(Burp 的杀手锏:不改系统代理,而是 scry 自己拉起客户端)。
//!
//! - **T1 内置浏览器**:拉起 Chromium 系浏览器,喂 `--proxy-server`(指向 MITM 内核)+
//!   `--ignore-certificate-errors-spki-list`(scry CA 的 SPKI → 免装系统 CA、连 pinning 都过)+
//!   独立 `--user-data-dir`(隔离日常浏览器)。走 HTTP 代理时 QUIC 自动失效,不会绕过。
//! - **T2 托管启动**:拉起任意程序 / 命令,注入 `HTTP(S)_PROXY` + 各运行时 CA 信任 + `SSLKEYLOGFILE`。
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

/// keylog 文件路径(给被动嗅探 / pcapng 兜底解密)。
pub fn keylog_path() -> PathBuf {
    scry_ca::default_ca_dir().join("sslkeylog.txt")
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

/// 找到第一个存在的 Chromium 系浏览器。
pub fn find_browser() -> Option<(String, PathBuf)> {
    browser_candidates()
        .into_iter()
        .find(|(_, p)| p.exists())
        .map(|(n, p)| (n.to_string(), p))
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

/// 把命令行字符串切成 `[程序, 参数…]`(支持双引号包裹含空格的参数)。
pub fn tokenize(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for ch in cmd.chars() {
        match ch {
            '"' => in_q = !in_q,
            c if c.is_whitespace() && !in_q => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// 托管程序需注入的环境变量矩阵(纯函数,可单测)——代理 + 各运行时 CA 信任 + keylog。
pub fn program_env(proxy_port: u16, ca_path: &Path, keylog: &Path) -> Vec<(String, String)> {
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    let ca = ca_path.display().to_string();
    let kl = keylog.display().to_string();
    vec![
        ("HTTP_PROXY".into(), proxy.clone()),
        ("http_proxy".into(), proxy.clone()),
        ("HTTPS_PROXY".into(), proxy.clone()),
        ("https_proxy".into(), proxy.clone()),
        ("ALL_PROXY".into(), proxy.clone()),
        ("all_proxy".into(), proxy),
        ("SSL_CERT_FILE".into(), ca.clone()), // curl / openssl / Python ssl
        ("CURL_CA_BUNDLE".into(), ca.clone()), // curl
        ("REQUESTS_CA_BUNDLE".into(), ca.clone()), // Python requests
        ("NODE_EXTRA_CA_CERTS".into(), ca.clone()), // Node.js
        ("GIT_SSL_CAINFO".into(), ca), // git
        ("SSLKEYLOGFILE".into(), kl), // 被动兜底解密
    ]
}

/// 托管启动一个程序 / 命令,返回 (程序名, 子进程句柄)。
pub fn launch_program(cmd: &str, proxy_port: u16, ca_path: &Path) -> Result<(String, Child)> {
    let toks = tokenize(cmd);
    let (prog, rest) = toks
        .split_first()
        .ok_or_else(|| anyhow!("请填写要启动的程序 / 命令"))?;
    let keylog = keylog_path();
    let mut c = Command::new(prog);
    c.args(rest);
    for (k, v) in program_env(proxy_port, ca_path, &keylog) {
        c.env(k, v);
    }
    let child = c
        .spawn()
        .with_context(|| format!("启动 {prog} 失败(确认程序名 / 路径正确)"))?;
    Ok((prog.clone(), child))
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

    /// T2:托管启动程序 / 命令抓包(起内核 → 注入代理 + CA env → 拉起程序)。
    pub fn launch_program_capture(&mut self, cx: &mut Context<Self>) {
        let cmd = self.prog_input.read(cx).text().to_string();
        let cmd = cmd.trim().to_string();
        if cmd.is_empty() {
            self.cert_msg = Some(if self.lang.is_zh() {
                "请先填写要启动的程序 / 命令,如:curl https://example.com".to_string()
            } else {
                "Enter a program / command first, e.g. curl https://example.com".to_string()
            });
            cx.notify();
            return;
        }
        if !self.ensure_proxy_running(cx) {
            return;
        }
        self.reap_finished(); // 先回收上次已退出的(curl 等一次性程序),避免句柄堆积
        let ca_path = crate::cert::ca_path();
        match launch_program(&cmd, proxy_port(), &ca_path) {
            Ok((prog, child)) => {
                self.launched.push(Launched {
                    child,
                    is_browser: false,
                });
                self.push_log(
                    LogLevel::Success,
                    "launch",
                    format!("已托管启动 {prog} · 已注入代理 + CA 信任"),
                );
                self.cert_msg = Some(if self.lang.is_zh() {
                    format!("已托管启动 {prog},其 HTTPS 流量将被解密抓取")
                } else {
                    format!("Launched {prog} with proxy + CA injected")
                });
                // 跳到 Proxy 页,让用户立刻看到被抓到的流量(curl 等一次性命令尤其需要)。
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

    /// 仅启动 MITM 抓包内核(供「对接代理客户端」:手动把客户端 / sing-box / Proxifier 指向 8888)。
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
    fn tokenize_respects_quotes() {
        assert_eq!(tokenize("curl https://x"), vec!["curl", "https://x"]);
        assert_eq!(
            tokenize("  python   app.py  --flag "),
            vec!["python", "app.py", "--flag"]
        );
        assert_eq!(
            tokenize("\"/Applications/My App\" --x 1"),
            vec!["/Applications/My App", "--x", "1"]
        );
        assert!(tokenize("   ").is_empty());
    }

    #[test]
    fn program_env_covers_proxy_and_ca_runtimes() {
        let env = program_env(8888, Path::new("/ca.pem"), Path::new("/kl"));
        let get = |k: &str| env.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
        assert_eq!(get("HTTPS_PROXY").as_deref(), Some("http://127.0.0.1:8888"));
        assert_eq!(get("https_proxy").as_deref(), Some("http://127.0.0.1:8888"));
        assert_eq!(get("SSL_CERT_FILE").as_deref(), Some("/ca.pem"));
        assert_eq!(get("NODE_EXTRA_CA_CERTS").as_deref(), Some("/ca.pem"));
        assert_eq!(get("REQUESTS_CA_BUNDLE").as_deref(), Some("/ca.pem"));
        assert_eq!(get("SSLKEYLOGFILE").as_deref(), Some("/kl"));
    }
}
