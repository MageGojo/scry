//! 站点爬虫(Spider)—— **浏览器驱动**(drission / CDP 真实 Chrome),对标 Burp 的 Crawl。
//!
//! 生命周期受控:**scry 自己启动无头 Chrome**(带 CDP 调试端口),drission `connect` 接管驱动 →
//! Chrome 进程归 scry 管(`state.crawl_child`),**停止 / 爬完 / 关软件都统一 kill**,杜绝孤儿浏览器。
//!
//! 全站发现(对标 Burp,解决"未在首页链接的页也能被抓到"):
//! 1. **robots.txt + sitemap.xml**:开爬先拉(经 scry `replay`),把 `Sitemap:`/`Disallow:` 路径与
//!    `<loc>` URL **注入队列**——这是发现"孤立页"的关键。
//! 2. **渲染后 DOM**:真实浏览器执行 JS 后再 `tab.html()`,动态生成的 `<a>` 也在。
//! 3. **扫 JS / 内联文本**:`scry_crawl` 从脚本里的字符串再抠路由 / API / 文章路径。
//!
//! 页面流量(主文档 + 子资源 + XHR)经 MITM **自动解密落历史**;本模块只驱动导航 + BFS 调度。
//!
//! 线程模型:独立 OS 线程 + **多线程** tokio runtime `block_on` 串行驱动 CDP(CDP 需后台读循环);
//! 每抓一页经 `mpsc` 流式回传,前台 150ms 轮询并入「本次发现列表」+ 刷进度。

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use drission::prelude::ChromiumBrowser;
use mage_ui::prelude::*;
use scry_crawl::{parse_robots, parse_sitemap, CrawlConfig, Crawler};
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};

use crate::logger::LogLevel;
use crate::state::{CrawlMsg, CrawlVisited, ScryApp};

/// 爬虫控制位两态(存于 `AtomicU8`,后台逐页查询)。
const CRAWL_RUN: u8 = 0;
const CRAWL_STOP: u8 = 1;

/// 每页导航后额外静置等待(给 JS / XHR 渲染、生成动态链接的时间;CDP 后端无 `wait().secs`)。
const SETTLE_MS: u64 = 700;

/// 深度下拉可选值。
pub const DEPTH_OPTS: [usize; 5] = [1, 2, 3, 4, 5];
/// 页数上限下拉可选值。
pub const PAGES_OPTS: [usize; 6] = [20, 40, 60, 100, 200, 500];

impl ScryApp {
    /// 选择 BFS 深度(下拉 `idx`)。
    pub fn set_crawl_depth(&mut self, idx: usize, cx: &mut Context<Self>) {
        if let Some(v) = DEPTH_OPTS.get(idx) {
            self.crawl_depth = *v;
        }
        self.crawl_depth_open = false;
        cx.notify();
    }

    /// 选择页数上限(下拉 `idx`)。
    pub fn set_crawl_pages(&mut self, idx: usize, cx: &mut Context<Self>) {
        if let Some(v) = PAGES_OPTS.get(idx) {
            self.crawl_pages = *v;
        }
        self.crawl_pages_open = false;
        cx.notify();
    }

    /// 解析种子 URL 列表:输入框按空白 / 换行分隔,缺 scheme 补 `https://`;
    /// 输入为空时回退到当前扫描目标 host,再回退到首个抓到的 host。
    fn crawl_seed_list(&self, cx: &Context<Self>) -> Vec<String> {
        let raw = self.crawl_seed.read(cx).text().to_string();
        let mut seeds: Vec<String> = raw
            .split_whitespace()
            .map(normalize_seed)
            .filter(|s| !s.is_empty())
            .collect();
        if seeds.is_empty() {
            if let Some(h) = &self.scan_target {
                seeds.push(format!("https://{h}/"));
            } else if let Some(f) = self.flows.first() {
                seeds.push(format!("{}://{}/", f.scheme, f.host));
            }
        }
        seeds
    }

    /// 启动站点爬虫(浏览器驱动):scry 自启无头 Chrome → drission 接管 BFS → 流量经 MITM 落历史。
    pub fn start_crawl(&mut self, cx: &mut Context<Self>) {
        if self.crawl_busy {
            return;
        }
        let seeds = self.crawl_seed_list(cx);
        if seeds.is_empty() {
            self.push_log(
                LogLevel::Warning,
                "crawl",
                "站点爬虫跳过:请填写种子 URL(http(s)://…),或先抓到 / 选择一个目标",
            );
            self.crawl_progress = Some(
                if self.lang.is_zh() {
                    "请填写种子 URL(http(s)://…)"
                } else {
                    "Enter a seed URL (http(s)://…)"
                }
                .to_string(),
            );
            cx.notify();
            return;
        }

        // 浏览器驱动:必须有 MITM 内核(8888)在跑,无头 Chrome 流量才会被解密落历史。
        if !self.ensure_proxy_running(cx) {
            self.push_log(
                LogLevel::Warning,
                "crawl",
                "站点爬虫需要 MITM 代理内核;请先停止被动嗅探再爬",
            );
            return;
        }
        // 算 CA SPKI:给无头 Chrome 白名单 → 免装系统 CA、连 pinning 都过。
        let spki =
            match scry_ca::Ca::load_or_create_default().and_then(|ca| ca.spki_sha256_base64()) {
                Ok(s) => s,
                Err(e) => {
                    let msg = format!("计算 CA 指纹失败:{e:#}");
                    self.push_log(LogLevel::Error, "crawl", msg.clone());
                    self.crawl_progress = Some(msg);
                    cx.notify();
                    return;
                }
            };
        let port = scry_proxy::ProxyConfig::default().addr.port();

        // 由 scry 自启无头 Chrome(进程归 scry 管,生命周期可控),拿到 CDP 调试端口供后台 connect。
        let debug_port = match crate::launcher::launch_headless_browser_debug(port, &spki) {
            Ok((child, dp)) => {
                self.crawl_child = Some(child);
                dp
            }
            Err(e) => {
                let msg = format!("启动爬虫浏览器失败:{e:#}");
                self.push_log(LogLevel::Error, "crawl", msg.clone());
                self.crawl_progress = Some(msg);
                cx.notify();
                return;
            }
        };

        let cfg = CrawlConfig {
            max_depth: self.crawl_depth,
            max_pages: self.crawl_pages,
            same_host_only: true,
            include_subdomains: true,
        };
        let upstream = self.upstream_proxy(cx);
        // 记下主 host(种子 host),供「爬完自动审计」把扫描范围限到爬过的站。
        self.crawl_audit_host = seeds.first().and_then(|s| bare_host(s));
        self.crawl_busy = true;
        self.crawl_visited.clear();
        self.crawl_progress = Some(format!("0 / {}", self.crawl_pages));
        self.push_log(
            LogLevel::Info,
            "crawl",
            format!(
                "站点爬虫(浏览器驱动)开始 · 种子 {} · 深度 {} · 上限 {} 页",
                seeds.join(" "),
                self.crawl_depth,
                self.crawl_pages
            ),
        );

        let ctrl = Arc::new(AtomicU8::new(CRAWL_RUN));
        self.crawl_ctrl = Some(ctrl.clone());
        let (tx, rx) = mpsc::channel::<CrawlMsg>();
        self.crawl_rx = Some(rx);
        cx.notify();

        // 后台:独立 OS 线程 + 多线程 runtime 串行驱动 CDP 浏览器(CDP 需后台读循环)。
        std::thread::Builder::new()
            .name("scry-spider".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = tx.send(CrawlMsg {
                            fetched: 0,
                            discovered: 0,
                            url: None,
                            ok: false,
                            note: Some(format!("爬虫运行时创建失败:{e}")),
                            done: true,
                        });
                        return;
                    }
                };
                rt.block_on(run_browser_crawl(cfg, seeds, debug_port, upstream, ctrl, tx));
            })
            .ok();

        // 前台轮询:陆续到达的访问页并入「本次发现列表」、刷新进度;结束即收尾。
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                let keep_going = this.update(cx, |this, cx| {
                    this.drain_crawl_results(cx);
                    cx.notify();
                    this.crawl_busy
                });
                match keep_going {
                    Ok(true) => continue,
                    _ => break,
                }
            }
        })
        .detach();
    }

    /// 停止爬虫(置停止位 + 丢弃接收端 + 关浏览器;停在已抓到的页,保留「本次发现列表」)。
    pub fn stop_crawl(&mut self, cx: &mut Context<Self>) {
        if !self.crawl_busy {
            return;
        }
        if let Some(ctrl) = &self.crawl_ctrl {
            ctrl.store(CRAWL_STOP, Ordering::Relaxed);
        }
        self.crawl_busy = false;
        self.crawl_rx = None;
        self.crawl_ctrl = None;
        self.kill_crawl_browser();
        self.push_log(LogLevel::Warning, "crawl", "站点爬虫已停止");
        cx.notify();
    }

    /// 把通道里已到的访问结果并入「本次发现列表」(表头)、刷新进度;结束则收尾 + 关浏览器。
    fn drain_crawl_results(&mut self, cx: &mut Context<Self>) {
        let Some(rx) = &self.crawl_rx else {
            return;
        };
        let mut visited: Vec<CrawlVisited> = Vec::new();
        let mut notes: Vec<String> = Vec::new();
        let mut last: Option<(usize, usize)> = None;
        let mut done = false;
        while let Ok(msg) = rx.try_recv() {
            last = Some((msg.fetched, msg.discovered));
            if let Some(u) = msg.url {
                visited.push(CrawlVisited { url: u, ok: msg.ok });
            }
            if let Some(n) = msg.note {
                notes.push(n);
            }
            if msg.done {
                done = true;
            }
        }

        // 新访问的页插到表头(最新在前),封顶防内存无限增长。
        for v in visited {
            self.crawl_visited.insert(0, v);
        }
        const MAX: usize = 1000;
        if self.crawl_visited.len() > MAX {
            self.crawl_visited.truncate(MAX);
        }
        for n in notes {
            self.push_log(LogLevel::Warning, "crawl", n);
        }
        if let Some((fetched, discovered)) = last {
            self.crawl_progress = Some(self.crawl_progress_text(fetched, discovered));
        }
        if done {
            let (fetched, discovered) = last.unwrap_or((0, 0));
            self.crawl_busy = false;
            self.crawl_rx = None;
            self.crawl_ctrl = None;
            self.kill_crawl_browser();
            self.push_log(
                LogLevel::Success,
                "crawl",
                format!("站点爬虫完成 · 抓取 {fetched} 页 · 发现 {discovered} 个 URL"),
            );
            // Crawl → Audit:爬完(且抓到了页)自动把流量喂给扫描器(被动 + 主动)。
            if self.crawl_then_audit && fetched > 0 {
                self.start_crawl_audit(cx);
            }
        }
    }

    /// 切换「爬完自动审计」开关。
    pub fn toggle_crawl_audit(&mut self, cx: &mut Context<Self>) {
        self.crawl_then_audit = !self.crawl_then_audit;
        cx.notify();
    }

    /// Crawl → Audit 流水线:把扫描范围限到爬过的 host,跳到扫描器并跑被动 + 主动扫描。
    ///
    /// 爬虫流量已经过 MITM 落进历史(`self.flows`),这里只是把它们喂给现成的扫描引擎,
    /// 实现「爬 → 审」一键闭环(对标 Burp 的 crawl + audit)。
    fn start_crawl_audit(&mut self, cx: &mut Context<Self>) {
        // 若主 host 在抓到的流量里,就把扫描限定到它;否则扫全部(范围最稳)。
        self.scan_target = match &self.crawl_audit_host {
            Some(h) if self.scan_hosts().iter().any(|x| x == h) => Some(h.clone()),
            _ => None,
        };
        self.tab = crate::state::Tab::Scanner;
        self.push_log(
            LogLevel::Info,
            "crawl",
            format!(
                "Crawl → Audit:对爬过的站启动审计({})",
                self.crawl_audit_host.as_deref().unwrap_or("全部")
            ),
        );
        // 被动扫描(同步,即时出结果)+ 主动扫描(后台 replay,自带进度/可停止)。
        self.run_passive_scan(cx);
        self.run_active_scan(cx);
    }

    /// 进度文案(`抓取 X · 发现 Y`)。
    fn crawl_progress_text(&self, fetched: usize, discovered: usize) -> String {
        if self.lang.is_zh() {
            format!("抓取 {fetched} · 发现 {discovered}")
        } else {
            format!("fetched {fetched} · found {discovered}")
        }
    }
}

/// 后台:drission `connect` 接管 scry 自启的无头 Chrome,串行 BFS 抓站(经 scry MITM,流量自动落历史)。
async fn run_browser_crawl(
    cfg: CrawlConfig,
    seeds: Vec<String>,
    debug_port: u16,
    upstream: Option<scry_proxy::upstream::UpstreamProxy>,
    ctrl: Arc<AtomicU8>,
    tx: mpsc::Sender<CrawlMsg>,
) {
    // 连接 scry 已启动的无头 Chrome(retry 等它的 CDP 端口 ready,最多约 10s)。
    let ws = format!("http://127.0.0.1:{debug_port}");
    let mut connected = None;
    for _ in 0..50 {
        if ctrl.load(Ordering::Relaxed) == CRAWL_STOP {
            let _ = tx.send(done_msg(0, 0));
            return;
        }
        match ChromiumBrowser::connect(&ws).await {
            Ok(b) => {
                connected = Some(b);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
    let Some(browser) = connected else {
        let _ = tx.send(err_done("连接内置浏览器失败(CDP 未就绪)"));
        return;
    };
    let tab = match browser.new_tab(None).await {
        Ok(t) => t,
        Err(e) => {
            let _ = tx.send(err_done(&format!("打开标签页失败:{e}")));
            let _ = browser.quit().await;
            return;
        }
    };

    let mut crawler = Crawler::new(cfg, &seeds);

    // ① robots.txt + sitemap.xml 注入孤立页(对标 Burp 发现未链接页面)。经 scry replay 拉原始文本。
    let rcfg = ReplayConfig {
        upstream,
        ..Default::default()
    };
    let injected = seed_from_robots_sitemap(&seeds, &rcfg, &mut crawler).await;
    if injected > 0 {
        let _ = tx.send(CrawlMsg {
            fetched: crawler.fetched(),
            discovered: crawler.discovered(),
            url: Some(format!("robots/sitemap 注入 {injected} 个孤立 URL")),
            ok: true,
            note: None,
            done: false,
        });
    }

    // ② BFS:浏览器渲染每页 → 渲染后 DOM + JS 文本双重抽链(scry_crawl)。
    while let Some(item) = crawler.next_target() {
        if ctrl.load(Ordering::Relaxed) == CRAWL_STOP {
            break;
        }
        let nav = matches!(tab.get(&item.url).await, Ok(true));
        let _ = tab.wait_loaded().await;
        tokio::time::sleep(Duration::from_millis(SETTLE_MS)).await;
        let mut ok = nav;
        if nav {
            match tab.html().await {
                Ok(html) => {
                    crawler.feed(&item.url, item.depth, &html);
                }
                Err(_) => ok = false,
            }
        }
        let note = (!ok).then(|| format!("抓取失败 {}", item.url));
        if tx
            .send(CrawlMsg {
                fetched: crawler.fetched(),
                discovered: crawler.discovered(),
                url: Some(item.url),
                ok,
                note,
                done: false,
            })
            .is_err()
        {
            break; // 前台已丢弃接收端(用户点了停止)→ 结束。
        }
    }
    let _ = browser.quit().await; // 断开 + 尽力关 Chrome;scry 的 crawl_child 兜底 kill。
    let _ = tx.send(done_msg(crawler.fetched(), crawler.discovered()));
}

/// 拉每个种子 origin 的 robots.txt + sitemap.xml,把发现的路径 / URL 注入爬虫队列。返回注入数。
async fn seed_from_robots_sitemap(
    seeds: &[String],
    rcfg: &ReplayConfig,
    crawler: &mut Crawler,
) -> usize {
    let mut origins: Vec<String> = Vec::new();
    for s in seeds {
        if let Some(o) = origin_of(s) {
            if !origins.contains(&o) {
                origins.push(o);
            }
        }
    }
    let mut injected = 0usize;
    for origin in &origins {
        if let Some(txt) = fetch_text(&format!("{origin}/robots.txt"), rcfg).await {
            let h = parse_robots(&txt);
            for p in &h.paths {
                if crawler.enqueue(&format!("{origin}{p}"), 1) {
                    injected += 1;
                }
            }
            for sm in &h.sitemaps {
                injected += fetch_sitemap_into(sm, rcfg, crawler).await;
            }
        }
        injected += fetch_sitemap_into(&format!("{origin}/sitemap.xml"), rcfg, crawler).await;
    }
    injected
}

/// 拉一个 sitemap 并把其中 `<loc>` 注入队列;遇 sitemap index(子 sitemap)再下钻一层。返回注入数。
async fn fetch_sitemap_into(url: &str, rcfg: &ReplayConfig, crawler: &mut Crawler) -> usize {
    let Some(xml) = fetch_text(url, rcfg).await else {
        return 0;
    };
    let mut n = 0;
    for loc in parse_sitemap(&xml) {
        if loc.ends_with(".xml") && loc.to_ascii_lowercase().contains("sitemap") {
            // sitemap index:下钻一层(不再深入,防无限递归)。
            if let Some(sub) = fetch_text(&loc, rcfg).await {
                for l2 in parse_sitemap(&sub) {
                    if crawler.enqueue(&l2, 1) {
                        n += 1;
                    }
                }
            }
        } else if crawler.enqueue(&loc, 1) {
            n += 1;
        }
    }
    n
}

/// 经 scry `replay`(与抓包同上游)GET 一个 URL,返回解码后的文本正文(失败 / 4xx+ 返回 `None`)。
async fn fetch_text(url: &str, rcfg: &ReplayConfig) -> Option<String> {
    let host = host_of(url)?;
    let headers = vec![
        ("Host".to_string(), host),
        ("User-Agent".to_string(), "Scry-Spider/0.1".to_string()),
        ("Accept".to_string(), "*/*".to_string()),
    ];
    let req = ReplayRequest::from_url("GET", url, headers, Vec::new())?;
    let flow = replay::send(&req, rcfg).await.ok()?;
    if flow.status == 0 || flow.status >= 400 {
        return None;
    }
    Some(scry_decode::display_text(&flow.resp_headers, &flow.resp_body))
}

/// 取 URL 的 `scheme://authority`(含端口),用于拼 `/robots.txt`、`/sitemap.xml`。
fn origin_of(s: &str) -> Option<String> {
    let s = s.trim();
    let (scheme, rest) = s.split_once("://")?;
    if scheme.is_empty() || rest.is_empty() {
        return None;
    }
    let authority = rest.split('/').next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    (!authority.is_empty()).then(|| format!("{scheme}://{authority}"))
}

/// 取 URL 的 authority(`host[:port]`),作 `Host` 头。
fn host_of(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split('/').next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    (!authority.is_empty()).then(|| authority.to_string())
}

/// 取 URL 的**裸 host**(去端口),用于匹配抓到的流量 `host`(流量里 host 不含端口)。
fn bare_host(url: &str) -> Option<String> {
    let authority = host_of(url)?;
    let host = authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(&authority);
    (!host.is_empty()).then(|| host.to_string())
}

/// 构造一条"结束"消息。
fn done_msg(fetched: usize, discovered: usize) -> CrawlMsg {
    CrawlMsg {
        fetched,
        discovered,
        url: None,
        ok: true,
        note: None,
        done: true,
    }
}

/// 构造一条"出错并结束"消息。
fn err_done(note: &str) -> CrawlMsg {
    CrawlMsg {
        fetched: 0,
        discovered: 0,
        url: None,
        ok: false,
        note: Some(note.to_string()),
        done: true,
    }
}

/// 规范化种子:去空白;缺 `http(s)://` 时补 `https://`。
fn normalize_seed(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return String::new();
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        s.to_string()
    } else {
        format!("https://{s}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_seed_adds_scheme() {
        assert_eq!(normalize_seed("example.com"), "https://example.com");
        assert_eq!(normalize_seed(" http://x.io/a "), "http://x.io/a");
        assert_eq!(normalize_seed("https://y.io"), "https://y.io");
        assert_eq!(normalize_seed("   "), "");
    }

    #[test]
    fn origin_and_host_of_url() {
        assert_eq!(
            origin_of("https://example.com/a/b?x=1").as_deref(),
            Some("https://example.com")
        );
        assert_eq!(
            origin_of("http://h:8080/p").as_deref(),
            Some("http://h:8080")
        );
        assert_eq!(host_of("https://example.com:443/x").as_deref(), Some("example.com:443"));
        assert_eq!(host_of("not a url"), None);
    }

    #[test]
    fn bare_host_strips_port() {
        assert_eq!(bare_host("https://example.com/x").as_deref(), Some("example.com"));
        assert_eq!(bare_host("http://h:8080/p").as_deref(), Some("h"));
        assert_eq!(bare_host("nope"), None);
    }
}
