//! XSS 页:**dalfox 式**上下文感知反射型 XSS 检测。
//!
//! 选一条请求(可从代理右键「发送到 XSS」带入)+ 注入点,后台对每个注入点:
//! **反射定位 → 上下文识别 → 可利用字符探测 → 按上下文合成载荷 → 反射验证**,并静态提示 DOM sink。
//! 引擎是纯函数 [`scry_xss`],发包复用 [`scry_proxy::replay`](与 SQLi / 扫描器 / 爆破同一条 async 路径)。
//!
//! ⚠️ 主动注入会向目标发送脚本载荷,**只对你已获授权的目标使用**。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::time::Duration;

use drission::prelude::ChromiumBrowser;
use mage_ui::prelude::*;
use scry_core::HttpFlow;
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};
use scry_proxy::upstream::UpstreamProxy;
use scry_xss::{
    abusable_chars, build_probe, canary, detect_context, dom_sinks, exec_vectors, injection_points,
    reflections, synthesize, InjectionPoint, Location, Payload, EXEC_MARK, REFLECT_MARK,
};

use crate::logger::LogLevel;
use crate::repeater::{parse_raw_request, render_raw_request, target_string};
use crate::state::{ScryApp, SqliLevel, SqliLine, XssFinding, XssMsg};
use crate::widgets::{divider, section_label};

/// 自动模式下最多测试的注入点数。
const CANDIDATE_CAP: usize = 16;
/// 测试日志最多保留行数。
const XSS_LOG_CAP: usize = 600;

// ───────────────────────── 后台 runner ─────────────────────────

fn log_line(tx: &Sender<XssMsg>, level: SqliLevel, text: impl Into<String>) {
    let _ = tx.send(XssMsg {
        line: Some(SqliLine {
            level,
            text: text.into(),
        }),
        finding: None,
        sinks: None,
        progress: None,
        done: false,
    });
}

fn push_finding(tx: &Sender<XssMsg>, f: XssFinding) {
    let _ = tx.send(XssMsg {
        line: None,
        finding: Some(f),
        sinks: None,
        progress: None,
        done: false,
    });
}

fn set_sinks(tx: &Sender<XssMsg>, sinks: Vec<String>) {
    let _ = tx.send(XssMsg {
        line: None,
        finding: None,
        sinks: Some(sinks),
        progress: None,
        done: false,
    });
}

fn log_prog(tx: &Sender<XssMsg>, p: impl Into<String>) {
    let _ = tx.send(XssMsg {
        line: None,
        finding: None,
        sinks: None,
        progress: Some(p.into()),
        done: false,
    });
}

fn finish(tx: &Sender<XssMsg>, p: impl Into<String>) {
    let _ = tx.send(XssMsg {
        line: None,
        finding: None,
        sinks: None,
        progress: Some(p.into()),
        done: true,
    });
}

fn flow_from_req(r: &ReplayRequest) -> HttpFlow {
    HttpFlow::request(
        &r.method,
        &r.scheme,
        r.host.clone(),
        r.port,
        r.path.clone(),
        r.headers.clone(),
        r.body.clone(),
    )
}

fn decode_body(flow: &HttpFlow) -> String {
    if flow.resp_body.is_empty() {
        String::new()
    } else {
        scry_decode::display_text(&flow.resp_headers, &flow.resp_body)
    }
}

/// 发一条变异探测请求,返回解码后的响应体(失败 = `None`)。
async fn fetch_body(probe: &HttpFlow, cfg: &ReplayConfig) -> Option<String> {
    let resp = replay::send(&ReplayRequest::from_flow(probe), cfg).await.ok()?;
    Some(decode_body(&resp))
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n).collect();
        format!("{t}…")
    }
}

/// 整条 XSS 测试流程;全程经 `tx` 流式回传日志 / 发现 / DOM sink / 进度。
async fn run_xss(
    base_req: ReplayRequest,
    points: Vec<InjectionPoint>,
    upstream: Option<UpstreamProxy>,
    ctrl: Arc<AtomicBool>,
    tx: Sender<XssMsg>,
) {
    let cfg = ReplayConfig {
        upstream,
        ..Default::default()
    };
    let base_flow = flow_from_req(&base_req);

    // 基线:静态扫一遍 DOM sink(信息性提示)。
    if let Ok(bl) = replay::send(&base_req, &cfg).await {
        let body = decode_body(&bl);
        let sinks: Vec<String> = dom_sinks(&body).iter().map(|s| s.to_string()).collect();
        if !sinks.is_empty() {
            log_line(
                &tx,
                SqliLevel::Warn,
                format!("发现 {} 个危险 DOM sink(可能存在 DOM 型 XSS,需结合来源排查)", sinks.len()),
            );
            set_sinks(&tx, sinks);
        }
    }

    let mut confirmed = 0usize;
    let mut reflected = 0usize;

    for (pi, point) in points.iter().enumerate() {
        if ctrl.load(Ordering::Relaxed) {
            finish(&tx, "已停止");
            return;
        }
        log_prog(&tx, format!("测试注入点 {}/{}", pi + 1, points.len()));
        log_line(
            &tx,
            SqliLevel::Info,
            format!("▶ 注入点 [{}] 原值「{}」", point.label(), truncate(&point.value, 40)),
        );

        // 1) 反射定位 + 上下文识别。
        let plain = build_probe(&base_flow, point, REFLECT_MARK);
        let Some(plain_body) = fetch_body(&plain, &cfg).await else {
            log_line(&tx, SqliLevel::Bad, format!("注入点 [{}] 请求失败", point.label()));
            continue;
        };
        let offs = reflections(&plain_body, REFLECT_MARK);
        if offs.is_empty() {
            log_line(&tx, SqliLevel::Info, format!("注入点 [{}] 未反射", point.label()));
            continue;
        }
        reflected += 1;
        let ctx = detect_context(&plain_body, offs[0]);
        log_line(
            &tx,
            SqliLevel::Info,
            format!("注入点 [{}] 反射于「{}」上下文,共 {} 处", point.label(), ctx.label(), offs.len()),
        );

        // 2) 可利用字符探测。
        if ctrl.load(Ordering::Relaxed) {
            finish(&tx, "已停止");
            return;
        }
        let canary_probe = build_probe(&base_flow, point, &canary());
        let ab = match fetch_body(&canary_probe, &cfg).await {
            Some(b) => abusable_chars(&b),
            None => {
                log_line(&tx, SqliLevel::Warn, "金丝雀请求失败,跳过该点");
                continue;
            }
        };

        // 3) 按上下文合成**多个候选载荷**(含 WAF 绕过变体),逐个验证,首个成功即确认。
        let candidates = synthesize(ctx, ab);
        if candidates.is_empty() {
            log_line(
                &tx,
                SqliLevel::Warn,
                format!("[{}] 反射但危险字符被编码,当前上下文不可利用", point.label()),
            );
            push_finding(
                &tx,
                XssFinding {
                    point: point.label(),
                    confirmed: false,
                    context: ctx.label(),
                    payload: None,
                    kind: None,
                },
            );
            continue;
        }
        let total = candidates.len();
        let mut hit: Option<Payload> = None;
        for p in candidates {
            if ctrl.load(Ordering::Relaxed) {
                finish(&tx, "已停止");
                return;
            }
            let probe = build_probe(&base_flow, point, &p.value);
            let ok = fetch_body(&probe, &cfg)
                .await
                .map(|b| b.contains(&p.proof))
                .unwrap_or(false);
            if ok {
                hit = Some(p);
                break;
            }
        }
        match hit {
            Some(p) => {
                confirmed += 1;
                log_line(
                    &tx,
                    SqliLevel::Good,
                    format!("✓ 确认 XSS![{}] {} · {} · 载荷 {}", point.label(), ctx.label(), p.kind, p.value),
                );
                push_finding(
                    &tx,
                    XssFinding {
                        point: point.label(),
                        confirmed: true,
                        context: ctx.label(),
                        payload: Some(p.value),
                        kind: Some(p.kind),
                    },
                );
            }
            None => {
                log_line(
                    &tx,
                    SqliLevel::Warn,
                    format!("[{}] 反射但 {total} 个候选载荷均未原样回显(疑似过滤 / WAF)", point.label()),
                );
                push_finding(
                    &tx,
                    XssFinding {
                        point: point.label(),
                        confirmed: false,
                        context: ctx.label(),
                        payload: None,
                        kind: None,
                    },
                );
            }
        }
    }

    finish(
        &tx,
        format!("完成:{confirmed} 处可利用 · {reflected} 处反射"),
    );
}

/// 后台:drission `connect` 接管 scry 自启的无头 Chrome,逐查询注入点导航执行向量,捕获 `alert` 弹窗即确认。
async fn run_xss_dom(
    base_flow: HttpFlow,
    points: Vec<InjectionPoint>,
    debug_port: u16,
    ctrl: Arc<AtomicBool>,
    tx: Sender<XssMsg>,
) {
    let ws = format!("http://127.0.0.1:{debug_port}");
    let mut connected = None;
    for _ in 0..50 {
        if ctrl.load(Ordering::Relaxed) {
            finish(&tx, "已停止");
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
        log_line(&tx, SqliLevel::Bad, "连接验证浏览器失败(CDP 未就绪)");
        finish(&tx, "失败");
        return;
    };
    let tab = match browser.new_tab(None).await {
        Ok(t) => t,
        Err(e) => {
            log_line(&tx, SqliLevel::Bad, format!("打开标签页失败:{e}"));
            let _ = browser.quit().await;
            finish(&tx, "失败");
            return;
        }
    };

    let mut confirmed = 0usize;
    let vectors = exec_vectors();
    for (pi, point) in points.iter().enumerate() {
        if ctrl.load(Ordering::Relaxed) {
            break;
        }
        log_prog(&tx, format!("验证注入点 {}/{}", pi + 1, points.len()));
        log_line(&tx, SqliLevel::Info, format!("▶ 浏览器验证 [{}]", point.label()));
        let mut hit: Option<(String, &'static str)> = None;
        for (value, kind) in &vectors {
            if ctrl.load(Ordering::Relaxed) {
                break;
            }
            let url = build_probe(&base_flow, point, value).url();
            // 导航 + 等待下一个对话框并发跑:载荷的 onload/onerror 触发 alert → handle_next_dialog 捕获并消解。
            let dlg = tab.handle_next_dialog(true, None);
            let nav = tab.get(&url);
            let (_n, dres) = tokio::join!(nav, tokio::time::timeout(Duration::from_millis(2500), dlg));
            let fired = matches!(dres, Ok(Ok(info)) if info.message.contains(EXEC_MARK));
            if fired {
                hit = Some((value.clone(), *kind));
                break;
            }
        }
        match hit {
            Some((value, kind)) => {
                confirmed += 1;
                log_line(
                    &tx,
                    SqliLevel::Good,
                    format!("✓ 浏览器确认执行![{}] alert 弹窗 · {kind} · {value}", point.label()),
                );
                push_finding(
                    &tx,
                    XssFinding {
                        point: point.label(),
                        confirmed: true,
                        context: "Live execution",
                        payload: Some(value),
                        kind: Some(kind),
                    },
                );
            }
            None => log_line(
                &tx,
                SqliLevel::Info,
                format!("[{}] 未触发执行(无弹窗)", point.label()),
            ),
        }
    }
    let _ = browser.quit().await;
    finish(&tx, format!("完成:浏览器确认 {confirmed} 处真实执行"));
}

// ───────────────────────── UI + 控制 ─────────────────────────

impl ScryApp {
    /// 从一条流带入 XSS 测试(代理右键「发送到 XSS」)。
    pub fn fill_xss_from_flow(&mut self, flow: &HttpFlow, cx: &mut Context<Self>) {
        let target = target_string(flow);
        let raw = render_raw_request(flow);
        self.xss_target.update(cx, |s, cx| s.set_text(target, cx));
        self.xss_req.update(cx, |s, cx| s.set_text(raw, cx));
        self.xss_point_sel = 0;
        self.xss_findings.clear();
        self.xss_sinks.clear();
        self.xss_log.clear();
        self.xss_progress = None;
    }

    /// 当前请求文本解析出的注入点(供下拉显示);解析失败返回空。
    pub(crate) fn xss_points(&self, cx: &Context<Self>) -> Vec<InjectionPoint> {
        let target = self.xss_target.read(cx).text().to_string();
        let raw = self.xss_req.read(cx).text().to_string();
        match parse_raw_request(&target, &raw) {
            Ok(r) => injection_points(&flow_from_req(&r)),
            Err(_) => Vec::new(),
        }
    }

    pub fn set_xss_point(&mut self, idx: usize, cx: &mut Context<Self>) {
        self.xss_point_sel = idx;
        self.xss_point_open = false;
        cx.notify();
    }

    pub fn stop_xss(&mut self, cx: &mut Context<Self>) {
        if let Some(c) = &self.xss_ctrl {
            c.store(true, Ordering::Relaxed);
        }
        self.xss_busy = false;
        self.xss_rx = None;
        self.xss_ctrl = None;
        self.kill_xss_browser();
        self.xss_progress = Some(self.lang.t("Stopped").to_string());
        self.push_log(LogLevel::Warning, "xss", "XSS 测试已停止");
        cx.notify();
    }

    /// 切换验证模式(0 = 静态反射检测;1 = 浏览器真执行确认)。
    pub fn set_xss_mode(&mut self, idx: usize, cx: &mut Context<Self>) {
        self.xss_dom = idx == 1;
        cx.notify();
    }

    /// 关闭浏览器验证用的无头 Chrome(杜绝孤儿进程)。
    pub fn kill_xss_browser(&mut self) {
        if let Some(mut child) = self.xss_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// 开始 XSS 测试:解析请求 → 取注入点 → 后台 runner 逐点检测 + 流式回填。
    pub fn start_xss(&mut self, cx: &mut Context<Self>) {
        if self.xss_busy {
            return;
        }
        if self.xss_dom {
            return self.start_xss_dom(cx);
        }
        let target = self.xss_target.read(cx).text().to_string();
        let raw = self.xss_req.read(cx).text().to_string();
        let base_req = match parse_raw_request(&target, &raw) {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("请求解析失败:{e}");
                self.xss_log = vec![SqliLine {
                    level: SqliLevel::Bad,
                    text: msg.clone(),
                }];
                self.xss_progress = Some(msg);
                cx.notify();
                return;
            }
        };
        let base_flow = flow_from_req(&base_req);
        let all_points = injection_points(&base_flow);
        if all_points.is_empty() {
            let msg = "无注入点(请求需带查询参数或表单字段)".to_string();
            self.xss_log = vec![SqliLine {
                level: SqliLevel::Warn,
                text: msg.clone(),
            }];
            self.xss_progress = Some(msg);
            cx.notify();
            return;
        }
        let points: Vec<InjectionPoint> = if self.xss_point_sel == 0 {
            all_points.into_iter().take(CANDIDATE_CAP).collect()
        } else {
            match all_points.get(self.xss_point_sel - 1) {
                Some(p) => vec![p.clone()],
                None => all_points.into_iter().take(CANDIDATE_CAP).collect(),
            }
        };
        let up = self.upstream_proxy(cx);

        self.xss_busy = true;
        self.xss_findings.clear();
        self.xss_sinks.clear();
        self.xss_log = vec![SqliLine {
            level: SqliLevel::Info,
            text: format!("开始 XSS 测试 · {} 个候选注入点", points.len()),
        }];
        self.xss_progress = Some("准备中…".to_string());
        let ctrl = Arc::new(AtomicBool::new(false));
        self.xss_ctrl = Some(ctrl.clone());
        let (tx, rx) = mpsc::channel::<XssMsg>();
        self.xss_rx = Some(rx);
        self.push_log(
            LogLevel::Info,
            "xss",
            format!("XSS 测试开始 · {} · {} 注入点", base_req.host, points.len()),
        );
        cx.notify();

        cx.background_executor()
            .spawn(async move {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => return,
                };
                rt.block_on(run_xss(base_req, points, up, ctrl, tx));
            })
            .detach();

        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(120))
                    .await;
                let keep = this.update(cx, |this, cx| {
                    this.drain_xss();
                    cx.notify();
                    this.xss_busy
                });
                match keep {
                    Ok(true) => continue,
                    _ => break,
                }
            }
        })
        .detach();
    }

    fn drain_xss(&mut self) {
        let Some(rx) = &self.xss_rx else {
            return;
        };
        let mut done = false;
        while let Ok(msg) = rx.try_recv() {
            if let Some(l) = msg.line {
                self.xss_log.push(l);
            }
            if let Some(f) = msg.finding {
                self.xss_findings.push(f);
            }
            if let Some(s) = msg.sinks {
                self.xss_sinks = s;
            }
            if let Some(p) = msg.progress {
                self.xss_progress = Some(p);
            }
            if msg.done {
                done = true;
            }
        }
        if self.xss_log.len() > XSS_LOG_CAP {
            let cut = self.xss_log.len() - XSS_LOG_CAP;
            self.xss_log.drain(0..cut);
        }
        if done {
            self.xss_busy = false;
            self.xss_rx = None;
            self.xss_ctrl = None;
            self.kill_xss_browser();
            let n = self.xss_findings.iter().filter(|f| f.confirmed).count();
            if n > 0 {
                self.push_log(LogLevel::Success, "xss", format!("XSS 确认 · {n} 处可利用"));
            } else {
                self.push_log(LogLevel::Info, "xss", "XSS 测试完成 · 未确认可利用点");
            }
        }
    }

    /// 浏览器真执行验证(对标 dalfox `--verify`):scry 自启无头 Chrome → drission 接管 → 对每个查询
    /// 注入点导航执行向量,**捕获到 `alert` 弹窗即确认真实执行**。仅支持查询参数注入点(GET 导航)。
    pub fn start_xss_dom(&mut self, cx: &mut Context<Self>) {
        let target = self.xss_target.read(cx).text().to_string();
        let raw = self.xss_req.read(cx).text().to_string();
        let base_req = match parse_raw_request(&target, &raw) {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("请求解析失败:{e}");
                self.xss_log = vec![SqliLine {
                    level: SqliLevel::Bad,
                    text: msg.clone(),
                }];
                self.xss_progress = Some(msg);
                cx.notify();
                return;
            }
        };
        let base_flow = flow_from_req(&base_req);
        let all_points = injection_points(&base_flow);
        let query_points: Vec<InjectionPoint> = all_points
            .iter()
            .filter(|p| p.location == Location::Query)
            .cloned()
            .collect();
        let points: Vec<InjectionPoint> = if self.xss_point_sel == 0 {
            query_points.into_iter().take(CANDIDATE_CAP).collect()
        } else {
            match all_points.get(self.xss_point_sel - 1) {
                Some(p) if p.location == Location::Query => vec![p.clone()],
                _ => query_points.into_iter().take(CANDIDATE_CAP).collect(),
            }
        };
        if points.is_empty() {
            let msg = "浏览器验证仅支持查询参数注入点(本请求无查询参数)".to_string();
            self.xss_log = vec![SqliLine {
                level: SqliLevel::Warn,
                text: msg.clone(),
            }];
            self.xss_progress = Some(msg);
            cx.notify();
            return;
        }
        // 需 MITM 内核在跑:无头 Chrome 经 8888 出网 + 解密(白名单 CA SPKI 过 pinning)。
        if !self.ensure_proxy_running(cx) {
            self.push_log(
                LogLevel::Warning,
                "xss",
                "浏览器验证需要 MITM 代理内核;请先停止被动嗅探再试",
            );
            return;
        }
        let spki =
            match scry_ca::Ca::load_or_create_default().and_then(|ca| ca.spki_sha256_base64()) {
                Ok(s) => s,
                Err(e) => {
                    let msg = format!("计算 CA 指纹失败:{e:#}");
                    self.push_log(LogLevel::Error, "xss", msg.clone());
                    self.xss_progress = Some(msg);
                    cx.notify();
                    return;
                }
            };
        let port = scry_proxy::ProxyConfig::default().addr.port();
        let debug_port = match crate::launcher::launch_headless_browser_debug(port, &spki) {
            Ok((child, dp)) => {
                self.xss_child = Some(child);
                dp
            }
            Err(e) => {
                let msg = format!("启动验证浏览器失败:{e:#}");
                self.push_log(LogLevel::Error, "xss", msg.clone());
                self.xss_progress = Some(msg);
                cx.notify();
                return;
            }
        };

        self.xss_busy = true;
        self.xss_findings.clear();
        self.xss_sinks.clear();
        self.xss_log = vec![SqliLine {
            level: SqliLevel::Info,
            text: format!("浏览器真执行验证开始 · {} 个查询注入点", points.len()),
        }];
        self.xss_progress = Some("启动浏览器…".to_string());
        let ctrl = Arc::new(AtomicBool::new(false));
        self.xss_ctrl = Some(ctrl.clone());
        let (tx, rx) = mpsc::channel::<XssMsg>();
        self.xss_rx = Some(rx);
        self.push_log(
            LogLevel::Info,
            "xss",
            format!("XSS 浏览器验证开始 · {} · {} 注入点", base_req.host, points.len()),
        );
        cx.notify();

        // 后台:独立 OS 线程 + 多线程 runtime 驱动 CDP(与爬虫同模型)。
        std::thread::Builder::new()
            .name("scry-xss-dom".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = tx.send(XssMsg {
                            line: Some(SqliLine {
                                level: SqliLevel::Bad,
                                text: format!("运行时创建失败:{e}"),
                            }),
                            finding: None,
                            sinks: None,
                            progress: Some("失败".into()),
                            done: true,
                        });
                        return;
                    }
                };
                rt.block_on(run_xss_dom(base_flow, points, debug_port, ctrl, tx));
            })
            .ok();

        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                let keep = this.update(cx, |this, cx| {
                    this.drain_xss();
                    cx.notify();
                    this.xss_busy
                });
                match keep {
                    Ok(true) => continue,
                    _ => break,
                }
            }
        })
        .detach();
    }

    /// XSS 页主体。
    pub fn xss_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let points = self.xss_points(cx);
        let mut point_opts: Vec<SharedString> = vec![self.lang.t("All parameters (auto)")];
        point_opts.extend(points.iter().map(|p| SharedString::from(p.label())));
        let point_idx = self.xss_point_sel.min(point_opts.len().saturating_sub(1));
        let view_p = cx.entity();
        let view_ps = cx.entity();
        let point_select = Select::new("xss-point", point_opts, point_idx)
            .width(px(260.0))
            .open(self.xss_point_open)
            .on_toggle(move |_e, _w, app| {
                view_p.update(app, |this, cx| {
                    this.xss_point_open = !this.xss_point_open;
                    cx.notify();
                });
            })
            .on_select(move |i, _e, _w, app| {
                view_ps.update(app, |this, cx| this.set_xss_point(i, cx));
            });

        // 验证模式:静态反射 / 浏览器真执行。
        let view_m = cx.entity();
        let mode_seg = Segmented::new("xss-mode")
            .items([self.lang.t("Static check"), self.lang.t("Live browser")])
            .selected(if self.xss_dom { 1 } else { 0 })
            .on_select(move |i, _e, _w, app| {
                view_m.update(app, |this, cx| this.set_xss_mode(i, cx));
            });

        let action = if self.xss_busy {
            Button::new("xss-stop", self.lang.t("Stop"))
                .variant(ButtonVariant::Danger)
                .size(ButtonSize::Sm)
                .icon(IconName::Box)
                .on_click(cx.listener(|this, _e, _w, cx| this.stop_xss(cx)))
        } else {
            Button::new("xss-start", self.lang.t("Start test"))
                .variant(ButtonVariant::Danger)
                .size(ButtonSize::Sm)
                .icon(IconName::Zap)
                .on_click(cx.listener(|this, _e, _w, cx| this.start_xss(cx)))
        };

        let mut toolbar = div()
            .flex()
            .items_center()
            .gap(t.space.md)
            .flex_shrink_0()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .flex_shrink_0()
                    .child(Icon::new(IconName::Tag).size(px(15.0)).color(c.text_subtle))
                    .child(
                        div()
                            .text_size(t.font_size.xs)
                            .text_color(c.text_subtle)
                            .child(self.lang.t("Injection point")),
                    )
                    .child(point_select),
            )
            .child(mode_seg)
            .child(action);
        if let Some(p) = &self.xss_progress {
            toolbar = toolbar.child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(if self.xss_busy { c.warning } else { c.text_muted })
                    .child(p.clone()),
            );
        }

        let hint = div()
            .flex_shrink_0()
            .text_size(t.font_size.xs)
            .text_color(c.text_subtle)
            .child(self.lang.t("Only test targets you are authorized to assess."));

        let left = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0))
            .child(section_label(self.lang.t("Target"), c, t))
            .child(self.xss_target.clone())
            .child(section_label(self.lang.t("Request"), c, t))
            .child(
                div()
                    .id("xss-req-scroll")
                    .flex_1()
                    .min_h(px(0.0))
                    .overflow_y_scroll()
                    .rounded(t.radius.lg)
                    .border_1()
                    .border_color(c.border)
                    .bg(c.surface)
                    .p(t.space.sm)
                    .child(self.xss_req.clone()),
            );

        let right = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0))
            .child(self.xss_findings_view(c, t))
            .children(self.xss_sinks_row(c, t))
            .child(self.xss_log_view(c, t));

        let body = div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .gap(t.space.md)
            .child(left)
            .child(right);

        div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .gap(t.space.md)
            .p(t.space.lg)
            .child(toolbar)
            .child(hint)
            .child(divider(c))
            .child(body)
    }

    /// 发现区:每个测过的注入点一张卡(可利用 / 反射但不可利用)。
    fn xss_findings_view(&self, c: ThemeColors, t: Tokens) -> AnyElement {
        if self.xss_log.is_empty() {
            return EmptyState::new(self.lang.t("Configure a request and start testing"))
                .icon(IconName::Tag)
                .into_any_element();
        }
        if self.xss_findings.is_empty() {
            return div()
                .flex_shrink_0()
                .p(t.space.md)
                .rounded(t.radius.lg)
                .bg(c.surface)
                .border_1()
                .border_color(c.border)
                .text_size(t.font_size.sm)
                .text_color(c.text_subtle)
                .child(if self.xss_busy {
                    self.lang.t("Testing…")
                } else {
                    self.lang.t("No reflection found")
                })
                .into_any_element();
        }
        let mut list = div()
            .id("xss-findings")
            .flex_1()
            .min_h(px(0.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(t.space.sm);
        for f in &self.xss_findings {
            list = list.child(self.xss_finding_card(f, c, t));
        }
        list.into_any_element()
    }

    fn xss_finding_card(&self, f: &XssFinding, c: ThemeColors, t: Tokens) -> impl IntoElement {
        let (badge_text, badge_color, border) = if f.confirmed {
            (self.lang.t("Exploitable"), c.danger, c.danger)
        } else {
            (self.lang.t("Reflected (not exploitable)"), c.warning, c.border)
        };
        // 上下文标签(可利用时附载荷类型,如 `HTML 文本 · html-tag`)。
        let ctx_label = match f.kind {
            Some(k) => format!("{} · {k}", self.lang.t(f.context)),
            None => self.lang.t(f.context).to_string(),
        };
        let mut card = div()
            .flex()
            .flex_col()
            .gap(px(4.0))
            .flex_shrink_0()
            .p(t.space.sm)
            .rounded(t.radius.lg)
            .bg(c.surface)
            .border_1()
            .border_color(border)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .child(Badge::new(badge_text, badge_color))
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .text_size(t.font_size.sm)
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(c.text)
                            .child(SharedString::from(f.point.clone())),
                    )
                    .child(
                        div()
                            .text_size(t.font_size.xs)
                            .text_color(c.text_subtle)
                            .child(SharedString::from(ctx_label)),
                    ),
            );
        if let Some(p) = &f.payload {
            card = card.child(
                div()
                    .font_family(crate::model::MONO)
                    .min_w(px(0.0))
                    .text_size(t.font_size.xs)
                    .text_color(if f.confirmed { c.accent } else { c.text_muted })
                    .child(SharedString::from(p.clone())),
            );
        }
        card
    }

    /// DOM sink 提示行(无则不渲染)。
    fn xss_sinks_row(&self, c: ThemeColors, t: Tokens) -> Option<AnyElement> {
        if self.xss_sinks.is_empty() {
            return None;
        }
        let mut row = div()
            .flex_shrink_0()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(4.0))
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("DOM sinks")),
            );
        for s in &self.xss_sinks {
            row = row.child(
                div()
                    .px(px(6.0))
                    .py(px(2.0))
                    .rounded(t.radius.md)
                    .bg(c.glass)
                    .border_1()
                    .border_color(c.glass_border)
                    .font_family(crate::model::MONO)
                    .text_size(t.font_size.xs)
                    .text_color(c.warning)
                    .child(SharedString::from(s.clone())),
            );
        }
        Some(row.into_any_element())
    }

    /// 测试日志(彩色,最近 300 行)。
    fn xss_log_view(&self, c: ThemeColors, t: Tokens) -> impl IntoElement {
        let mut list = div()
            .id("xss-log")
            .flex_1()
            .min_h(px(0.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(px(2.0))
            .p(t.space.sm)
            .rounded(t.radius.lg)
            .bg(c.surface)
            .border_1()
            .border_color(c.border)
            .font_family(crate::model::MONO);
        let start = self.xss_log.len().saturating_sub(300);
        for l in &self.xss_log[start..] {
            let col = match l.level {
                SqliLevel::Good => c.success,
                SqliLevel::Warn => c.warning,
                SqliLevel::Bad => c.danger,
                SqliLevel::Info => c.text_muted,
            };
            list = list.child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(col)
                    .child(l.text.clone()),
            );
        }
        list
    }
}

