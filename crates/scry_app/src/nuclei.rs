//! Nuclei 页:**nuclei 式 YAML 模板扫描**(对标 [`projectdiscovery/nuclei`](https://github.com/projectdiscovery/nuclei))。
//!
//! 加载 nuclei 格式模板(内置示例 + 可选的本地 `nuclei-templates` 目录),对一个目标
//! `scheme://host[:port]` 逐模板发请求,用 matchers(word/regex/status/size/binary/dsl)判命中、
//! 用 extractors(regex/kval/dsl)抽证据。引擎是纯函数 [`scry_nuclei`],发包复用
//! [`scry_proxy::replay`](与扫描器 / SQLi / XSS / 越权 同一条 async 路径:后台临时 current-thread
//! runtime 串行驱动 + mpsc 流式回填 + 前台 120ms 轮询)。
//!
//! 杠杆点:把本地 [`nuclei-templates`](https://github.com/projectdiscovery/nuclei-templates) 仓库
//! 目录填进来,即可白嫖社区几千个检测模板(CVE / 暴露 / 错误配置 …),无需逐个手写规则。
//!
//! ⚠️ 模板扫描会向目标真实发包,**只对你已获授权的目标使用**。

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::time::Duration;

use mage_ui::prelude::*;
use scry_core::HttpFlow;
use scry_nuclei::{build_block_requests, evaluate_request, RespData, Severity, Target};
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};
use scry_proxy::upstream::UpstreamProxy;

use crate::logger::LogLevel;
use crate::repeater::target_string;
use crate::scanner::severity_color;
use crate::state::{NucleiHit, NucleiMsg, ScryApp, SqliLevel, SqliLine};
use crate::widgets::{divider, section_label};

/// 测试日志最多保留行数。
const NUCLEI_LOG_CAP: usize = 500;
/// 目录最多扫描的 YAML 文件数(防超大目录卡死)。
const MAX_FILES: usize = 20_000;
/// 单个模板文件最大字节(nuclei 模板都很小;过大跳过)。
const MAX_FILE_BYTES: u64 = 512 * 1024;
/// 最多运行的模板数(过滤后封顶,防失控)。
const TEMPLATE_CAP: usize = 1500;
/// 总请求预算(每模板每 path 一请求;防对目标狂轰)。
const REQUEST_BUDGET: usize = 8000;

/// 严重度过滤下拉项:`(英文 key, 最小阈值)`(None = 全部)。
const SEV_OPTS: [(&str, Option<Severity>); 5] = [
    ("All severities", None),
    ("Low and above", Some(Severity::Low)),
    ("Medium and above", Some(Severity::Medium)),
    ("High and above", Some(Severity::High)),
    ("Critical only", Some(Severity::Critical)),
];

// ───────────────────────── 后台 runner ─────────────────────────

fn log_line(tx: &Sender<NucleiMsg>, level: SqliLevel, text: impl Into<String>) {
    let _ = tx.send(NucleiMsg {
        line: Some(SqliLine {
            level,
            text: text.into(),
        }),
        hit: None,
        loaded: None,
        progress: None,
        done: false,
    });
}

fn log_hit(tx: &Sender<NucleiMsg>, hit: NucleiHit) {
    let _ = tx.send(NucleiMsg {
        line: None,
        hit: Some(hit),
        loaded: None,
        progress: None,
        done: false,
    });
}

fn log_loaded(tx: &Sender<NucleiMsg>, loaded: usize, skipped: usize) {
    let _ = tx.send(NucleiMsg {
        line: None,
        hit: None,
        loaded: Some((loaded, skipped)),
        progress: None,
        done: false,
    });
}

fn log_prog(tx: &Sender<NucleiMsg>, p: impl Into<String>) {
    let _ = tx.send(NucleiMsg {
        line: None,
        hit: None,
        loaded: None,
        progress: Some(p.into()),
        done: false,
    });
}

fn finish(tx: &Sender<NucleiMsg>, p: impl Into<String>) {
    let _ = tx.send(NucleiMsg {
        line: None,
        hit: None,
        loaded: None,
        progress: Some(p.into()),
        done: true,
    });
}

/// 映射 nuclei 严重度 → `scry_scan::Severity`(复用扫描器的着色)。
fn map_sev(s: Severity) -> scry_scan::Severity {
    match s {
        Severity::Critical => scry_scan::Severity::Critical,
        Severity::High => scry_scan::Severity::High,
        Severity::Medium => scry_scan::Severity::Medium,
        Severity::Low => scry_scan::Severity::Low,
        Severity::Info | Severity::Unknown => scry_scan::Severity::Info,
    }
}

/// 由内置请求 + 当前会话构造重放请求(有会话则注入 Cookie/令牌 + `{{token}}` 替换)。
fn build_req(b: &scry_nuclei::BuiltRequest, sess: &Option<Sess>) -> ReplayRequest {
    let (headers, body) = match sess {
        Some((plan, st)) => crate::session::apply_session_to(&b.headers, &b.body, st, &plan.apply),
        None => (b.headers.clone(), b.body.clone()),
    };
    ReplayRequest {
        method: b.method.clone(),
        scheme: b.scheme.clone(),
        host: b.host.clone(),
        port: b.port,
        path: b.path.clone(),
        headers,
        body,
    }
}

/// 发一个内置请求;若启用会话且响应「掉登录」,重跑登录宏刷新会话后再发一次。
async fn send_built(
    b: &scry_nuclei::BuiltRequest,
    cfg: &ReplayConfig,
    sess: &mut Option<Sess>,
    tx: &Sender<NucleiMsg>,
) -> Option<HttpFlow> {
    let req = build_req(b, sess);
    let flow = replay::send(&req, cfg).await.ok()?;

    // 掉登录检测(不可变借用)。
    let need_relogin = match sess.as_ref() {
        Some((plan, _)) => {
            let resp = scry_session::Resp::new(flow.status, &flow.resp_headers, &flow.resp_body);
            scry_session::looks_logged_out(&resp, &plan.logout)
        }
        None => false,
    };
    if !need_relogin {
        return Some(flow);
    }

    // 重登:克隆计划(避免跨 await 持有 sess 借用)→ 跑宏 → 更新会话 → 重发一次。
    let plan = sess.as_ref().map(|(p, _)| p.clone())?;
    log_line(tx, SqliLevel::Warn, "检测到掉登录,重跑登录宏…");
    match crate::session::run_login_macro(&plan).await {
        Ok((s2, newst)) => {
            if let Some((_, st)) = sess.as_mut() {
                *st = newst;
            }
            log_line(tx, SqliLevel::Good, format!("会话已刷新(HTTP {s2}),重发请求"));
            let req2 = build_req(b, sess);
            replay::send(&req2, cfg).await.ok().or(Some(flow))
        }
        Err(e) => {
            log_line(tx, SqliLevel::Warn, format!("重登失败:{e}"));
            Some(flow)
        }
    }
}

/// 递归收集目录下的 `*.yaml` / `*.yml`(跳过隐藏目录;有文件数预算)。
fn collect_template_files(dir: &Path, out: &mut Vec<PathBuf>, budget: &mut usize) {
    if *budget == 0 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        if *budget == 0 {
            return;
        }
        let path = entry.path();
        if path.is_dir() {
            let hidden = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with('.'))
                .unwrap_or(false);
            if !hidden {
                collect_template_files(&path, out, budget);
            }
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
            .unwrap_or(false)
        {
            out.push(path);
            *budget -= 1;
        }
    }
}

/// 整条模板扫描流程(加载模板 → 过滤 → 逐模板对目标发请求 → matcher/extractor 判命中);
/// 全程经 `tx` 流式回传日志 / 命中 / 进度。
type Sess = (crate::session::SessionPlan, scry_session::SessionState);

async fn run_nuclei(
    target_url: String,
    dir: String,
    min_sev: Option<Severity>,
    session: Option<crate::session::SessionPlan>,
    upstream: Option<UpstreamProxy>,
    ctrl: Arc<AtomicBool>,
    tx: Sender<NucleiMsg>,
) {
    let cfg = ReplayConfig {
        upstream,
        ..Default::default()
    };
    let Some(target) = Target::parse(&target_url) else {
        finish(&tx, "目标无效(形如 https://host[:port])");
        return;
    };
    log_line(&tx, SqliLevel::Info, format!("目标:{}", target.root_url()));

    // 会话处理:开扫前跑登录宏建立会话(自动重登),后续每请求注入 + 中途掉登录再重登。
    let mut sess: Option<Sess> = None;
    if let Some(plan) = session {
        log_line(&tx, SqliLevel::Info, "运行登录宏建立会话…");
        match crate::session::run_login_macro(&plan).await {
            Ok((status, st)) => {
                log_line(
                    &tx,
                    if st.is_empty() {
                        SqliLevel::Warn
                    } else {
                        SqliLevel::Good
                    },
                    format!("会话已建立(HTTP {status}):{}", st.summary()),
                );
                sess = Some((plan, st));
            }
            Err(e) => log_line(
                &tx,
                SqliLevel::Warn,
                format!("登录宏失败:{e}(继续无会话扫描)"),
            ),
        }
    }

    // ── 1) 收集模板:内置 + 可选目录 ──
    let mut templates = scry_nuclei::load_builtins();
    let builtin_n = templates.len();
    let mut skipped = 0usize;
    let dir = dir.trim().to_string();
    if !dir.is_empty() {
        let p = Path::new(&dir);
        if p.is_dir() {
            log_line(&tx, SqliLevel::Info, format!("加载模板目录:{dir}"));
            let mut files = Vec::new();
            let mut budget = MAX_FILES;
            collect_template_files(p, &mut files, &mut budget);
            log_line(
                &tx,
                SqliLevel::Info,
                format!("发现 {} 个 YAML 文件,解析中…", files.len()),
            );
            for f in files {
                if ctrl.load(Ordering::Relaxed) {
                    break;
                }
                let too_big = std::fs::metadata(&f)
                    .map(|m| m.len() > MAX_FILE_BYTES)
                    .unwrap_or(true);
                if too_big {
                    skipped += 1;
                    continue;
                }
                match std::fs::read_to_string(&f) {
                    Ok(text) => match scry_nuclei::parse_template(&text) {
                        Ok(t) => templates.push(t),
                        Err(_) => skipped += 1,
                    },
                    Err(_) => skipped += 1,
                }
            }
        } else {
            log_line(
                &tx,
                SqliLevel::Warn,
                format!("模板目录不存在:{dir}(仅用内置模板)"),
            );
        }
    }
    log_loaded(&tx, templates.len(), skipped);
    log_line(
        &tx,
        SqliLevel::Info,
        format!(
            "已加载 {} 个模板(内置 {builtin_n})· 跳过 {skipped}",
            templates.len()
        ),
    );

    // ── 2) 过滤严重度 + 封顶 ──
    if let Some(min) = min_sev {
        templates.retain(|t| t.severity() >= min);
    }
    if templates.len() > TEMPLATE_CAP {
        log_line(
            &tx,
            SqliLevel::Warn,
            format!("模板数超过上限,仅运行前 {TEMPLATE_CAP} 个"),
        );
        templates.truncate(TEMPLATE_CAP);
    }
    if templates.is_empty() {
        finish(&tx, "无可运行模板(检查目录 / 严重度过滤)");
        return;
    }

    // ── 3) 逐模板对目标发请求 + 判命中 ──
    let total = templates.len();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut budget = REQUEST_BUDGET;
    let mut hits = 0usize;
    log_line(&tx, SqliLevel::Info, format!("开始运行 {total} 个模板…"));

    for (ti, t) in templates.iter().enumerate() {
        if ctrl.load(Ordering::Relaxed) {
            finish(&tx, format!("已停止 · {hits} 条命中"));
            return;
        }
        if budget == 0 {
            log_line(&tx, SqliLevel::Warn, "请求预算用尽,停止");
            break;
        }
        if ti.is_multiple_of(10) || total < 60 {
            log_prog(&tx, format!("模板 {}/{total} · 命中 {hits}", ti + 1));
        }

        for block in &t.requests {
            for b in build_block_requests(block, &target) {
                if ctrl.load(Ordering::Relaxed) {
                    finish(&tx, format!("已停止 · {hits} 条命中"));
                    return;
                }
                if budget == 0 {
                    break;
                }
                budget -= 1;
                let url = b.url();
                let Some(flow) = send_built(&b, &cfg, &mut sess, &tx).await else {
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
                    if seen.insert((t.id.clone(), url.clone())) {
                        hits += 1;
                        let extracted = res
                            .extracted
                            .iter()
                            .map(|(k, v)| format!("{k}: {v}"))
                            .collect::<Vec<_>>()
                            .join(" · ");
                        log_line(
                            &tx,
                            SqliLevel::Good,
                            format!("✓ [{}] {} → {url}", t.severity().label(), t.info.name),
                        );
                        log_hit(
                            &tx,
                            NucleiHit {
                                template_id: t.id.clone(),
                                name: t.info.name.clone(),
                                severity: map_sev(t.severity()),
                                url,
                                matchers: res.matched_names.join(", "),
                                extracted,
                            },
                        );
                    }
                    if block.stop_at_first_match {
                        break;
                    }
                }
            }
        }
    }

    finish(&tx, format!("完成 · {hits} 条命中"));
}

// ───────────────────────── UI + 控制 ─────────────────────────

impl ScryApp {
    /// 从一条流带入模板扫描(代理右键「发送到 Nuclei」):用其根 URL 预填目标。
    pub fn fill_nuclei_from_flow(&mut self, flow: &HttpFlow, cx: &mut Context<Self>) {
        let target = target_string(flow);
        self.nuclei_target.update(cx, |s, cx| s.set_text(target, cx));
        self.nuclei_hits.clear();
        self.nuclei_log.clear();
        self.nuclei_ran = false;
        self.nuclei_progress = None;
    }

    pub fn set_nuclei_sev(&mut self, idx: usize, cx: &mut Context<Self>) {
        self.nuclei_sev = idx.min(SEV_OPTS.len() - 1);
        self.nuclei_sev_open = false;
        cx.notify();
    }

    /// 停止扫描(置停止位 + 丢弃接收端)。
    pub fn stop_nuclei(&mut self, cx: &mut Context<Self>) {
        if let Some(c) = &self.nuclei_ctrl {
            c.store(true, Ordering::Relaxed);
        }
        self.nuclei_busy = false;
        self.nuclei_rx = None;
        self.nuclei_ctrl = None;
        self.nuclei_progress = Some(self.lang.t("Stopped").to_string());
        self.push_log(LogLevel::Warning, "nuclei", "模板扫描已停止");
        cx.notify();
    }

    /// 开始模板扫描:解析目标 + 模板目录 → 后台 runner 加载模板 + 逐个发请求 + 流式回填。
    pub fn start_nuclei(&mut self, cx: &mut Context<Self>) {
        if self.nuclei_busy {
            return;
        }
        let target_url = self.nuclei_target.read(cx).text().trim().to_string();
        if target_url.is_empty() {
            let msg = "请填写目标(形如 https://host[:port])".to_string();
            self.nuclei_log = vec![SqliLine {
                level: SqliLevel::Bad,
                text: msg.clone(),
            }];
            self.nuclei_progress = Some(msg);
            self.nuclei_ran = true;
            cx.notify();
            return;
        }
        let dir = self.nuclei_dir.read(cx).text().trim().to_string();
        let min_sev = SEV_OPTS.get(self.nuclei_sev).and_then(|(_, s)| *s);
        let session = self.session_plan(cx);
        let up = self.upstream_proxy(cx);

        self.nuclei_busy = true;
        self.nuclei_ran = true;
        self.nuclei_hits = Vec::new();
        self.nuclei_loaded = 0;
        self.nuclei_skipped = 0;
        self.nuclei_log = vec![SqliLine {
            level: SqliLevel::Info,
            text: format!("开始模板扫描 · {target_url}"),
        }];
        self.nuclei_progress = Some("准备中…".to_string());
        let ctrl = Arc::new(AtomicBool::new(false));
        self.nuclei_ctrl = Some(ctrl.clone());
        let (tx, rx) = mpsc::channel::<NucleiMsg>();
        self.nuclei_rx = Some(rx);
        self.push_log(
            LogLevel::Info,
            "nuclei",
            format!("模板扫描开始 · {target_url}"),
        );
        cx.notify();

        // 后台:临时 current-thread runtime 串行驱动整条扫描流程。
        cx.background_executor()
            .spawn(async move {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => return,
                };
                rt.block_on(run_nuclei(target_url, dir, min_sev, session, up, ctrl, tx));
            })
            .detach();

        // 前台轮询:把日志 / 命中 / 进度并入状态,结束即收尾。
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(120))
                    .await;
                let keep = this.update(cx, |this, cx| {
                    this.drain_nuclei();
                    cx.notify();
                    this.nuclei_busy
                });
                match keep {
                    Ok(true) => continue,
                    _ => break,
                }
            }
        })
        .detach();
    }

    /// 排空通道:并入日志 / 命中 / 统计 / 进度;结束则收尾。
    fn drain_nuclei(&mut self) {
        let Some(rx) = &self.nuclei_rx else {
            return;
        };
        let mut done = false;
        while let Ok(msg) = rx.try_recv() {
            if let Some(l) = msg.line {
                self.nuclei_log.push(l);
            }
            if let Some(h) = msg.hit {
                self.nuclei_hits.push(h);
            }
            if let Some((loaded, skipped)) = msg.loaded {
                self.nuclei_loaded = loaded;
                self.nuclei_skipped = skipped;
            }
            if let Some(p) = msg.progress {
                self.nuclei_progress = Some(p);
            }
            if msg.done {
                done = true;
            }
        }
        if self.nuclei_log.len() > NUCLEI_LOG_CAP {
            let cut = self.nuclei_log.len() - NUCLEI_LOG_CAP;
            self.nuclei_log.drain(0..cut);
        }
        if done {
            self.nuclei_busy = false;
            self.nuclei_rx = None;
            self.nuclei_ctrl = None;
            if self.nuclei_hits.is_empty() {
                self.push_log(LogLevel::Info, "nuclei", "模板扫描完成 · 无命中");
            } else {
                self.push_log(
                    LogLevel::Success,
                    "nuclei",
                    format!("模板扫描完成 · {} 条命中", self.nuclei_hits.len()),
                );
            }
        }
    }

    /// Nuclei 页主体。
    pub fn nuclei_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        // 严重度过滤下拉。
        let sev_opts: Vec<SharedString> =
            SEV_OPTS.iter().map(|(l, _)| self.lang.t(l)).collect();
        let sev_idx = self.nuclei_sev.min(SEV_OPTS.len() - 1);
        let view_s = cx.entity();
        let view_ss = cx.entity();
        let sev_select = Select::new("nuclei-sev", sev_opts, sev_idx)
            .width(px(170.0))
            .open(self.nuclei_sev_open)
            .on_toggle(move |_e, _w, app| {
                view_s.update(app, |this, cx| {
                    this.nuclei_sev_open = !this.nuclei_sev_open;
                    cx.notify();
                });
            })
            .on_select(move |i, _e, _w, app| {
                view_ss.update(app, |this, cx| this.set_nuclei_sev(i, cx));
            });

        let action = if self.nuclei_busy {
            Button::new("nuclei-stop", self.lang.t("Stop"))
                .variant(ButtonVariant::Danger)
                .size(ButtonSize::Sm)
                .icon(IconName::Box)
                .on_click(cx.listener(|this, _e, _w, cx| this.stop_nuclei(cx)))
        } else {
            Button::new("nuclei-start", self.lang.t("Start scan"))
                .variant(ButtonVariant::Danger)
                .size(ButtonSize::Sm)
                .icon(IconName::Zap)
                .on_click(cx.listener(|this, _e, _w, cx| this.start_nuclei(cx)))
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
                    .child(Icon::new(IconName::Folder).size(px(15.0)).color(c.text_subtle))
                    .child(
                        div()
                            .text_size(t.font_size.sm)
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(c.text)
                            .child(self.lang.t("Template scan")),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .flex_shrink_0()
                    .child(
                        div()
                            .text_size(t.font_size.xs)
                            .text_color(c.text_subtle)
                            .child(self.lang.t("Severity")),
                    )
                    .child(sev_select),
            )
            .child(action);
        if let Some(p) = &self.nuclei_progress {
            toolbar = toolbar.child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(if self.nuclei_busy { c.warning } else { c.text_muted })
                    .child(p.clone()),
            );
        }

        let hint = div()
            .flex_shrink_0()
            .text_size(t.font_size.xs)
            .text_color(c.text_subtle)
            .child(self.lang.t("Only test targets you are authorized to assess."));

        // 左:目标 + 模板目录 + 说明。
        let left = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0))
            .child(section_label(self.lang.t("Target"), c, t))
            .child(self.nuclei_target.clone())
            .child(section_label(self.lang.t("Templates directory"), c, t))
            .child(self.nuclei_dir.clone())
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t(
                        "Built-in templates always run; point the directory at the nuclei-templates repo for thousands more.",
                    )),
            )
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(
                        self.lang
                            .t("Loads nuclei-format YAML templates and runs them against the target."),
                    ),
            );

        // 右:统计卡 + 命中列表 + 日志。
        let mut right = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0));
        if self.nuclei_busy || self.nuclei_ran {
            right = right.child(self.nuclei_report_card(c, t));
        }
        right = right.child(self.nuclei_hits_view(c, t));
        if !self.nuclei_log.is_empty() {
            right = right.child(self.nuclei_log_view(c, t));
        }

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

    /// 统计 / 结论卡:总体徽标 + 加载统计。
    fn nuclei_report_card(&self, c: ThemeColors, t: Tokens) -> AnyElement {
        let (badge_text, badge_color) = if !self.nuclei_hits.is_empty() {
            (self.lang.t("Template matches"), c.danger)
        } else if self.nuclei_busy {
            (self.lang.t("Scanning…"), c.warning)
        } else if self.nuclei_ran {
            (self.lang.t("No issues found"), c.success)
        } else {
            (self.lang.t("Idle"), c.text_subtle)
        };

        let stat = if self.lang.is_zh() {
            format!(
                "已加载 {} 个模板 · 跳过 {} · 命中 {}",
                self.nuclei_loaded,
                self.nuclei_skipped,
                self.nuclei_hits.len()
            )
        } else {
            format!(
                "{} templates loaded · {} skipped · {} matches",
                self.nuclei_loaded,
                self.nuclei_skipped,
                self.nuclei_hits.len()
            )
        };

        div()
            .flex()
            .flex_col()
            .gap(px(6.0))
            .flex_shrink_0()
            .p(t.space.md)
            .rounded(t.radius.lg)
            .bg(c.surface)
            .border_1()
            .border_color(if self.nuclei_hits.is_empty() {
                c.border
            } else {
                c.danger
            })
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .child(Badge::new(badge_text, badge_color))
                    .child(
                        div()
                            .text_size(t.font_size.sm)
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(c.text)
                            .child(self.lang.t("Template scan")),
                    ),
            )
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_muted)
                    .child(stat),
            )
            .into_any_element()
    }

    /// 命中列表(空态按是否已扫描给不同提示)。
    fn nuclei_hits_view(&self, c: ThemeColors, t: Tokens) -> AnyElement {
        if self.nuclei_hits.is_empty() {
            let (text, icon) = if self.nuclei_ran && !self.nuclei_busy {
                (self.lang.t("No template matched"), IconName::Check)
            } else {
                (
                    self.lang.t("Configure a target and start scanning"),
                    IconName::Folder,
                )
            };
            return EmptyState::new(text).icon(icon).into_any_element();
        }
        let mut list = div()
            .id("nuclei-hits")
            .flex_1()
            .min_h(px(0.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(t.space.sm);
        for h in &self.nuclei_hits {
            list = list.child(self.nuclei_hit_card(h, c, t));
        }
        list.into_any_element()
    }

    /// 单条命中卡:严重度徽标 + 模板名 + (模板 id · matcher · 提取值)+ URL。
    fn nuclei_hit_card(&self, h: &NucleiHit, c: ThemeColors, t: Tokens) -> impl IntoElement {
        let sev_color = severity_color(h.severity, c);
        let mut detail = h.template_id.clone();
        if !h.matchers.is_empty() {
            detail.push_str(" · ");
            detail.push_str(&h.matchers);
        }
        if !h.extracted.is_empty() {
            detail.push_str(" · ");
            detail.push_str(&h.extracted);
        }
        div()
            .flex()
            .flex_col()
            .gap(px(4.0))
            .flex_shrink_0()
            .p(t.space.sm)
            .rounded(t.radius.lg)
            .bg(c.surface)
            .border_1()
            .border_color(c.border)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .child(Badge::new(self.lang.t(h.severity.label()), sev_color))
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .text_size(t.font_size.sm)
                            .text_color(c.text)
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(h.name.clone()),
                    ),
            )
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_muted)
                    .child(detail),
            )
            .child(
                div()
                    .font_family(crate::model::MONO)
                    .min_w(px(0.0))
                    .truncate()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(h.url.clone()),
            )
    }

    /// 测试日志列表(彩色,最近 300 行)。
    fn nuclei_log_view(&self, c: ThemeColors, t: Tokens) -> impl IntoElement {
        let mut list = div()
            .id("nuclei-log")
            .flex_shrink_0()
            .h(px(168.0))
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
        let start = self.nuclei_log.len().saturating_sub(300);
        for l in &self.nuclei_log[start..] {
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
