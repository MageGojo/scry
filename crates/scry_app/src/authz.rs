//! Authz 页:**越权 / 访问控制测试**(对标 Burp **Autorize / AuthMatrix**)。
//!
//! 把一条「高权限」请求(通常从代理右键「发送到越权」带入,本身就带管理员会话)当**基准**,
//! 再用**低权限身份**与**匿名身份**重放同一请求,比对响应:谁不该拿到却拿到了 = **Broken
//! Access Control**(匿名命中 = 未授权访问 Critical;低权命中 = 越权/提权 High)。
//!
//! 引擎是纯函数 [`scry_scan::authz`](身份套用 + 判定),发包复用 [`scry_proxy::replay`]
//! (与扫描器 / SQLi / XSS 同一条 async 路径:后台临时 current-thread runtime 串行驱动 +
//! mpsc 流式回填 + 前台 120ms 轮询)。
//!
//! ⚠️ 多身份重放会向目标真实发包,**只对你已获授权的目标使用**。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::time::Duration;

use mage_ui::prelude::*;
use scry_core::HttpFlow;
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};
use scry_proxy::upstream::UpstreamProxy;
use scry_scan::authz::{self, AuthVerdict, Identity};

use crate::logger::LogLevel;
use crate::repeater::{parse_raw_request, render_raw_request, target_string};
use crate::scanner::finding_card;
use crate::state::{AuthzMsg, AuthzRow, ScryApp, SqliLevel, SqliLine};
use crate::widgets::{divider, section_label};

/// 测试身份重放之间的小间隔(避免对目标突发并发)。
const PACE_MS: u64 = 100;
/// 测试日志最多保留行数。
const AUTHZ_LOG_CAP: usize = 400;

// 判定码(与 `AuthzRow::verdict` 对齐):0 拦截到位 · 1 疑似越权 · 2 无法判定 · 3 高权限基准。
const V_ENFORCED: u8 = 0;
const V_BYPASS: u8 = 1;
const V_INCONCLUSIVE: u8 = 2;
const V_BASELINE: u8 = 3;

// ───────────────────────── 后台 runner ─────────────────────────

fn log_line(tx: &Sender<AuthzMsg>, level: SqliLevel, text: impl Into<String>) {
    let _ = tx.send(AuthzMsg {
        line: Some(SqliLine {
            level,
            text: text.into(),
        }),
        row: None,
        finding: None,
        progress: None,
        done: false,
    });
}

fn log_row(tx: &Sender<AuthzMsg>, row: AuthzRow) {
    let _ = tx.send(AuthzMsg {
        line: None,
        row: Some(row),
        finding: None,
        progress: None,
        done: false,
    });
}

fn log_finding(tx: &Sender<AuthzMsg>, f: scry_scan::Finding) {
    let _ = tx.send(AuthzMsg {
        line: None,
        row: None,
        finding: Some(f),
        progress: None,
        done: false,
    });
}

fn log_prog(tx: &Sender<AuthzMsg>, p: impl Into<String>) {
    let _ = tx.send(AuthzMsg {
        line: None,
        row: None,
        finding: None,
        progress: Some(p.into()),
        done: false,
    });
}

fn finish(tx: &Sender<AuthzMsg>, p: impl Into<String>) {
    let _ = tx.send(AuthzMsg {
        line: None,
        row: None,
        finding: None,
        progress: Some(p.into()),
        done: true,
    });
}

/// 由重放请求拼一条「仅请求」的流(供身份套用)。
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

fn verdict_code(v: AuthVerdict) -> u8 {
    match v {
        AuthVerdict::Enforced => V_ENFORCED,
        AuthVerdict::Bypass => V_BYPASS,
        AuthVerdict::Inconclusive => V_INCONCLUSIVE,
    }
}

/// 整条越权测试流程(高权限基准 → 低权限 / 匿名重放比对);全程经 `tx` 流式回传。
async fn run_authz(
    base_req: ReplayRequest,
    high: Option<Identity>,
    low: Option<Identity>,
    upstream: Option<UpstreamProxy>,
    ctrl: Arc<AtomicBool>,
    tx: Sender<AuthzMsg>,
) {
    let cfg = ReplayConfig {
        upstream,
        ..Default::default()
    };
    let base_flow = flow_from_req(&base_req);
    let url = base_flow.url();

    // ── 1) 高权限基准:套用高权限身份(留空则直接用请求本身)并发送 ──
    log_line(&tx, SqliLevel::Info, "建立高权限基准:发送特权请求…");
    let priv_req = match &high {
        Some(h) => ReplayRequest::from_flow(&authz::apply_identity(&base_flow, h)),
        None => base_req.clone(),
    };
    let privileged = match replay::send(&priv_req, &cfg).await {
        Ok(f) => f,
        Err(e) => {
            finish(&tx, format!("基准请求失败:{e:#}"));
            return;
        }
    };
    log_row(
        &tx,
        AuthzRow {
            identity: "high".to_string(),
            verdict: V_BASELINE,
            status: privileged.status,
            len: privileged.resp_body.len(),
        },
    );
    log_line(
        &tx,
        SqliLevel::Info,
        format!(
            "高权限基准:HTTP {} · {} 字节",
            privileged.status,
            privileged.resp_body.len()
        ),
    );
    if !(200..300).contains(&privileged.status) {
        finish(
            &tx,
            "基准非 2xx,无法比对越权(请用一个能成功取到数据的高权限请求)",
        );
        return;
    }

    // ── 2) 测试身份:低权限(可选)+ 匿名(总测)──
    let mut tests: Vec<Identity> = Vec::new();
    if let Some(l) = low {
        tests.push(l);
    }
    tests.push(Identity::anonymous());

    let total = tests.len();
    for (i, id) in tests.iter().enumerate() {
        if ctrl.load(Ordering::Relaxed) {
            finish(&tx, "已停止");
            return;
        }
        log_prog(&tx, format!("测试身份 {}/{}", i + 1, total));
        tokio::time::sleep(Duration::from_millis(PACE_MS)).await;

        let req = ReplayRequest::from_flow(&authz::apply_identity(&base_flow, id));
        let resp = match replay::send(&req, &cfg).await {
            Ok(r) => r,
            Err(e) => {
                log_line(&tx, SqliLevel::Bad, format!("身份「{}」重放失败:{e:#}", id.name));
                continue;
            }
        };
        let verdict = authz::compare(&privileged, &resp);
        log_row(
            &tx,
            AuthzRow {
                identity: id.name.clone(),
                verdict: verdict_code(verdict),
                status: resp.status,
                len: resp.resp_body.len(),
            },
        );
        let (lvl, tip) = match verdict {
            AuthVerdict::Bypass => (SqliLevel::Bad, "疑似越权:该身份拿到了与高权限相同的成功响应"),
            AuthVerdict::Enforced => (SqliLevel::Good, "拦截到位:该身份被正确拒绝 / 跳登录"),
            AuthVerdict::Inconclusive => (SqliLevel::Warn, "无法判定:响应不同但非明确拒绝"),
        };
        log_line(
            &tx,
            lvl,
            format!(
                "身份「{}」→ HTTP {} · {} 字节 · {tip}",
                id.name,
                resp.status,
                resp.resp_body.len()
            ),
        );
        if let Some(f) = authz::evaluate(&url, id, &privileged, &resp) {
            log_line(&tx, SqliLevel::Bad, format!("✗ 命中:{}", f.detail));
            log_finding(&tx, f);
        }
    }

    finish(&tx, "完成");
}

// ───────────────────────── UI + 控制 ─────────────────────────

impl ScryApp {
    /// 从一条流带入越权测试(代理右键「发送到越权」);其鉴权头即作为高权限基准。
    pub fn fill_authz_from_flow(&mut self, flow: &HttpFlow, cx: &mut Context<Self>) {
        let target = target_string(flow);
        let raw = render_raw_request(flow);
        self.authz_target.update(cx, |s, cx| s.set_text(target, cx));
        self.authz_req.update(cx, |s, cx| s.set_text(raw, cx));
        self.authz_rows.clear();
        self.authz_findings.clear();
        self.authz_log.clear();
        self.authz_ran = false;
        self.authz_progress = None;
    }

    /// 停止测试(置停止位 + 丢弃接收端)。
    pub fn stop_authz(&mut self, cx: &mut Context<Self>) {
        if let Some(c) = &self.authz_ctrl {
            c.store(true, Ordering::Relaxed);
        }
        self.authz_busy = false;
        self.authz_rx = None;
        self.authz_ctrl = None;
        self.authz_progress = Some(self.lang.t("Stopped").to_string());
        self.push_log(LogLevel::Warning, "authz", "越权测试已停止");
        cx.notify();
    }

    /// 开始越权测试:解析请求 + 身份 → 后台 runner 多身份重放 + 流式回填。
    pub fn start_authz(&mut self, cx: &mut Context<Self>) {
        if self.authz_busy {
            return;
        }
        let target = self.authz_target.read(cx).text().to_string();
        let raw = self.authz_req.read(cx).text().to_string();
        let base_req = match parse_raw_request(&target, &raw) {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("请求解析失败:{e}");
                self.authz_log = vec![SqliLine {
                    level: SqliLevel::Bad,
                    text: msg.clone(),
                }];
                self.authz_progress = Some(msg);
                self.authz_ran = true;
                cx.notify();
                return;
            }
        };
        let high_text = self.authz_high.read(cx).text().trim().to_string();
        let low_text = self.authz_low.read(cx).text().trim().to_string();
        let high = (!high_text.is_empty()).then(|| Identity::parse("high", &high_text));
        let low = (!low_text.is_empty()).then(|| Identity::parse("low", &low_text));
        let up = self.upstream_proxy(cx);

        let test_count = 1 + usize::from(low.is_some()); // 低权限(可选)+ 匿名
        self.authz_busy = true;
        self.authz_ran = true;
        self.authz_rows = Vec::new();
        self.authz_findings = Vec::new();
        self.authz_log = vec![SqliLine {
            level: SqliLevel::Info,
            text: format!(
                "开始越权测试 · {} · 高权限基准 + {test_count} 个测试身份(含匿名)",
                base_req.host
            ),
        }];
        self.authz_progress = Some("准备中…".to_string());
        let ctrl = Arc::new(AtomicBool::new(false));
        self.authz_ctrl = Some(ctrl.clone());
        let (tx, rx) = mpsc::channel::<AuthzMsg>();
        self.authz_rx = Some(rx);
        self.push_log(
            LogLevel::Info,
            "authz",
            format!("越权测试开始 · {} · {test_count} 个测试身份", base_req.host),
        );
        cx.notify();

        // 后台:临时 current-thread runtime 串行驱动整条越权流程。
        cx.background_executor()
            .spawn(async move {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => return,
                };
                rt.block_on(run_authz(base_req, high, low, up, ctrl, tx));
            })
            .detach();

        // 前台轮询:把日志 / 结果 / 进度并入状态,结束即收尾。
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(120))
                    .await;
                let keep = this.update(cx, |this, cx| {
                    this.drain_authz();
                    cx.notify();
                    this.authz_busy
                });
                match keep {
                    Ok(true) => continue,
                    _ => break,
                }
            }
        })
        .detach();
    }

    /// 排空通道:并入日志 / 结果行 / 发现 / 进度;结束则收尾。
    fn drain_authz(&mut self) {
        let Some(rx) = &self.authz_rx else {
            return;
        };
        let mut done = false;
        while let Ok(msg) = rx.try_recv() {
            if let Some(l) = msg.line {
                self.authz_log.push(l);
            }
            if let Some(r) = msg.row {
                self.authz_rows.push(r);
            }
            if let Some(f) = msg.finding {
                self.authz_findings.push(f);
            }
            if let Some(p) = msg.progress {
                self.authz_progress = Some(p);
            }
            if msg.done {
                done = true;
            }
        }
        if self.authz_log.len() > AUTHZ_LOG_CAP {
            let cut = self.authz_log.len() - AUTHZ_LOG_CAP;
            self.authz_log.drain(0..cut);
        }
        if done {
            self.authz_busy = false;
            self.authz_rx = None;
            self.authz_ctrl = None;
            if self.authz_findings.is_empty() {
                self.push_log(LogLevel::Info, "authz", "越权测试完成 · 未发现越权");
            } else {
                self.push_log(
                    LogLevel::Success,
                    "authz",
                    format!("越权测试完成 · {} 条发现", self.authz_findings.len()),
                );
            }
        }
    }

    /// 越权页主体。
    pub fn authz_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let action = if self.authz_busy {
            Button::new("authz-stop", self.lang.t("Stop"))
                .variant(ButtonVariant::Danger)
                .size(ButtonSize::Sm)
                .icon(IconName::Box)
                .on_click(cx.listener(|this, _e, _w, cx| this.stop_authz(cx)))
        } else {
            Button::new("authz-start", self.lang.t("Start test"))
                .variant(ButtonVariant::Danger)
                .size(ButtonSize::Sm)
                .icon(IconName::Shield)
                .on_click(cx.listener(|this, _e, _w, cx| this.start_authz(cx)))
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
                    .child(Icon::new(IconName::Shield).size(px(15.0)).color(c.text_subtle))
                    .child(
                        div()
                            .text_size(t.font_size.sm)
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(c.text)
                            .child(self.lang.t("Access control test")),
                    ),
            )
            .child(action);
        if let Some(p) = &self.authz_progress {
            toolbar = toolbar.child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(if self.authz_busy { c.warning } else { c.text_muted })
                    .child(p.clone()),
            );
        }

        let hint = div()
            .flex_shrink_0()
            .text_size(t.font_size.xs)
            .text_color(c.text_subtle)
            .child(self.lang.t(
                "Replays the request as low-privilege & anonymous; the request itself is the privileged baseline.",
            ));

        // 左:目标 + 可编辑请求 + 身份配置。
        let identities = div()
            .flex_shrink_0()
            .flex()
            .flex_col()
            .gap(px(4.0))
            .child(section_label(self.lang.t("Test identities"), c, t))
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("High-privilege identity (baseline)")),
            )
            .child(self.authz_high.clone())
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("Low-privilege identity")),
            )
            .child(self.authz_low.clone());

        let left = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0))
            .child(section_label(self.lang.t("Target"), c, t))
            .child(self.authz_target.clone())
            .child(section_label(self.lang.t("Request"), c, t))
            .child(
                div()
                    .id("authz-req-scroll")
                    .flex_1()
                    .min_h(px(0.0))
                    .overflow_y_scroll()
                    .rounded(t.radius.lg)
                    .border_1()
                    .border_color(c.border)
                    .bg(c.surface)
                    .p(t.space.sm)
                    .child(self.authz_req.clone()),
            )
            .child(identities);

        // 右:结论卡(基准 + 各身份判定)+ 发现列表 + 日志。
        let mut right = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0));
        if self.authz_busy || self.authz_ran || !self.authz_rows.is_empty() {
            right = right.child(self.authz_report_card(c, t));
        }
        right = right.child(self.authz_findings_view(c, t));
        if !self.authz_log.is_empty() {
            right = right.child(self.authz_log_view(c, t));
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

    /// 结论卡:总体徽标 + 各身份重放结果(基准 + 判定)。
    fn authz_report_card(&self, c: ThemeColors, t: Tokens) -> AnyElement {
        let (badge_text, badge_color) = if !self.authz_findings.is_empty() {
            (self.lang.t("Broken access control"), c.danger)
        } else if self.authz_busy {
            (self.lang.t("Testing…"), c.warning)
        } else if self.authz_ran {
            (self.lang.t("Access control enforced"), c.success)
        } else {
            (self.lang.t("Idle"), c.text_subtle)
        };

        let mut card = div()
            .flex()
            .flex_col()
            .gap(px(6.0))
            .flex_shrink_0()
            .p(t.space.md)
            .rounded(t.radius.lg)
            .bg(c.surface)
            .border_1()
            .border_color(if self.authz_findings.is_empty() {
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
                            .child(self.lang.t("Access control")),
                    ),
            );

        for row in &self.authz_rows {
            card = card.child(self.authz_verdict_row(row, c, t));
        }
        card.into_any_element()
    }

    /// 结论卡里的一行:身份名 + 状态/长度 + 判定徽标。
    fn authz_verdict_row(&self, row: &AuthzRow, c: ThemeColors, t: Tokens) -> impl IntoElement {
        div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .child(
                div()
                    .w(px(132.0))
                    .flex_shrink_0()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_muted)
                    .child(identity_label(&row.identity, self.lang)),
            )
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .font_family(crate::model::MONO)
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(format!("HTTP {} · {} B", row.status, row.len)),
            )
            .child(Badge::new(
                verdict_label(row.verdict, self.lang),
                verdict_color(row.verdict, c),
            ))
    }

    /// 发现列表(命中越权 / 未授权访问);空态按是否已测试给不同提示。
    fn authz_findings_view(&self, c: ThemeColors, t: Tokens) -> AnyElement {
        if self.authz_findings.is_empty() {
            let (text, icon) = if self.authz_ran && !self.authz_busy {
                (self.lang.t("No access control issues"), IconName::Check)
            } else {
                (
                    self.lang.t("Configure identities and start testing"),
                    IconName::Shield,
                )
            };
            return EmptyState::new(text).icon(icon).into_any_element();
        }
        let mut list = div()
            .id("authz-findings")
            .flex_1()
            .min_h(px(0.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(t.space.sm);
        for f in &self.authz_findings {
            list = list.child(finding_card(f, self.lang, c, t));
        }
        list.into_any_element()
    }

    /// 测试日志列表(彩色,最近 300 行)。
    fn authz_log_view(&self, c: ThemeColors, t: Tokens) -> impl IntoElement {
        let mut list = div()
            .id("authz-log")
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
        let start = self.authz_log.len().saturating_sub(300);
        for l in &self.authz_log[start..] {
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

/// 身份名 → 界面标签(英文 key 走 i18n)。
fn identity_label(name: &str, lang: crate::i18n::Lang) -> SharedString {
    match name {
        "high" => lang.t("High-privilege (baseline)"),
        "low" => lang.t("Low-privilege"),
        "anonymous" => lang.t("Anonymous"),
        other => SharedString::from(other.to_string()),
    }
}

/// 判定码 → 界面标签。
fn verdict_label(code: u8, lang: crate::i18n::Lang) -> SharedString {
    match code {
        V_ENFORCED => lang.t("Enforced"),
        V_BYPASS => lang.t("Bypass"),
        V_INCONCLUSIVE => lang.t("Inconclusive"),
        _ => lang.t("Baseline"),
    }
}

/// 判定码 → 颜色(拦截绿 / 越权红 / 无法判定灰 / 基准蓝)。
fn verdict_color(code: u8, c: ThemeColors) -> Hsla {
    match code {
        V_ENFORCED => c.success,
        V_BYPASS => c.danger,
        V_INCONCLUSIVE => c.text_muted,
        _ => c.primary,
    }
}
