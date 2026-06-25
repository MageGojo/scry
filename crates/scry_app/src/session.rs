//! Session 页:**会话处理 + 登录宏**(对标 Burp **Session Handling Rules + Macros**)。
//!
//! 定义一条**登录宏**(原始请求,如 `POST /login`),scry 用 [`scry_proxy::replay`] 运行它,从响应里
//! 捕获**会话**(`Set-Cookie` + 可选的 CSRF/JWT 令牌正则)。开启「套用到扫描」后,各扫描器
//! (Nuclei / SQLi / XSS)在开扫前**自动重跑登录宏建立新会话**并把它注入到每个请求
//! (合并 Cookie 头 / 注入令牌头 / `{{token}}` 占位替换);Nuclei 还会在扫描中途检测「掉登录」并自动重登。
//!
//! 引擎是纯函数 [`scry_session`](捕获 / 注入 / 登出判定),本模块负责跑宏(IO)+ 页面 +
//! 给各 runner 复用的 [`SessionPlan`] / [`run_login_macro`] / [`apply_session_to`]。

use std::sync::mpsc;
use std::time::Duration;

use mage_ui::prelude::*;
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};
use scry_proxy::upstream::UpstreamProxy;
use scry_session::{ApplySpec, CaptureSpec, LoggedOutSpec, Part, SessionState};

use crate::logger::LogLevel;
use crate::repeater::parse_raw_request;
use crate::state::{ScryApp, SessionMsg, SqliLevel, SqliLine};
use crate::widgets::{divider, section_label};

/// 一次会话处理计划(登录宏 + 捕获/注入/登出规则 + 上游);供各扫描 runner 复用。
#[derive(Clone)]
pub(crate) struct SessionPlan {
    pub macro_req: ReplayRequest,
    pub capture: CaptureSpec,
    pub apply: ApplySpec,
    pub logout: LoggedOutSpec,
    pub upstream: Option<UpstreamProxy>,
}

/// 运行登录宏:发宏请求 → 从响应捕获会话。返回 `(状态码, 会话)`。
pub(crate) async fn run_login_macro(
    plan: &SessionPlan,
) -> Result<(u16, SessionState), String> {
    let cfg = ReplayConfig {
        upstream: plan.upstream.clone(),
        ..Default::default()
    };
    let flow = replay::send(&plan.macro_req, &cfg)
        .await
        .map_err(|e| format!("{e:#}"))?;
    let resp = scry_session::Resp::new(flow.status, &flow.resp_headers, &flow.resp_body);
    let st = scry_session::build_session(&resp, &plan.capture);
    Ok((flow.status, st))
}

/// 把会话套到一组请求头 + body 上(合并 Cookie / 注入令牌头 / `{{token}}` 替换)。
pub(crate) fn apply_session_to(
    headers: &[(String, String)],
    body: &[u8],
    st: &SessionState,
    apply: &ApplySpec,
) -> (Vec<(String, String)>, Vec<u8>) {
    let mut h = scry_session::inject_headers(headers, st, apply);
    for (_, v) in h.iter_mut() {
        *v = scry_session::substitute(v, st);
    }
    let body = scry_session::substitute(&String::from_utf8_lossy(body), st).into_bytes();
    (h, body)
}

// ───────────────────────── UI + 控制 ─────────────────────────

impl ScryApp {
    /// 由当前编辑器内容构造会话计划(忽略「套用」总开关,用于手动测试登录宏)。
    fn current_plan(&self, cx: &Context<Self>) -> Result<SessionPlan, String> {
        let target = self.session_target.read(cx).text().trim().to_string();
        let raw = self.session_macro.read(cx).text().to_string();
        if target.is_empty() || raw.trim().is_empty() {
            return Err("请填写登录宏目标与原始请求".into());
        }
        let macro_req = parse_raw_request(&target, &raw)?;
        let token_regex = {
            let r = self.session_token_regex.read(cx).text().trim().to_string();
            (!r.is_empty()).then_some(r)
        };
        let token_header = {
            let h = self.session_token_header.read(cx).text().trim().to_string();
            (!h.is_empty()).then_some(h)
        };
        let body_contains = {
            let b = self.session_logout_body.read(cx).text().trim().to_string();
            (!b.is_empty()).then_some(b)
        };
        Ok(SessionPlan {
            macro_req,
            capture: CaptureSpec {
                capture_cookies: self.session_capture_cookies,
                token_regex,
                token_part: Part::Body,
            },
            apply: ApplySpec {
                apply_cookies: true,
                token_header,
            },
            logout: LoggedOutSpec {
                statuses: vec![401, 403],
                redirect_to_login: true,
                body_contains,
            },
            upstream: self.upstream_proxy(cx),
        })
    }

    /// 供各扫描 runner 取用的会话计划:仅当「套用到扫描」开启且宏配置有效时返回。
    pub(crate) fn session_plan(&self, cx: &Context<Self>) -> Option<SessionPlan> {
        if !self.session_apply {
            return None;
        }
        self.current_plan(cx).ok()
    }

    pub fn toggle_session_apply(&mut self, cx: &mut Context<Self>) {
        self.session_apply = !self.session_apply;
        cx.notify();
    }

    pub fn toggle_session_capture(&mut self, cx: &mut Context<Self>) {
        self.session_capture_cookies = !self.session_capture_cookies;
        cx.notify();
    }

    pub fn clear_session(&mut self, cx: &mut Context<Self>) {
        self.session_active = None;
        self.session_status = None;
        self.session_msg = None;
        cx.notify();
    }

    /// 手动运行登录宏(测试 + 建立会话)。
    pub fn start_session_login(&mut self, cx: &mut Context<Self>) {
        if self.session_busy {
            return;
        }
        let plan = match self.current_plan(cx) {
            Ok(p) => p,
            Err(e) => {
                self.session_msg = Some(e.clone());
                self.session_log.push(SqliLine {
                    level: SqliLevel::Bad,
                    text: e,
                });
                cx.notify();
                return;
            }
        };
        self.session_busy = true;
        self.session_msg = Some(self.lang.t("Running login macro…").to_string());
        self.session_log.push(SqliLine {
            level: SqliLevel::Info,
            text: format!("运行登录宏 · {} {}", plan.macro_req.method, plan.macro_req.host),
        });
        let (tx, rx) = mpsc::channel::<SessionMsg>();
        self.session_rx = Some(rx);
        self.push_log(LogLevel::Info, "session", "运行登录宏");
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
                rt.block_on(async move {
                    match run_login_macro(&plan).await {
                        Ok((status, st)) => {
                            let _ = tx.send(SessionMsg {
                                line: Some(SqliLine {
                                    level: if st.is_empty() {
                                        SqliLevel::Warn
                                    } else {
                                        SqliLevel::Good
                                    },
                                    text: format!("登录宏完成(HTTP {status}):{}", st.summary()),
                                }),
                                result: Some((status, st)),
                                error: None,
                                done: true,
                            });
                        }
                        Err(e) => {
                            let _ = tx.send(SessionMsg {
                                line: Some(SqliLine {
                                    level: SqliLevel::Bad,
                                    text: format!("登录宏失败:{e}"),
                                }),
                                result: None,
                                error: Some(e),
                                done: true,
                            });
                        }
                    }
                });
            })
            .detach();

        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(120))
                    .await;
                let keep = this.update(cx, |this, cx| {
                    this.drain_session();
                    cx.notify();
                    this.session_busy
                });
                match keep {
                    Ok(true) => continue,
                    _ => break,
                }
            }
        })
        .detach();
    }

    fn drain_session(&mut self) {
        let Some(rx) = &self.session_rx else {
            return;
        };
        let mut done = false;
        while let Ok(msg) = rx.try_recv() {
            if let Some(l) = msg.line {
                self.session_log.push(l);
            }
            if let Some((status, st)) = msg.result {
                self.session_status = Some(status);
                self.session_active = Some(st);
                self.session_msg = None;
            }
            if let Some(e) = msg.error {
                self.session_msg = Some(e);
            }
            if msg.done {
                done = true;
            }
        }
        if self.session_log.len() > 200 {
            let cut = self.session_log.len() - 200;
            self.session_log.drain(0..cut);
        }
        if done {
            self.session_busy = false;
            self.session_rx = None;
            match &self.session_active {
                Some(st) if !st.is_empty() => {
                    self.push_log(LogLevel::Success, "session", "登录宏完成 · 会话已捕获")
                }
                _ => self.push_log(LogLevel::Warning, "session", "登录宏完成 · 未捕获到会话"),
            }
        }
    }

    /// Session 页主体。
    pub fn session_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let action = if self.session_busy {
            Button::new("session-run", self.lang.t("Running…"))
                .variant(ButtonVariant::Ghost)
                .size(ButtonSize::Sm)
                .icon(IconName::Refresh)
        } else {
            Button::new("session-run", self.lang.t("Run login macro"))
                .variant(ButtonVariant::Primary)
                .size(ButtonSize::Sm)
                .icon(IconName::Power)
                .on_click(cx.listener(|this, _e, _w, cx| this.start_session_login(cx)))
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
                    .child(Icon::new(IconName::Power).size(px(15.0)).color(c.text_subtle))
                    .child(
                        div()
                            .text_size(t.font_size.sm)
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(c.text)
                            .child(self.lang.t("Session handling")),
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
                            .child(self.lang.t("Apply to scans")),
                    )
                    .child(
                        Switch::new("session-apply", self.session_apply).on_toggle(cx.listener(
                            |this, _e, _w, cx| this.toggle_session_apply(cx),
                        )),
                    ),
            )
            .child(action);
        if let Some(p) = &self.session_msg {
            toolbar = toolbar.child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(if self.session_busy { c.warning } else { c.text_muted })
                    .child(p.clone()),
            );
        }

        let hint = div()
            .flex_shrink_0()
            .text_size(t.font_size.xs)
            .text_color(c.text_subtle)
            .child(self.lang.t(
                "Scans auto re-login via the macro and inject the captured session (Cookie + token).",
            ));

        // 左:目标 + 登录宏。
        let left = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0))
            .child(section_label(self.lang.t("Target"), c, t))
            .child(self.session_target.clone())
            .child(section_label(self.lang.t("Login macro (raw request)"), c, t))
            .child(
                div()
                    .id("session-macro-scroll")
                    .flex_1()
                    .min_h(px(0.0))
                    .overflow_y_scroll()
                    .rounded(t.radius.lg)
                    .border_1()
                    .border_color(c.border)
                    .bg(c.surface)
                    .p(t.space.sm)
                    .child(self.session_macro.clone()),
            );

        // 右:捕获/注入配置 + 活动会话卡 + 日志。
        let mut right = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0))
            .child(self.session_config_card(c, t, cx))
            .child(self.session_active_card(c, t, cx));
        if !self.session_log.is_empty() {
            right = right.child(self.session_log_view(c, t));
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

    /// 捕获 / 注入配置卡。
    fn session_config_card(&self, c: ThemeColors, t: Tokens, cx: &mut Context<Self>) -> AnyElement {
        div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_shrink_0()
            .p(t.space.md)
            .rounded(t.radius.lg)
            .bg(c.surface)
            .border_1()
            .border_color(c.border)
            .child(section_label(self.lang.t("Capture & inject"), c, t))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_size(t.font_size.xs)
                            .text_color(c.text_muted)
                            .child(self.lang.t("Capture Set-Cookie")),
                    )
                    .child(
                        Switch::new("session-cap", self.session_capture_cookies).on_toggle(
                            cx.listener(|this, _e, _w, cx| this.toggle_session_capture(cx)),
                        ),
                    ),
            )
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("Token regex (optional)")),
            )
            .child(self.session_token_regex.clone())
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("Inject token into header (optional)")),
            )
            .child(self.session_token_header.clone())
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("Logged-out body marker (optional)")),
            )
            .child(self.session_logout_body.clone())
            .into_any_element()
    }

    /// 活动会话卡:状态 + 摘要 + 清除。
    fn session_active_card(&self, c: ThemeColors, t: Tokens, cx: &mut Context<Self>) -> AnyElement {
        let (badge_text, badge_color) = match &self.session_active {
            Some(st) if !st.is_empty() => (self.lang.t("Session active"), c.success),
            _ => (self.lang.t("No session"), c.text_subtle),
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
            .border_color(c.border)
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
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
                                    .child(self.lang.t("Active session")),
                            ),
                    )
                    .child(
                        Button::new("session-clear", self.lang.t("Clear"))
                            .variant(ButtonVariant::Ghost)
                            .size(ButtonSize::Sm)
                            .icon(IconName::Trash)
                            .on_click(cx.listener(|this, _e, _w, cx| this.clear_session(cx))),
                    ),
            );
        if let Some(status) = self.session_status {
            card = card.child(FieldRow::new(self.lang.t("Macro status"), format!("HTTP {status}")));
        }
        if let Some(st) = &self.session_active {
            card = card.child(
                div()
                    .font_family(crate::model::MONO)
                    .text_size(t.font_size.xs)
                    .text_color(c.text_muted)
                    .child(st.summary()),
            );
            if let Some(ch) = st.cookie_header() {
                card = card.child(
                    div()
                        .font_family(crate::model::MONO)
                        .min_w(px(0.0))
                        .truncate()
                        .text_size(t.font_size.xs)
                        .text_color(c.text_subtle)
                        .child(format!("Cookie: {ch}")),
                );
            }
        }
        card.into_any_element()
    }

    /// 运行日志(彩色,最近 200 行)。
    fn session_log_view(&self, c: ThemeColors, t: Tokens) -> impl IntoElement {
        let mut list = div()
            .id("session-log")
            .flex_shrink_0()
            .h(px(150.0))
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
        let start = self.session_log.len().saturating_sub(200);
        for l in &self.session_log[start..] {
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
