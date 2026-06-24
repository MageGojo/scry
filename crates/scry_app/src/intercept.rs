//! 交互式拦截(Intercept 断点队列)—— 对标 Burp Proxy 的 Intercept。
//!
//! 机制:抓包内核在 `on_request` / `on_response` 钩子里命中拦截开关时,把报文快照发到 UI 并**阻塞**
//! 等用户决策(见 [`crate::ext::ExtRegistry::maybe_intercept`])。UI 在「拦截」页展示队首报文、
//! 允许**编辑原始报文**,然后「放行」(按编辑重建 flow 回传)或「丢弃」(断连)。
//!
//! 全部建在 `scry_app` + 复用现有宿主钩子,**不改 `scry_proxy` 引擎**:放行 = 钩子返回
//! `Continue`(代理用改后的 flow 重建转发),丢弃 = 返回 `Drop`。响应拦截依赖
//! `wants_response_hook()`(开了拦响应即为真),代理据此重建响应字节。

use mage_ui::gpui::Div;
use mage_ui::prelude::*;
use scry_core::HttpFlow;

use crate::ext::{InterceptDecision, InterceptDir};
use crate::model::MONO;
use crate::repeater::{parse_raw_request, render_raw_request, render_raw_response, target_string};
use crate::rules::{Condition, Field, Op, ReplaceRule, ScopeRule, Target};
use crate::state::{HistTab, ScryApp, Tab};
use crate::widgets::{divider, section_label};

impl ScryApp {
    // ── 队列驱动 ──

    /// 每拍排空拦截通道:新项入队 → (在代理页时)自动切到「拦截」页 → 刷新编辑器到队首。
    pub fn drain_intercepts(&mut self, cx: &mut Context<Self>) {
        // 借用 rx 期间先收集,借用结束后再入队(规避对 self 的双重借用)。
        let mut incoming = Vec::new();
        if let Some(rx) = &self.intercept_rx {
            while let Ok(item) = rx.try_recv() {
                incoming.push(item);
            }
        }
        let got = !incoming.is_empty();
        for item in incoming {
            self.intercept_queue.push_back(item);
        }
        if got && self.tab == Tab::Proxy && self.hist_tab != HistTab::Intercept {
            self.hist_tab = HistTab::Intercept; // 拦到东西自动亮出来,避免静默暂停
        }
        self.refresh_intercept_editor(cx);
    }

    /// 把编辑器同步到队首报文(仅当队首 id 变化才重灌,保住用户正在做的编辑)。
    fn refresh_intercept_editor(&mut self, cx: &mut Context<Self>) {
        match self.intercept_queue.front() {
            Some(item) if self.intercept_edit_id != Some(item.id) => {
                let text = match item.dir {
                    InterceptDir::Request => render_raw_request(&item.flow),
                    InterceptDir::Response => render_raw_response(&item.flow),
                };
                let id = item.id;
                self.intercept_edit.update(cx, |s, cx| s.set_text(text, cx));
                self.intercept_edit_id = Some(id);
            }
            None if self.intercept_edit_id.is_some() => {
                self.intercept_edit.update(cx, |s, cx| s.set_text(String::new(), cx));
                self.intercept_edit_id = None;
            }
            _ => {}
        }
    }

    /// 放行队首:按编辑器文本重建 flow → 回传 `Forward` → 切到下一个。
    pub fn intercept_forward(&mut self, cx: &mut Context<Self>) {
        if let Some(item) = self.intercept_queue.pop_front() {
            let edited = self.intercept_edit.read(cx).text().to_string();
            let mut flow = item.flow;
            match item.dir {
                InterceptDir::Request => apply_edited_request(&mut flow, &edited),
                InterceptDir::Response => apply_edited_response(&mut flow, &edited),
            }
            let _ = item.reply.send(InterceptDecision::Forward(Box::new(flow)));
        }
        self.intercept_edit_id = None;
        self.refresh_intercept_editor(cx);
        cx.notify();
    }

    /// 丢弃队首:回传 `Drop`(代理断连)→ 切到下一个。
    pub fn intercept_drop(&mut self, cx: &mut Context<Self>) {
        if let Some(item) = self.intercept_queue.pop_front() {
            let _ = item.reply.send(InterceptDecision::Drop);
        }
        self.intercept_edit_id = None;
        self.refresh_intercept_editor(cx);
        cx.notify();
    }

    /// 取当前持有报文 + 套用编辑器内容的快照(供「发送到…」用,不改变队列、不放行)。
    fn intercept_edited_snapshot(&self, cx: &mut Context<Self>) -> Option<HttpFlow> {
        let item = self.intercept_queue.front()?;
        let dir = item.dir;
        let mut flow = item.flow.clone();
        let edited = self.intercept_edit.read(cx).text().to_string();
        match dir {
            InterceptDir::Request => apply_edited_request(&mut flow, &edited),
            InterceptDir::Response => apply_edited_response(&mut flow, &edited),
        }
        Some(flow)
    }

    /// 把当前持有的(已编辑)报文「发送到重放」—— 保持拦截不放行(对标 Burp intercept 的 Action)。
    pub fn intercept_send_to_repeater(&mut self, cx: &mut Context<Self>) {
        if let Some(flow) = self.intercept_edited_snapshot(cx) {
            self.fill_repeater_from_flow(&flow, cx);
            let msg = self.lang.t("Sent to Repeater").to_string();
            self.show_toast(msg, cx);
        }
    }

    /// 把当前持有的(已编辑)报文「发送到爆破」—— 保持拦截不放行。
    pub fn intercept_send_to_intruder(&mut self, cx: &mut Context<Self>) {
        if let Some(flow) = self.intercept_edited_snapshot(cx) {
            self.fill_intruder_from_flow(&flow, cx);
            let msg = self.lang.t("Sent to Intruder").to_string();
            self.show_toast(msg, cx);
        }
    }

    /// 放行**全部**待处理项(原样转发)—— 切关拦截 / 停止抓包时收尾。
    pub fn release_all_intercepts(&mut self, cx: &mut Context<Self>) {
        while let Some(item) = self.intercept_queue.pop_front() {
            let _ = item.reply.send(InterceptDecision::Forward(Box::new(item.flow)));
        }
        self.intercept_edit_id = None;
        self.refresh_intercept_editor(cx);
        cx.notify();
    }

    /// 切换「拦截请求」开关;两个开关都关时放行所有已拦项。
    pub fn toggle_intercept_req(&mut self, cx: &mut Context<Self>) {
        let (req, resp) = self.ext.intercept_flags();
        let req = !req;
        self.ext.set_intercept(req, resp);
        if !req && !resp {
            self.release_all_intercepts(cx);
        }
        cx.notify();
    }

    /// 切换「拦截响应」开关;两个开关都关时放行所有已拦项。
    pub fn toggle_intercept_resp(&mut self, cx: &mut Context<Self>) {
        let (req, resp) = self.ext.intercept_flags();
        let resp = !resp;
        self.ext.set_intercept(req, resp);
        if !req && !resp {
            self.release_all_intercepts(cx);
        }
        cx.notify();
    }

    /// 一键关闭拦截:请求 / 响应开关都关 + 放行所有待处理项(对标 Burp 关掉 Intercept)。
    /// 范围规则(Scope)保留不动 —— 关掉的是「开关」,下次需要时再开即按原范围生效。
    pub fn intercept_off(&mut self, cx: &mut Context<Self>) {
        self.ext.set_intercept(false, false);
        self.release_all_intercepts(cx); // 内含 refresh_intercept_editor + cx.notify
        self.show_toast(self.lang.t("Intercept turned off").to_string(), cx);
    }

    /// 当前「拦截范围」摘要,供代理页提示条显示「正在拦截哪些链接」。
    /// 返回 `(启用的 include 规则匹配值去重, 是否存在启用的 exclude 规则)`;
    /// include 为空 = 未限定范围(拦全部流量)。
    pub fn intercept_scope_summary(&self) -> (Vec<String>, bool) {
        let mut includes: Vec<String> = Vec::new();
        let mut has_exclude = false;
        for r in self.scope_rules.iter().filter(|r| r.enabled) {
            if r.intercept {
                let v = r.cond.value.trim();
                if !v.is_empty() && !includes.iter().any(|x| x == v) {
                    includes.push(v.to_string());
                }
            } else {
                has_exclude = true;
            }
        }
        (includes, has_exclude)
    }

    // ── UI:拦截页 ──

    /// 「拦截」页主体:开关行 + 队首报文编辑器 + 放行 / 丢弃;无待处理项时显示状态提示。
    pub fn intercept_panel(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let (req_on, resp_on) = self.ext.intercept_flags();
        let pending = self.intercept_queue.len();

        let status_text = if pending > 0 {
            if self.lang.is_zh() {
                format!("{pending} 个待处理")
            } else {
                format!("{pending} pending")
            }
        } else if req_on || resp_on {
            self.lang.t("Waiting for matching traffic…").to_string()
        } else {
            self.lang.t("Intercept is off").to_string()
        };

        let header = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.md)
            .flex_shrink_0()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.lg)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(t.space.sm)
                            .child(
                                div()
                                    .text_size(t.font_size.sm)
                                    .text_color(c.text_muted)
                                    .child(self.lang.t("Intercept requests")),
                            )
                            .child(Switch::new("ic-req", req_on).on_toggle(cx.listener(
                                |this, _e, _w, cx| this.toggle_intercept_req(cx),
                            ))),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(t.space.sm)
                            .child(
                                div()
                                    .text_size(t.font_size.sm)
                                    .text_color(c.text_muted)
                                    .child(self.lang.t("Intercept responses")),
                            )
                            .child(Switch::new("ic-resp", resp_on).on_toggle(cx.listener(
                                |this, _e, _w, cx| this.toggle_intercept_resp(cx),
                            ))),
                    ),
            )
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(if pending > 0 { c.warning } else { c.text_subtle })
                    .child(status_text),
            );

        let body = if let Some(item) = self.intercept_queue.front() {
            let (dir_label, dir_color) = match item.dir {
                InterceptDir::Request => (self.lang.t("Intercepted request"), c.accent),
                InterceptDir::Response => (self.lang.t("Intercepted response"), c.primary),
            };
            let bar = div()
                .flex()
                .items_center()
                .justify_between()
                .gap(t.space.sm)
                .flex_shrink_0()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(t.space.sm)
                        .min_w(px(0.0))
                        .child(StatusDot::new(dir_color).size(px(7.0)))
                        .child(
                            div()
                                .flex_shrink_0()
                                .text_size(t.font_size.sm)
                                .text_color(c.text)
                                .font_weight(FontWeight::SEMIBOLD)
                                .child(dir_label),
                        )
                        .child(
                            div()
                                .min_w(px(0.0))
                                .truncate()
                                .font_family(MONO)
                                .text_size(t.font_size.xs)
                                .text_color(c.text_muted)
                                .child(item.flow.url()),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(t.space.sm)
                        .child(
                            Button::new("ic-to-rep", self.lang.t("Send to Repeater"))
                                .ghost()
                                .size(ButtonSize::Sm)
                                .icon(IconName::ChevronRight)
                                .on_click(cx.listener(|this, _e, _w, cx| {
                                    this.intercept_send_to_repeater(cx)
                                })),
                        )
                        .child(
                            Button::new("ic-to-int", self.lang.t("Send to Intruder"))
                                .ghost()
                                .size(ButtonSize::Sm)
                                .icon(IconName::Zap)
                                .on_click(cx.listener(|this, _e, _w, cx| {
                                    this.intercept_send_to_intruder(cx)
                                })),
                        )
                        .child(
                            Button::new("ic-forward", self.lang.t("Forward"))
                                .variant(ButtonVariant::Primary)
                                .size(ButtonSize::Sm)
                                .icon(IconName::Refresh)
                                .on_click(
                                    cx.listener(|this, _e, _w, cx| this.intercept_forward(cx)),
                                ),
                        )
                        .child(
                            Button::new("ic-drop", self.lang.t("Drop"))
                                .variant(ButtonVariant::Danger)
                                .size(ButtonSize::Sm)
                                .icon(IconName::Trash)
                                .on_click(cx.listener(|this, _e, _w, cx| this.intercept_drop(cx))),
                        ),
                );
            div()
                .flex_1()
                .min_h(px(0.0))
                .flex()
                .flex_col()
                .gap(t.space.sm)
                .child(bar)
                .child(divider(c))
                .child(
                    div()
                        .id("ic-edit-scroll")
                        .flex_1()
                        .min_h(px(0.0))
                        .overflow_y_scroll()
                        .child(self.intercept_edit.clone()),
                )
                .into_any_element()
        } else {
            let (icon, title, hint) = if req_on || resp_on {
                (
                    IconName::Zap,
                    self.lang.t("Waiting for matching traffic…"),
                    self.lang
                        .t("Matching requests/responses will pause here for you to edit, then Forward or Drop."),
                )
            } else {
                (
                    IconName::Filter,
                    self.lang.t("Intercept is off"),
                    self.lang
                        .t("Turn on a switch above; matching traffic will pause here to edit and forward."),
                )
            };
            div()
                .flex_1()
                .min_h(px(0.0))
                .flex()
                .flex_col()
                .items_center()
                .justify_center()
                .gap(t.space.sm)
                .child(Icon::new(icon).size(px(28.0)).color(c.text_subtle))
                .child(div().text_size(t.font_size.md).text_color(c.text_muted).child(title))
                .child(
                    div()
                        .max_w(px(440.0))
                        .text_size(t.font_size.xs)
                        .text_color(c.text_subtle)
                        .child(hint),
                )
                .into_any_element()
        };

        div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .gap(t.space.md)
            .p(t.space.md)
            .rounded(t.radius.lg)
            .bg(c.surface)
            .border_1()
            .border_color(c.border)
            .child(header)
            .child(body)
    }
}

// ───────────────────────── Options 页:拦截规则(自定义范围 + Match & Replace) ─────────────────────────

impl ScryApp {
    /// 把当前可编辑规则编译并推给引擎(增删 / 启停 / 抓包启动时调用),并持久化到磁盘。
    pub fn sync_rules_to_engine(&self) {
        self.ext.set_scope_rules(&self.scope_rules);
        self.ext.set_replace_rules(&self.replace_rules);
        // 任何规则变更都经此 → 顺手存盘;下次启动 `load_rules` 自动恢复
        //(= 开启后下次遇到同一链接自动执行拦截 / 改包,无需重新配置)。
        crate::rules::save_rules(&self.scope_rules, &self.replace_rules);
    }

    // ── 自定义拦截范围(Scope)──

    /// 按表单新增一条范围规则(值为空则提示)。
    pub fn add_scope_rule(&mut self, cx: &mut Context<Self>) {
        let value = self.sr_value.read(cx).text().trim().to_string();
        if value.is_empty() {
            self.show_toast(self.lang.t("Enter a match value first").to_string(), cx);
            return;
        }
        self.scope_rules.push(ScopeRule {
            enabled: true,
            dir: self.sr_dir,
            cond: Condition {
                field: self.sr_field,
                op: self.sr_op,
                value,
                negate: self.sr_negate,
            },
            intercept: self.sr_intercept,
        });
        self.sr_value.update(cx, |s, cx| s.set_text(String::new(), cx));
        self.sync_rules_to_engine();
        cx.notify();
    }

    pub fn remove_scope_rule(&mut self, idx: usize, cx: &mut Context<Self>) {
        if idx < self.scope_rules.len() {
            self.scope_rules.remove(idx);
            self.sync_rules_to_engine();
            cx.notify();
        }
    }

    pub fn toggle_scope_rule(&mut self, idx: usize, cx: &mut Context<Self>) {
        if let Some(r) = self.scope_rules.get_mut(idx) {
            r.enabled = !r.enabled;
            self.sync_rules_to_engine();
            cx.notify();
        }
    }

    // ── Match & Replace 自动改包 ──

    pub fn add_replace_rule(&mut self, cx: &mut Context<Self>) {
        let find = self.mr_find.read(cx).text().to_string();
        let replace = self.mr_replace.read(cx).text().to_string();
        if find.is_empty() && replace.trim().is_empty() {
            self.show_toast(self.lang.t("Enter find or replace text first").to_string(), cx);
            return;
        }
        self.replace_rules.push(ReplaceRule {
            enabled: true,
            target: self.mr_target,
            is_regex: self.mr_regex,
            find,
            replace,
        });
        self.mr_find.update(cx, |s, cx| s.set_text(String::new(), cx));
        self.mr_replace.update(cx, |s, cx| s.set_text(String::new(), cx));
        self.sync_rules_to_engine();
        cx.notify();
    }

    pub fn remove_replace_rule(&mut self, idx: usize, cx: &mut Context<Self>) {
        if idx < self.replace_rules.len() {
            self.replace_rules.remove(idx);
            self.sync_rules_to_engine();
            cx.notify();
        }
    }

    pub fn toggle_replace_rule(&mut self, idx: usize, cx: &mut Context<Self>) {
        if let Some(r) = self.replace_rules.get_mut(idx) {
            r.enabled = !r.enabled;
            self.sync_rules_to_engine();
            cx.notify();
        }
    }

    // ── 右键快捷(代理历史行 → 范围规则)──

    /// 仅拦截某 Host(添加 include 范围规则 + 打开请求拦截开关)。
    pub fn intercept_only_host(&mut self, host: String, cx: &mut Context<Self>) {
        self.scope_rules.push(ScopeRule {
            enabled: true,
            dir: InterceptDir::Request,
            cond: Condition {
                field: Field::Host,
                op: Op::Equals,
                value: host.clone(),
                negate: false,
            },
            intercept: true,
        });
        let (_, resp) = self.ext.intercept_flags();
        self.ext.set_intercept(true, resp);
        self.sync_rules_to_engine();
        let msg = if self.lang.is_zh() {
            format!("已设为仅拦截 {host} 的请求")
        } else {
            format!("Now intercepting only {host}")
        };
        self.show_toast(msg, cx);
        cx.notify();
    }

    /// 不拦截某 Host(请求 + 响应各加一条 exclude 范围规则)。
    pub fn intercept_skip_host(&mut self, host: String, cx: &mut Context<Self>) {
        for dir in [InterceptDir::Request, InterceptDir::Response] {
            self.scope_rules.push(ScopeRule {
                enabled: true,
                dir,
                cond: Condition {
                    field: Field::Host,
                    op: Op::Equals,
                    value: host.clone(),
                    negate: false,
                },
                intercept: false,
            });
        }
        self.sync_rules_to_engine();
        let msg = if self.lang.is_zh() {
            format!("已排除 {host}(不拦截)")
        } else {
            format!("Excluding {host} from intercept")
        };
        self.show_toast(msg, cx);
        cx.notify();
    }

    // ── UI:Options 页(规则总览 + 新增表单)──

    /// Proxy → Options 页主体:自定义拦截范围卡 + Match & Replace 卡(对标 Burp Proxy options)。
    pub fn options_panel(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let intro = div()
            .flex_shrink_0()
            .text_size(t.font_size.xs)
            .text_color(c.text_subtle)
            .child(self.lang.t(
                "Rules below shape interception and auto-rewrite. Scope decides which traffic pauses in Intercept; Match & Replace rewrites traffic automatically (no pause). Tip: right-click a row in HTTP History for quick scope.",
            ));

        div()
            .id("proxy-options-scroll")
            .flex_1()
            .min_h(px(0.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(t.space.lg)
            .child(intro)
            .child(self.scope_rules_card(cx))
            .child(self.replace_rules_card(cx))
    }

    /// 「自定义拦截范围」卡:规则列表 + 新增表单。
    fn scope_rules_card(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let zh = self.lang.is_zh();

        // 规则列表。
        let mut rows: Vec<AnyElement> = Vec::new();
        for (i, r) in self.scope_rules.iter().enumerate() {
            let dir_txt = match r.dir {
                InterceptDir::Request => self.lang.t("Request"),
                InterceptDir::Response => self.lang.t("Response"),
            };
            let (act_txt, act_col) = if r.intercept {
                (self.lang.t("Intercept"), c.primary)
            } else {
                (self.lang.t("Skip"), c.text_subtle)
            };
            let op_txt = if r.cond.negate {
                if zh {
                    format!("非 {}", self.lang.t(r.cond.op.label()))
                } else {
                    format!("not {}", self.lang.t(r.cond.op.label()))
                }
            } else {
                self.lang.t(r.cond.op.label()).to_string()
            };
            let cond_txt =
                format!("{} {} \"{}\"", self.lang.t(r.cond.field.label()), op_txt, r.cond.value);
            let enabled = r.enabled;
            rows.push(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .py(px(3.0))
                    .child(Switch::new(("sr-en", i), enabled).on_toggle(
                        cx.listener(move |this, _e, _w, cx| this.toggle_scope_rule(i, cx)),
                    ))
                    .child(Badge::new(dir_txt, c.text_muted))
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .truncate()
                            .font_family(MONO)
                            .text_size(t.font_size.xs)
                            .text_color(if enabled { c.text } else { c.text_subtle })
                            .child(cond_txt),
                    )
                    .child(Badge::new(act_txt, act_col))
                    .child(
                        IconButton::new(("sr-del", i), IconName::Trash).ghost().on_click(
                            cx.listener(move |this, _e, _w, cx| this.remove_scope_rule(i, cx)),
                        ),
                    )
                    .into_any_element(),
            );
        }
        let list: AnyElement = if rows.is_empty() {
            div()
                .text_size(t.font_size.sm)
                .text_color(c.text_subtle)
                .child(self.lang.t(
                    "No scope rules — intercept pauses all matching traffic. Add a rule to narrow it.",
                ))
                .into_any_element()
        } else {
            div().flex().flex_col().children(rows).into_any_element()
        };

        card(c, t)
            .child(section_label(self.lang.t("Intercept scope"), c, t))
            .child(list)
            .child(divider(c))
            .child(self.scope_form(cx))
    }

    /// 范围规则新增表单(两行:方向/字段/算子 + 值/取反/动作/添加)。
    fn scope_form(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        // 方向。
        let dir_idx = match self.sr_dir {
            InterceptDir::Request => 0,
            InterceptDir::Response => 1,
        };
        let vd = cx.entity();
        let dir_seg = Segmented::new("sr-dir")
            .items([self.lang.t("Request"), self.lang.t("Response")])
            .selected(dir_idx)
            .on_select(move |i, _e, _w, app| {
                vd.update(app, |this, cx| {
                    this.sr_dir = if i == 0 {
                        InterceptDir::Request
                    } else {
                        InterceptDir::Response
                    };
                    cx.notify();
                });
            });

        // 字段。
        let field_opts: Vec<SharedString> =
            Field::ALL.iter().map(|f| self.lang.t(f.label())).collect();
        let field_idx = Field::ALL.iter().position(|f| *f == self.sr_field).unwrap_or(0);
        let vf = cx.entity();
        let vfo = cx.entity();
        let field_sel = Select::new("sr-field", field_opts, field_idx)
            .width(px(150.0))
            .open(self.sr_field_open)
            .on_toggle(move |_e, _w, app| {
                vfo.update(app, |this, cx| {
                    this.sr_field_open = !this.sr_field_open;
                    cx.notify();
                });
            })
            .on_select(move |i, _e, _w, app| {
                vf.update(app, |this, cx| {
                    this.sr_field = Field::ALL[i];
                    this.sr_field_open = false;
                    cx.notify();
                });
            });

        // 算子。
        let op_opts: Vec<SharedString> = Op::ALL.iter().map(|o| self.lang.t(o.label())).collect();
        let op_idx = Op::ALL.iter().position(|o| *o == self.sr_op).unwrap_or(0);
        let vop = cx.entity();
        let vopo = cx.entity();
        let op_sel = Select::new("sr-op", op_opts, op_idx)
            .width(px(132.0))
            .open(self.sr_op_open)
            .on_toggle(move |_e, _w, app| {
                vopo.update(app, |this, cx| {
                    this.sr_op_open = !this.sr_op_open;
                    cx.notify();
                });
            })
            .on_select(move |i, _e, _w, app| {
                vop.update(app, |this, cx| {
                    this.sr_op = Op::ALL[i];
                    this.sr_op_open = false;
                    cx.notify();
                });
            });

        // 动作:拦截 / 排除。
        let act_idx = if self.sr_intercept { 0 } else { 1 };
        let va = cx.entity();
        let act_seg = Segmented::new("sr-act")
            .items([self.lang.t("Intercept"), self.lang.t("Skip")])
            .selected(act_idx)
            .on_select(move |i, _e, _w, app| {
                va.update(app, |this, cx| {
                    this.sr_intercept = i == 0;
                    cx.notify();
                });
            });

        let row1 = div()
            .flex()
            .items_center()
            .flex_wrap()
            .gap(t.space.sm)
            .child(dir_seg)
            .child(field_sel)
            .child(op_sel);

        let row2 = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .child(div().flex_1().min_w(px(120.0)).child(self.sr_value.clone()))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(4.0))
                    .child(
                        div()
                            .text_size(t.font_size.xs)
                            .text_color(c.text_subtle)
                            .child(self.lang.t("Negate")),
                    )
                    .child(Switch::new("sr-neg", self.sr_negate).on_toggle(cx.listener(
                        |this, _e, _w, cx| {
                            this.sr_negate = !this.sr_negate;
                            cx.notify();
                        },
                    ))),
            )
            .child(act_seg)
            .child(
                Button::new("sr-add", self.lang.t("Add rule"))
                    .variant(ButtonVariant::Primary)
                    .size(ButtonSize::Sm)
                    .icon(IconName::Plus)
                    .on_click(cx.listener(|this, _e, _w, cx| this.add_scope_rule(cx))),
            );

        div().flex().flex_col().gap(t.space.sm).child(row1).child(row2)
    }

    /// 「Match & Replace」卡:规则列表 + 新增表单。
    fn replace_rules_card(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let mut rows: Vec<AnyElement> = Vec::new();
        for (i, r) in self.replace_rules.iter().enumerate() {
            let enabled = r.enabled;
            let mode_txt = if r.is_regex {
                self.lang.t("Regex")
            } else {
                self.lang.t("Text")
            };
            let find_disp = if r.find.is_empty() {
                self.lang.t("(append)").to_string()
            } else {
                r.find.clone()
            };
            let rule_txt = format!("{find_disp}  →  {}", r.replace);
            rows.push(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .py(px(3.0))
                    .child(Switch::new(("mr-en", i), enabled).on_toggle(
                        cx.listener(move |this, _e, _w, cx| this.toggle_replace_rule(i, cx)),
                    ))
                    .child(Badge::new(self.lang.t(r.target.label()), c.text_muted))
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .truncate()
                            .font_family(MONO)
                            .text_size(t.font_size.xs)
                            .text_color(if enabled { c.text } else { c.text_subtle })
                            .child(rule_txt),
                    )
                    .child(Badge::new(
                        mode_txt,
                        if r.is_regex { c.warning } else { c.text_subtle },
                    ))
                    .child(
                        IconButton::new(("mr-del", i), IconName::Trash).ghost().on_click(
                            cx.listener(move |this, _e, _w, cx| this.remove_replace_rule(i, cx)),
                        ),
                    )
                    .into_any_element(),
            );
        }
        let list: AnyElement = if rows.is_empty() {
            div()
                .text_size(t.font_size.sm)
                .text_color(c.text_subtle)
                .child(self.lang.t(
                    "No rules — add one to rewrite live traffic automatically (e.g. spoof User-Agent).",
                ))
                .into_any_element()
        } else {
            div().flex().flex_col().children(rows).into_any_element()
        };

        card(c, t)
            .child(section_label(self.lang.t("Match & Replace"), c, t))
            .child(list)
            .child(divider(c))
            .child(self.replace_form(cx))
    }

    /// Match & Replace 新增表单(两行:目标/模式 + 查找/替换/添加)。
    fn replace_form(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        // 目标。
        let tgt_opts: Vec<SharedString> =
            Target::ALL.iter().map(|x| self.lang.t(x.label())).collect();
        let tgt_idx = Target::ALL.iter().position(|x| *x == self.mr_target).unwrap_or(0);
        let vt = cx.entity();
        let vto = cx.entity();
        let tgt_sel = Select::new("mr-target", tgt_opts, tgt_idx)
            .width(px(168.0))
            .open(self.mr_target_open)
            .on_toggle(move |_e, _w, app| {
                vto.update(app, |this, cx| {
                    this.mr_target_open = !this.mr_target_open;
                    cx.notify();
                });
            })
            .on_select(move |i, _e, _w, app| {
                vt.update(app, |this, cx| {
                    this.mr_target = Target::ALL[i];
                    this.mr_target_open = false;
                    cx.notify();
                });
            });

        // 模式:文本 / 正则。
        let mode_idx = if self.mr_regex { 1 } else { 0 };
        let vm = cx.entity();
        let mode_seg = Segmented::new("mr-mode")
            .items([self.lang.t("Text"), self.lang.t("Regex")])
            .selected(mode_idx)
            .on_select(move |i, _e, _w, app| {
                vm.update(app, |this, cx| {
                    this.mr_regex = i == 1;
                    cx.notify();
                });
            });

        let row1 = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("Target")),
            )
            .child(tgt_sel)
            .child(mode_seg);

        let row2 = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .child(div().flex_1().min_w(px(80.0)).child(self.mr_find.clone()))
            .child(Icon::new(IconName::ChevronRight).size(px(14.0)).color(c.text_subtle))
            .child(div().flex_1().min_w(px(80.0)).child(self.mr_replace.clone()))
            .child(
                Button::new("mr-add", self.lang.t("Add rule"))
                    .variant(ButtonVariant::Primary)
                    .size(ButtonSize::Sm)
                    .icon(IconName::Plus)
                    .on_click(cx.listener(|this, _e, _w, cx| this.add_replace_rule(cx))),
            );

        div().flex().flex_col().gap(t.space.sm).child(row1).child(row2)
    }
}

/// 一张卡(实色面板 + 描边 + 圆角),Options 页用。
fn card(c: ThemeColors, t: Tokens) -> Div {
    div()
        .flex()
        .flex_col()
        .gap(t.space.md)
        .p(t.space.lg)
        .rounded(t.radius.xl)
        .bg(c.surface)
        .border_1()
        .border_color(c.border)
}

/// 把编辑器里的原始请求文本套回 flow(只改 method/path/头/体;host/port 维持原连接)。
/// 解析失败则保持原样(不破坏放行)。
fn apply_edited_request(flow: &mut HttpFlow, edited: &str) {
    let target = target_string(flow);
    if let Ok(req) = parse_raw_request(&target, edited) {
        flow.method = req.method;
        flow.path = req.path;
        flow.req_headers = req.headers;
        flow.req_body = req.body;
        // 关键修复:改包后同步 Content-Length(对标 Burp 自动更新)。否则代理 `build_origin_request`
        // 原样转发旧长度头 → 上游按旧 Content-Length 读 body:改长被截断、改短则挂起,
        // 表现为「拦截修改没生效」。
        sync_content_length(&mut flow.req_headers, flow.req_body.len());
    }
}

/// 让 `Content-Length` 与实际 body 长度一致:有该头则更新,无该头但 body 非空则追加。
fn sync_content_length(headers: &mut Vec<(String, String)>, body_len: usize) {
    if let Some((_, v)) = headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    {
        *v = body_len.to_string();
    } else if body_len > 0 {
        headers.push(("Content-Length".to_string(), body_len.to_string()));
    }
}

/// 把编辑器里的原始响应文本套回 flow(状态行 + 头 + 体)。
fn apply_edited_response(flow: &mut HttpFlow, edited: &str) {
    let norm = edited.replace("\r\n", "\n");
    let (head, body) = norm.split_once("\n\n").unwrap_or((norm.as_str(), ""));
    let mut lines = head.lines();
    if let Some(code) = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
    {
        flow.status = code;
    }
    let mut headers = Vec::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    flow.resp_headers = headers;
    flow.resp_body = body.as_bytes().to_vec();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow() -> HttpFlow {
        HttpFlow::request(
            "GET",
            "https",
            "api.example.com",
            443,
            "/v1",
            vec![("Host".to_string(), "api.example.com".to_string())],
            Vec::new(),
        )
        .with_response(200, vec![], Vec::new(), 0)
    }

    #[test]
    fn edited_request_applies_method_path_body() {
        let mut f = flow();
        let edited = "POST /v2/login HTTP/1.1\nHost: api.example.com\nX-Test: 1\n\n{\"u\":\"a\"}";
        apply_edited_request(&mut f, edited);
        assert_eq!(f.method, "POST");
        assert_eq!(f.path, "/v2/login");
        assert!(f.req_headers.iter().any(|(k, v)| k == "X-Test" && v == "1"));
        assert_eq!(f.req_body, b"{\"u\":\"a\"}");
    }

    #[test]
    fn edited_response_applies_status_headers_body() {
        let mut f = flow();
        let edited = "HTTP/1.1 403 Forbidden\nContent-Type: text/plain\n\nnope";
        apply_edited_response(&mut f, edited);
        assert_eq!(f.status, 403);
        assert!(f.resp_headers.iter().any(|(k, v)| k == "Content-Type" && v == "text/plain"));
        assert_eq!(f.resp_body, b"nope");
    }

    #[test]
    fn edited_request_syncs_content_length() {
        let mut f = flow();
        // 原报文 Content-Length 故意写错(3),改包后应被纠正为实际 body 长度。
        let edited =
            "POST /v2 HTTP/1.1\nHost: api.example.com\nContent-Length: 3\n\n{\"user\":\"longer\"}";
        apply_edited_request(&mut f, edited);
        let cl = f
            .req_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| v.clone());
        assert_eq!(cl, Some(f.req_body.len().to_string()));
        assert_ne!(cl, Some("3".to_string()));
    }

    #[test]
    fn sync_content_length_appends_when_missing() {
        let mut headers = vec![("Host".to_string(), "x".to_string())];
        sync_content_length(&mut headers, 5);
        assert!(headers.iter().any(|(k, v)| k == "Content-Length" && v == "5"));
    }
}
