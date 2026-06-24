//! 应用外壳:顶栏(工具页签)+ 左栏(会话 / 工具 / 项目)+ 右侧 Inspector + 图标栏 + 状态栏,
//! 以及把各页装进三栏布局的 [`Render`] 实现。各面板无状态,通过 `cx.listener` 回写 [`ScryApp`]。

use std::time::Duration;

use mage_ui::gpui::{deferred, ClipboardItem};
use mage_ui::prelude::*;
use mage_ui::theme;

use scry_analyze::{request_cookies, response_set_cookies, CodeLang};

use crate::model::{self, method_color, pseudo_ip, status_color, tone_color, MONO};
use crate::state::{CaptureMode, InspTab, ScryApp, Tab};
use crate::widgets::{count_pill, divider, section_label, stat};

const TRANSPARENT: Hsla = Hsla { h: 0.0, s: 0.0, l: 0.0, a: 0.0 };

impl ScryApp {
    // ── 顶栏 ──────────────────────────────────────────────────────

    fn topbar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let mode = cx.theme().mode;

        let brand = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .flex_shrink_0()
            .child(TechIcon::new("S", c.primary).size(px(34.0)).radius(t.radius.md))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .text_size(t.font_size.md)
                            .text_color(c.text)
                            .font_weight(FontWeight::SEMIBOLD)
                            .child("Scry"),
                    )
                    .child(
                        div()
                            .text_size(t.font_size.xs)
                            .text_color(c.text_subtle)
                            .child(self.lang.t("Pentest Suite")),
                    ),
            );

        let mut tabs = Vec::new();
        for &tb in Tab::ALL.iter() {
            tabs.push(self.top_tab(tb, cx).into_any_element());
        }

        let cap = self.capturing;
        let conn = div()
            .id("conn-pill")
            .flex()
            .items_center()
            .gap(px(7.0))
            .px(t.space.md)
            .py(px(6.0))
            .rounded(t.radius.full)
            .bg(c.glass)
            .border_1()
            .border_color(c.glass_border)
            .cursor_pointer()
            .hover(move |s| s.bg(c.surface_hover))
            .child(StatusDot::new(if cap { c.success } else { c.text_subtle }))
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_muted)
                    .child(if self.capture_mode == CaptureMode::Proxy {
                        SharedString::from("127.0.0.1:8888")
                    } else {
                        self.lang.t("Kernel sniff")
                    }),
            )
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(if cap { c.success } else { c.text_subtle })
                    .child(self.lang.t(if cap { "Capturing" } else { "Stopped" })),
            )
            .on_click(cx.listener(|this, _e, _w, cx| this.toggle_capture(cx)));

        let lang_btn = div()
            .id("lang-toggle")
            .flex()
            .items_center()
            .justify_center()
            .w(px(32.0))
            .h(px(32.0))
            .rounded(t.radius.md)
            .cursor_pointer()
            .border_1()
            .border_color(c.glass_border)
            .bg(c.glass)
            .text_size(t.font_size.xs)
            .text_color(c.text_muted)
            .font_weight(FontWeight::SEMIBOLD)
            .hover(move |s| s.bg(c.surface_hover))
            .child(self.lang.short())
            .on_click(cx.listener(|this, _e, _w, cx| this.toggle_lang(cx)));

        let right = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .flex_shrink_0()
            .child(conn)
            .child(lang_btn)
            .child(
                IconButton::new(
                    "theme-toggle",
                    if mode == ThemeMode::Dark {
                        IconName::Moon
                    } else {
                        IconName::Sun
                    },
                )
                .on_click(|_e, window, cx| {
                    theme::toggle(cx);
                    window.refresh();
                }),
            )
            .child(IconButton::new("settings-btn", IconName::Settings).on_click(
                cx.listener(|this, _e, _w, cx| {
                    this.tab = Tab::Settings;
                    cx.notify();
                }),
            ))
            .child(Avatar::new("SH", c.primary).size(px(30.0)));

        div()
            .flex()
            .items_center()
            .gap(t.space.lg)
            .w_full()
            .h(px(58.0))
            .flex_shrink_0()
            // 左侧仅留出 macOS 红绿灯按钮的最小空间,品牌区尽量靠左(实测红绿灯右缘≈69px)。
            .pl(px(60.0))
            .pr(t.space.lg)
            .bg(linear_gradient(
                180.0,
                linear_color_stop(c.surface, 0.0),
                linear_color_stop(c.background, 1.0),
            ))
            .border_b_1()
            .border_color(c.border)
            .child(brand)
            .child(
                // 页签过多时横向滚动(触控板左右滑 / Shift+滚轮),不再被裁掉隐藏。
                div()
                    .id("top-tabs")
                    .flex_1()
                    .min_w(px(0.0))
                    .flex()
                    .items_center()
                    .gap(px(2.0))
                    .overflow_x_scroll()
                    .children(tabs),
            )
            .child(right)
    }

    fn top_tab(&self, tab: Tab, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let active = self.tab == tab;

        div()
            .id(SharedString::from(format!("tab-{}", tab.label())))
            .flex()
            .flex_shrink_0()
            .items_center()
            .gap(px(7.0))
            .px(px(10.0))
            .py(px(7.0))
            .rounded(t.radius.md)
            .cursor_pointer()
            .border_1()
            .border_color(if active { c.glass_border } else { TRANSPARENT })
            .when(active, |d| d.bg(c.glass))
            .hover(move |s| s.bg(c.surface_hover))
            .child(
                Icon::new(tab.icon())
                    .size(px(15.0))
                    .color(if active { c.primary } else { c.text_subtle }),
            )
            .child(
                div()
                    .whitespace_nowrap()
                    .text_size(t.font_size.sm)
                    .text_color(if active { c.text } else { c.text_muted })
                    .child(self.lang.t(tab.label())),
            )
            .on_click(cx.listener(move |this, _e, _w, cx| {
                this.tab = tab;
                cx.notify();
            }))
    }

    // ── 左栏 ──────────────────────────────────────────────────────

    fn left_panel(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        // Sessions
        let mut sessions = Vec::new();
        for i in 0..self.sessions.len() {
            sessions.push(self.session_row(i, cx).into_any_element());
        }
        let sessions_block = div()
            .flex()
            .flex_col()
            .gap(px(4.0))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(section_label(self.lang.t("Sessions"), c, t))
                    .child(
                        IconButton::new("new-session", IconName::Plus)
                            .size(px(22.0))
                            .icon_size(px(13.0))
                            .on_click(cx.listener(|this, _e, _w, cx| this.add_session(cx))),
                    ),
            )
            .children(sessions);

        // Tools
        let tools: [(IconName, &'static str, Option<Tab>); 11] = [
            (IconName::Filter, "Scope", None),
            (IconName::Layers, "SQLi", Some(Tab::Sqli)),
            (IconName::Tag, "XSS", Some(Tab::Xss)),
            (IconName::Shield, "Authz", Some(Tab::Authz)),
            (IconName::GitBranch, "Spider", Some(Tab::Spider)),
            (IconName::Refresh, "Repeater", Some(Tab::Repeater)),
            (IconName::Zap, "Intruder", Some(Tab::Intruder)),
            (IconName::Sort, "Sequencer", Some(Tab::Sequencer)),
            (IconName::Hash, "Decoder", Some(Tab::Decoder)),
            (IconName::Copy, "Comparer", Some(Tab::Comparer)),
            (IconName::Clock, "Logger", Some(Tab::Logger)),
        ];
        let mut tool_rows = Vec::new();
        for (icon, label, target) in tools {
            tool_rows.push(self.tool_row(icon, label, target, cx).into_any_element());
        }
        let tools_block = div()
            .flex()
            .flex_col()
            .gap(px(2.0))
            .child(section_label(self.lang.t("Tools"), c, t))
            .children(tool_rows);

        div()
            .w(px(248.0))
            .flex_shrink_0()
            .flex()
            .flex_col()
            .min_h(px(0.0))
            .bg(c.surface)
            .border_r_1()
            .border_color(c.border)
            .child(
                div()
                    .id("left-scroll")
                    .flex_1()
                    .min_h(px(0.0))
                    .overflow_y_scroll()
                    .flex()
                    .flex_col()
                    .gap(t.space.lg)
                    .p(t.space.md)
                    .child(sessions_block)
                    .child(divider(c))
                    .child(tools_block),
            )
    }

    fn session_row(&self, i: usize, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let s = &self.sessions[i];
        let name = s.name.clone();
        // 活动会话数据在 self.flows;非活动会话在各自存档。
        let count = if i == self.active_session {
            self.flows.len()
        } else {
            s.flows.len()
        };
        let color = tone_color(s.tone, c);
        let active = i == self.active_session;
        let open = active && self.host_cat_open;
        let renaming = self.rename_idx == Some(i);
        let can_delete = self.sessions.len() > 1;

        // 左:状态点 + 名字 / 重命名输入框。名字区独立 on_click(切换/展开),与右侧按钮区**兄弟分离**避免点击冒泡。
        let left: AnyElement = if renaming {
            div()
                .flex_1()
                .min_w(px(0.0))
                .child(self.rename_input.clone())
                .into_any_element()
        } else {
            div()
                .id(("session-name", i))
                .flex()
                .items_center()
                .gap(t.space.sm)
                .flex_1()
                .min_w(px(0.0))
                .cursor_pointer()
                .child(StatusDot::new(color))
                .child(
                    div()
                        .min_w(px(0.0))
                        .truncate()
                        .text_size(t.font_size.sm)
                        .text_color(if active { c.text } else { c.text_muted })
                        .child(name),
                )
                .on_click(cx.listener(move |this, _e, _w, cx| {
                    if this.active_session == i {
                        this.host_cat_open = !this.host_cat_open;
                        cx.notify();
                    } else {
                        this.switch_session(i, cx);
                        this.host_cat_open = true;
                    }
                }))
                .into_any_element()
        };

        // 右:重命名 / 删除按钮(仅活动会话)+ 展开箭头 + 计数。
        let mut right = div().flex().items_center().gap(px(4.0)).flex_shrink_0();
        if renaming {
            right = right.child(
                IconButton::new(("rn-ok", i), IconName::Check)
                    .size(px(20.0))
                    .icon_size(px(12.0))
                    .on_click(cx.listener(|this, _e, _w, cx| this.commit_rename(cx))),
            );
        } else if active {
            right = right
                .child(
                    IconButton::new(("rn", i), IconName::Tag)
                        .size(px(20.0))
                        .icon_size(px(12.0))
                        .on_click(cx.listener(move |this, _e, _w, cx| this.start_rename(i, cx))),
                )
                .when(can_delete, |r| {
                    r.child(
                        IconButton::new(("del", i), IconName::Trash)
                            .size(px(20.0))
                            .icon_size(px(12.0))
                            .on_click(
                                cx.listener(move |this, _e, _w, cx| this.delete_session(i, cx)),
                            ),
                    )
                })
                .child(
                    Icon::new(if open {
                        IconName::ChevronDown
                    } else {
                        IconName::ChevronRight
                    })
                    .size(px(13.0))
                    .color(c.text_subtle),
                );
        }
        right = right.child(count_pill(count, color, t));

        let row = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.sm)
            .px(t.space.sm)
            .py(t.space.sm)
            .rounded(t.radius.md)
            .border_1()
            .border_color(if active { c.glass_border } else { TRANSPARENT })
            .when(active, |d| d.bg(c.glass))
            .hover(move |s| s.bg(c.surface_hover))
            .child(left)
            .child(right);

        // 网站分类**嵌在当前会话内**:展开时在会话行下方缩进显示。
        let mut container = div().flex().flex_col().gap(px(3.0)).child(row);
        if open {
            container = container.child(self.session_sites(cx));
        }
        container
    }

    /// 把当前流量按「网站」(eTLD+1)分组并按条数降序。
    fn site_groups(&self) -> Vec<(String, usize)> {
        use std::collections::HashMap;
        let mut m: HashMap<String, usize> = HashMap::new();
        for f in &self.flows {
            *m.entry(model::site_of(&f.host)).or_insert(0) += 1;
        }
        let mut v: Vec<(String, usize)> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    /// 当前会话内嵌的「网站分类」列表(缩进 + 左引导线 + 淡入动画)。
    /// 顶部「全部」复位项,其后按条数降序列出各网站;点选只看该站流量。
    fn session_sites(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let l = self.lang;
        let groups = self.site_groups();
        let total = self.flows.len();

        let mut rows: Vec<AnyElement> = Vec::new();
        rows.push(
            self.site_row("site-all", None, l.t("All"), total, self.host_filter.is_none(), cx)
                .into_any_element(),
        );
        // 网站较多时只列前若干(按条数),其余靠搜索框定位。
        for (site, n) in groups.into_iter().take(24) {
            let active = self.host_filter.as_deref() == Some(site.as_str());
            let id = format!("site-{site}");
            rows.push(
                self.site_row(&id, Some(site.clone()), SharedString::from(site), n, active, cx)
                    .into_any_element(),
            );
        }

        // 淡入动画:每次展开重新播放(收起即卸载,再展开重挂载 → gpui 回收旧动画状态后重播)。
        div()
            .flex()
            .flex_col()
            .gap(px(2.0))
            .ml(px(10.0))
            .pl(px(8.0))
            .border_l_1()
            .border_color(c.border)
            .children(rows)
            .with_animation(
                "scry-cats-fade",
                Animation::new(Duration::from_millis(180)).with_easing(ease_in_out),
                |el, delta| el.opacity(delta),
            )
    }

    /// 「网站分类」里的一行(可点选过滤;`site = None` 表示「全部」复位)。
    fn site_row(
        &self,
        id: &str,
        site: Option<String>,
        label: SharedString,
        count: usize,
        active: bool,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        div()
            .id(SharedString::from(id.to_string()))
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.sm)
            .pl(px(18.0))
            .pr(t.space.xs)
            .py(px(4.0))
            .rounded(t.radius.md)
            .cursor_pointer()
            .border_1()
            .border_color(if active { c.glass_border } else { TRANSPARENT })
            .when(active, |d| d.bg(c.glass))
            .hover(move |s| s.bg(c.surface_hover))
            .child(
                div()
                    .min_w(px(0.0))
                    .truncate()
                    .text_size(t.font_size.sm)
                    .text_color(if active { c.text } else { c.text_muted })
                    .child(label),
            )
            .child(count_pill(count, if active { c.primary } else { c.text_subtle }, t))
            .on_click(cx.listener(move |this, _e, _w, cx| {
                this.host_filter = site.clone();
                this.tab = Tab::Proxy;
                cx.notify();
            }))
    }

    fn tool_row(
        &self,
        icon: IconName,
        label: &'static str,
        target: Option<Tab>,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        div()
            .id(SharedString::from(format!("tool-{label}")))
            .flex()
            .items_center()
            .gap(t.space.sm)
            .px(t.space.sm)
            .py(px(6.0))
            .rounded(t.radius.md)
            .cursor_pointer()
            .hover(move |s| s.bg(c.surface_hover))
            .child(Icon::new(icon).size(px(16.0)).color(c.text_subtle))
            .child(
                div()
                    .text_size(t.font_size.sm)
                    .text_color(c.text_muted)
                    .child(self.lang.t(label)),
            )
            .on_click(cx.listener(move |this, _e, _w, cx| {
                if let Some(tt) = target {
                    this.tab = tt;
                    cx.notify();
                }
            }))
    }

    // ── 右侧 Inspector ────────────────────────────────────────────

    fn inspector(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let insp_idx = InspTab::ALL.iter().position(|x| *x == self.insp_tab).unwrap_or(0);
        let view = cx.entity();
        let header = div()
            .flex()
            .items_center()
            .w_full()
            .h(px(46.0))
            .flex_shrink_0()
            .px(t.space.md)
            .border_b_1()
            .border_color(c.border)
            .child(
                Segmented::new("insp-tabs")
                    .items(InspTab::ALL.map(|x| self.lang.t(x.label())))
                    .selected(insp_idx)
                    .on_select(move |i, _e, _w, app| {
                        view.update(app, |this, cx| {
                            this.insp_tab = InspTab::ALL[i];
                            cx.notify();
                        });
                    }),
            );

        let content = if self.insp_tab == InspTab::Notes {
            div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .p(t.space.lg)
                .child(
                    div()
                        .text_size(t.font_size.sm)
                        .text_color(c.text_subtle)
                        .child(self.lang.t("No notes for this request")),
                )
                .into_any_element()
        } else if let Some(f) = self.current_flow() {
            let m_color = method_color(&f.method, c);
            let s_color = status_color(f.status, c);
            let status_text = if f.status == 0 {
                self.lang.t("Pending").to_string()
            } else {
                format!("{} {}", f.status, model::status_reason(f.status))
            };

            // 概览卡:目标 URL + 关键元信息。
            let general = div()
                .flex()
                .flex_col()
                .gap(t.space.xs)
                .p(t.space.sm)
                .rounded(t.radius.lg)
                .bg(c.glass)
                .border_1()
                .border_color(c.glass_border)
                .child(section_label(self.lang.t("General"), c, t))
                .child(
                    div()
                        .font_family(MONO)
                        .min_w(px(0.0))
                        .truncate()
                        .text_size(t.font_size.xs)
                        .text_color(c.text)
                        .child(format!("{} {}", f.method, f.url())),
                )
                .child(
                    DetailRow::new(IconName::Zap, self.lang.t("Method"))
                        .trailing(Badge::new(f.method.clone(), m_color)),
                )
                .child(
                    DetailRow::new(IconName::Hash, self.lang.t("Status"))
                        .trailing(Badge::new(status_text, s_color)),
                )
                .child(
                    DetailRow::new(IconName::Clock, self.lang.t("Latency"))
                        .value(format!("{} ms", f.duration_ms)),
                )
                .child(DetailRow::new(IconName::Globe, self.lang.t("IP")).value(pseudo_ip(&f.host)))
                .child(
                    DetailRow::new(IconName::Tag, self.lang.t("TLS")).value(if f.scheme == "https" {
                        "TLS 1.3"
                    } else {
                        "—"
                    }),
                );

            let req_headers = f.req_headers.clone();
            let req_cookies = request_cookies(f);
            let resp_headers = f.resp_headers.clone();
            let resp_cookies = response_set_cookies(f);

            div()
                .id("insp-scroll")
                .flex_1()
                .min_h(px(0.0))
                .overflow_y_scroll()
                .flex()
                .flex_col()
                .gap(t.space.sm)
                .p(t.space.md)
                .child(general)
                .child(self.insp_section(0, "Request Headers", IconName::Layers, req_headers, c.accent, cx))
                .child(self.insp_section(1, "Request Cookies", IconName::Tag, req_cookies, c.warning, cx))
                .child(self.insp_section(2, "Response Headers", IconName::Layers, resp_headers, c.primary, cx))
                .child(self.insp_section(3, "Response Cookies", IconName::Tag, resp_cookies, c.success, cx))
                .into_any_element()
        } else {
            div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .p(t.space.lg)
                .child(
                    div()
                        .text_size(t.font_size.sm)
                        .text_color(c.text_subtle)
                        .child(self.lang.t("Select a request to inspect")),
                )
                .into_any_element()
        };

        div()
            .w(px(298.0))
            .flex_shrink_0()
            .flex()
            .flex_col()
            .min_h(px(0.0))
            .bg(c.surface)
            .border_l_1()
            .border_color(c.border)
            .child(header)
            .child(content)
    }

    fn insp_section(
        &self,
        idx: usize,
        title: &'static str,
        icon: IconName,
        rows: Vec<(String, String)>,
        accent: Hsla,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let n = rows.len();

        let mut col = Collapsible::new(("insp-sec", idx), self.lang.t(title))
            .icon(icon)
            .open(self.insp_open[idx])
            .accent(accent)
            .count(n)
            .on_toggle(cx.listener(move |this, _e, _w, cx| {
                this.insp_open[idx] = !this.insp_open[idx];
                cx.notify();
            }));

        if n == 0 {
            col = col.child(
                div()
                    .font_family(MONO)
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("(none)")),
            );
        } else {
            for (k, v) in rows.into_iter().take(60) {
                col = col.child(
                    div()
                        .flex()
                        .gap(px(6.0))
                        .font_family(MONO)
                        .text_size(t.font_size.xs)
                        .child(div().flex_shrink_0().text_color(accent).child(k))
                        .child(div().min_w(px(0.0)).truncate().text_color(c.text_muted).child(v)),
                );
            }
        }
        col
    }

    // ── 右侧图标栏 ────────────────────────────────────────────────

    fn rail(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let items = [
            IconName::Layers,
            IconName::Zap,
            IconName::Package,
            IconName::Tag,
        ];
        let mut btns = Vec::new();
        for (i, icon) in items.into_iter().enumerate() {
            let active = self.rail == i;
            btns.push(
                div()
                    .id(("rail", i))
                    .flex()
                    .items_center()
                    .justify_center()
                    .w(px(38.0))
                    .h(px(38.0))
                    .rounded(t.radius.md)
                    .cursor_pointer()
                    .border_1()
                    .border_color(if active { c.glass_border } else { TRANSPARENT })
                    .when(active, |d| d.bg(c.glass))
                    .hover(move |s| s.bg(c.surface_hover))
                    .child(
                        Icon::new(icon)
                            .size(px(18.0))
                            .color(if active { c.primary } else { c.text_subtle }),
                    )
                    .on_click(cx.listener(move |this, _e, _w, cx| {
                        this.rail = i;
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }

        div()
            .w(px(52.0))
            .flex_shrink_0()
            .flex()
            .flex_col()
            .items_center()
            .gap(t.space.sm)
            .py(t.space.md)
            .bg(c.background)
            .border_l_1()
            .border_color(c.border)
            .children(btns)
    }

    // ── 状态栏 ────────────────────────────────────────────────────

    fn status_bar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let cap = self.capturing;

        let left = div()
            .flex()
            .items_center()
            .gap(t.space.md)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .child(StatusDot::new(c.success))
                    .child(
                        div()
                            .text_size(t.font_size.xs)
                            .text_color(c.success)
                            .child(self.lang.t("Online")),
                    ),
            )
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(if cap { c.success } else { c.text_subtle })
                    .child(self.lang.t(if cap { "Capturing" } else { "Ready" })),
            )
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child("Proxy 127.0.0.1:8888 · CA ~/.scry/ca.pem"),
            );

        let right = div()
            .flex()
            .items_center()
            .gap(t.space.lg)
            .child(stat(self.lang.t("Memory"), "128 MB", c.accent, c, t))
            .child(stat(self.lang.t("Events"), self.flows.len().to_string(), c.primary, c, t))
            .child(stat(self.lang.t("Duration"), self.uptime(), c.success, c, t));

        div()
            .flex()
            .items_center()
            .justify_between()
            .w_full()
            .h(px(28.0))
            .flex_shrink_0()
            .px(t.space.lg)
            .bg(c.surface)
            .border_t_1()
            .border_color(c.border)
            .child(left)
            .child(right)
    }

    /// 中栏页内容分发(对 `Tab` 穷尽匹配:新增页签会被编译器强制处理)。
    fn page(&self, cx: &mut Context<Self>) -> AnyElement {
        match self.tab {
            Tab::Dashboard => self.dashboard_content(cx).into_any_element(),
            Tab::Proxy => self.proxy_content(cx).into_any_element(),
            Tab::Scanner => self.scanner_content(cx).into_any_element(),
            Tab::Sqli => self.sqli_content(cx).into_any_element(),
            Tab::Xss => self.xss_content(cx).into_any_element(),
            Tab::Authz => self.authz_content(cx).into_any_element(),
            Tab::Spider => self.spider_content(cx).into_any_element(),
            Tab::Repeater => self.repeater_content(cx).into_any_element(),
            Tab::Intruder => self.intruder_content(cx).into_any_element(),
            Tab::Sequencer => self.sequencer_content(cx).into_any_element(),
            Tab::Decoder => self.decoder_content(cx).into_any_element(),
            Tab::Comparer => self.comparer_content(cx).into_any_element(),
            Tab::Logger => self.logger_content(cx).into_any_element(),
            Tab::Extender => self.extender_content(cx).into_any_element(),
            Tab::Settings => self.settings_content(cx).into_any_element(),
        }
    }

    // ── 右键上下文菜单 + 提示浮层 ────────────────────────────────────

    /// 代理 history 行右键菜单浮层(**级联**:顶层只列 4 个父类目,具体动作收进各自子菜单,
    /// 避免一屏放不下)。父项 `on_hover` 切换 [`CtxMenu::sub`];二级 / 三级用
    /// [`mage_ui::Menu::no_backdrop`] 浮层、更高 `priority`,定位在父项右侧。
    /// 右键上下文菜单浮层。返回**各层 deferred 菜单**(顶层 + 二级 + 三级),
    /// 由调用方直接铺进根布局的子节点——**绝不能再包一层普通 `div()`**:
    /// gpui/taffy 的 `absolute` 定位相对**直接父元素**,若包进根 flex 列末尾那个 0 高 wrapper,
    /// 菜单根 `absolute().inset_0()` 会贴着屏幕底部(wrapper 在最底),面板 `.top(y)` 直接被推出屏外 → 看不见。
    /// 像 toast 一样把 deferred 作为根布局的直接子节点,才相对整窗定位。
    fn context_menu_overlay(&self, _window: &Window, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let Some(cm) = self.ctx_menu.as_ref() else {
            return Vec::new();
        };
        let idx = cm.flow;
        let (x, y) = (cm.x, cm.y);
        let sub = cm.sub;
        let subsub = cm.subsub;

        // ── 顶层:发送到 / 复制为 / 标记 / 范围(各带 ▸,悬停展开二级) ──
        let parents: [(&str, &str, IconName, u8); 4] = [
            ("ctx-top-send", "Send to", IconName::Refresh, 0),
            ("ctx-top-copy", "Copy as", IconName::Copy, 1),
            ("ctx-top-mark", "Mark", IconName::Tag, 2),
            ("ctx-top-scope", "Scope", IconName::Filter, 3),
        ];
        let mut tops: Vec<AnyElement> = Vec::new();
        for (id, key, icon, which) in parents {
            tops.push(
                MenuItem::new(id, self.lang.t(key))
                    .icon(icon)
                    .submenu(true)
                    .active(sub == Some(which))
                    .on_hover(cx.listener(move |this, hovered: &bool, _w, cx| {
                        // 进入父项即展开其二级(并收起旧的三级);离开不收,以便鼠标移入子菜单。
                        if *hovered {
                            if let Some(cm) = this.ctx_menu.as_mut() {
                                cm.sub = Some(which);
                                cm.subsub = None;
                            }
                            cx.notify();
                        }
                    }))
                    // 点击父项也展开其二级:hover 偶发不灵时的可靠兜底,符合「点一下就开」的直觉。
                    .on_click(cx.listener(move |this, _e, _w, cx| {
                        if let Some(cm) = this.ctx_menu.as_mut() {
                            cm.sub = Some(which);
                            cm.subsub = None;
                        }
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        let top = Menu::new("ctx-menu")
            .at(x, y)
            .min_width(px(168.0))
            .on_dismiss(cx.listener(|this, _e, _w, cx| {
                this.ctx_menu = None;
                cx.notify();
            }))
            .children(tops);

        let mut layers: Vec<AnyElement> = vec![top.into_any_element()];
        if let Some(which) = sub {
            layers.push(self.ctx_submenu(which, idx, x, y, cx));
        }
        if sub == Some(0) && subsub == Some(0) {
            layers.push(self.ctx_comparer_submenu(idx, x, y, cx));
        }
        layers
    }

    /// 顶层弹出宽度(用于把二级菜单定位到父项右侧)。
    const CTX_TOP_W: f32 = 168.0;
    /// 二级弹出宽度(用于把三级菜单定位到二级项右侧)。
    const CTX_SUB_W: f32 = 196.0;
    /// 菜单单项的近似行高(估算子菜单纵向偏移用)。
    const CTX_STEP: f32 = 32.0;

    /// 二级子菜单(`which`:0=发送到 / 1=复制为 / 2=标记 / 3=范围),定位在顶层父项右侧。
    fn ctx_submenu(
        &self,
        which: u8,
        idx: usize,
        tx: Pixels,
        ty: Pixels,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let sx = tx + px(Self::CTX_TOP_W - 8.0);
        let sy = ty + px(which as f32 * Self::CTX_STEP);
        let zh = self.lang.is_zh();
        let mut items: Vec<AnyElement> = Vec::new();
        match which {
            // ── 发送到:重放 / 爆破 / SQLi / XSS,以及三级「比较器」──
            0 => {
                items.push(
                    MenuItem::new("ctx-send-rep", self.lang.t("Repeater"))
                        .icon(IconName::Refresh)
                        .on_click(cx.listener(move |this, _e, _w, cx| {
                            if let Some(f) = this.flows.get(idx).cloned() {
                                this.fill_repeater_from_flow(&f, cx);
                                this.selected = Some(idx);
                                this.tab = Tab::Repeater;
                            }
                            this.ctx_menu = None;
                            cx.notify();
                        }))
                        .into_any_element(),
                );
                items.push(
                    MenuItem::new("ctx-send-int", self.lang.t("Intruder"))
                        .icon(IconName::Zap)
                        .on_click(cx.listener(move |this, _e, _w, cx| {
                            if let Some(f) = this.flows.get(idx).cloned() {
                                this.fill_intruder_from_flow(&f, cx);
                                this.selected = Some(idx);
                                this.tab = Tab::Intruder;
                            }
                            this.ctx_menu = None;
                            cx.notify();
                        }))
                        .into_any_element(),
                );
                items.push(
                    MenuItem::new("ctx-send-sqli", "SQLi")
                        .icon(IconName::Layers)
                        .on_click(cx.listener(move |this, _e, _w, cx| {
                            if let Some(f) = this.flows.get(idx).cloned() {
                                this.fill_sqli_from_flow(&f, cx);
                                this.selected = Some(idx);
                                this.tab = Tab::Sqli;
                            }
                            this.ctx_menu = None;
                            cx.notify();
                        }))
                        .into_any_element(),
                );
                items.push(
                    MenuItem::new("ctx-send-xss", "XSS")
                        .icon(IconName::Tag)
                        .on_click(cx.listener(move |this, _e, _w, cx| {
                            if let Some(f) = this.flows.get(idx).cloned() {
                                this.fill_xss_from_flow(&f, cx);
                                this.selected = Some(idx);
                                this.tab = Tab::Xss;
                            }
                            this.ctx_menu = None;
                            cx.notify();
                        }))
                        .into_any_element(),
                );
                items.push(
                    MenuItem::new("ctx-send-authz", self.lang.t("Authz"))
                        .icon(IconName::Shield)
                        .on_click(cx.listener(move |this, _e, _w, cx| {
                            if let Some(f) = this.flows.get(idx).cloned() {
                                this.fill_authz_from_flow(&f, cx);
                                this.selected = Some(idx);
                                this.tab = Tab::Authz;
                            }
                            this.ctx_menu = None;
                            cx.notify();
                        }))
                        .into_any_element(),
                );
                items.push(Divider::new().into_any_element());
                let cmp_active = self
                    .ctx_menu
                    .as_ref()
                    .map(|c| c.subsub == Some(0))
                    .unwrap_or(false);
                items.push(
                    MenuItem::new("ctx-send-cmp", self.lang.t("Comparer"))
                        .icon(IconName::Copy)
                        .submenu(true)
                        .active(cmp_active)
                        .on_hover(cx.listener(|this, hovered: &bool, _w, cx| {
                            if *hovered {
                                if let Some(cm) = this.ctx_menu.as_mut() {
                                    cm.subsub = Some(0);
                                }
                                cx.notify();
                            }
                        }))
                        .on_click(cx.listener(|this, _e, _w, cx| {
                            if let Some(cm) = this.ctx_menu.as_mut() {
                                cm.subsub = Some(0);
                            }
                            cx.notify();
                        }))
                        .into_any_element(),
                );
            }
            // ── 复制为:curl / Python / fetch / XHR ──
            1 => {
                for (i, cl) in CodeLang::ALL.into_iter().enumerate() {
                    let short = match cl {
                        CodeLang::Curl => "curl",
                        CodeLang::Python => "Python",
                        CodeLang::JsFetch => "fetch",
                        CodeLang::JsXhr => "XHR",
                    };
                    let copied = self.lang.t("Copied to clipboard").to_string();
                    items.push(
                        MenuItem::new(("ctx-copy", i), short)
                            .icon(IconName::Copy)
                            .on_click(cx.listener(move |this, _e, _w, cx| {
                                if let Some(f) = this.flows.get(idx) {
                                    cx.write_to_clipboard(ClipboardItem::new_string(cl.generate(f)));
                                    this.show_toast(copied.clone(), cx);
                                }
                                this.ctx_menu = None;
                                cx.notify();
                            }))
                            .into_any_element(),
                    );
                }
            }
            // ── 标记:红 / 橙 / 绿 / 蓝 / 紫 / 清除 ──
            2 => {
                for (color_idx, zh_l, en_l) in [
                    (1usize, "红", "Red"),
                    (2, "橙", "Orange"),
                    (3, "绿", "Green"),
                    (4, "蓝", "Blue"),
                    (5, "紫", "Purple"),
                ] {
                    let label = if zh { zh_l.to_string() } else { en_l.to_string() };
                    items.push(
                        MenuItem::new(("ctx-mark", color_idx), label)
                            .icon(IconName::Tag)
                            .on_click(cx.listener(move |this, _e, _w, cx| {
                                if let Some(f) = this.flows.get(idx) {
                                    let fp = f.fingerprint();
                                    this.marks.insert(fp, color_idx);
                                }
                                this.ctx_menu = None;
                                cx.notify();
                            }))
                            .into_any_element(),
                    );
                }
                items.push(Divider::new().into_any_element());
                items.push(
                    MenuItem::new("ctx-mark-clear", if zh { "清除标记" } else { "Clear mark" })
                        .icon(IconName::Trash)
                        .on_click(cx.listener(move |this, _e, _w, cx| {
                            if let Some(f) = this.flows.get(idx) {
                                let fp = f.fingerprint();
                                this.marks.remove(&fp);
                            }
                            this.ctx_menu = None;
                            cx.notify();
                        }))
                        .into_any_element(),
                );
            }
            // ── 范围(对标 Burp scope):仅拦此 Host / 不拦此 Host ──
            _ => {
                items.push(
                    MenuItem::new("ctx-int-only", self.lang.t("Intercept only this host"))
                        .icon(IconName::Filter)
                        .on_click(cx.listener(move |this, _e, _w, cx| {
                            let host = this.flows.get(idx).map(|f| f.host.clone());
                            if let Some(host) = host {
                                this.intercept_only_host(host, cx);
                            }
                            this.ctx_menu = None;
                            cx.notify();
                        }))
                        .into_any_element(),
                );
                items.push(
                    MenuItem::new("ctx-int-skip", self.lang.t("Don't intercept this host"))
                        .icon(IconName::Filter)
                        .on_click(cx.listener(move |this, _e, _w, cx| {
                            let host = this.flows.get(idx).map(|f| f.host.clone());
                            if let Some(host) = host {
                                this.intercept_skip_host(host, cx);
                            }
                            this.ctx_menu = None;
                            cx.notify();
                        }))
                        .into_any_element(),
                );
                // 一键关闭拦截(对应用户「右键关闭拦截」诉求):关掉开关 + 放行待处理。
                items.push(Divider::new().into_any_element());
                items.push(
                    MenuItem::new("ctx-int-off", self.lang.t("Turn off intercept"))
                        .icon(IconName::Power)
                        .on_click(cx.listener(|this, _e, _w, cx| {
                            this.intercept_off(cx);
                            this.ctx_menu = None;
                            cx.notify();
                        }))
                        .into_any_element(),
                );
            }
        }
        Menu::new(("ctx-submenu", which as usize))
            .at(sx, sy)
            .min_width(px(Self::CTX_SUB_W))
            .no_backdrop()
            .priority(22)
            .children(items)
            .into_any_element()
    }

    /// 三级子菜单:发送到 → 比较器(请求 / 响应 × A / B),定位在「发送到」二级的「比较器」项右侧。
    fn ctx_comparer_submenu(
        &self,
        idx: usize,
        tx: Pixels,
        ty: Pixels,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        // 「发送到」二级在 (tx+TOP_W-8, ty);「比较器」是其第 5 项(前 5 项 + 1 分隔)。
        let sx = tx + px(Self::CTX_TOP_W - 8.0) + px(Self::CTX_SUB_W - 8.0);
        let sy = ty + px(5.0 * Self::CTX_STEP + 9.0);
        let zh = self.lang.is_zh();
        let mut items: Vec<AnyElement> = Vec::new();
        for (id, label_zh, label_en, is_req, to_a) in [
            ("ctx-cmp-ra", "请求 → A", "Request → A", true, true),
            ("ctx-cmp-rb", "请求 → B", "Request → B", true, false),
            ("ctx-cmp-sa", "响应 → A", "Response → A", false, true),
            ("ctx-cmp-sb", "响应 → B", "Response → B", false, false),
        ] {
            let label = if zh { label_zh } else { label_en };
            items.push(
                MenuItem::new(id, label)
                    .icon(IconName::Copy)
                    .on_click(cx.listener(move |this, _e, _w, cx| {
                        if let Some(f) = this.flows.get(idx).cloned() {
                            let text = if is_req {
                                crate::repeater::render_raw_request(&f)
                            } else {
                                crate::repeater::render_raw_response(&f)
                            };
                            this.selected = Some(idx);
                            this.send_to_comparer(to_a, text, cx);
                        }
                        this.ctx_menu = None;
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        Menu::new("ctx-subsubmenu")
            .at(sx, sy)
            .min_width(px(150.0))
            .no_backdrop()
            .priority(24)
            .children(items)
            .into_any_element()
    }

    /// 短暂提示浮层(底部居中)。
    fn toast_overlay(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let msg = self.toast.clone()?;
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        Some(
            deferred(
                div()
                    .absolute()
                    .left_0()
                    .right_0()
                    .bottom(px(46.0))
                    .flex()
                    .justify_center()
                    .child(
                        div()
                            .px(t.space.md)
                            .py(t.space.sm)
                            .rounded(t.radius.full)
                            .bg(c.glass)
                            .border_1()
                            .border_color(c.glass_border)
                            .text_size(t.font_size.sm)
                            .text_color(c.text)
                            .child(msg),
                    ),
            )
            .with_priority(30)
            .into_any_element(),
        )
    }
}

impl Render for ScryApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let wide = self.tab.is_wide();

        // 当前页可见时,把报文 / 输出同步进各自的只读**可选中**查看器(签名不变则跳过)。
        // 代理所有视图(含美化高亮)统一用可选中文本框(选中 + Cmd/Ctrl+C 复制);
        // 重放响应、爆破响应、解码输出同样用只读可选中查看器。
        match self.tab {
            Tab::Proxy => self.sync_message_inputs(cx),
            Tab::Repeater => self.sync_repeater_views(cx),
            Tab::Intruder => self.sync_intruder_views(cx),
            Tab::Decoder => self.sync_decoder_view(cx),
            _ => {}
        }

        let center = div()
            .flex_1()
            .min_w(px(0.0))
            .flex()
            .flex_col()
            .min_h(px(0.0))
            .bg(c.background)
            .child(self.page(cx));

        let mut body = div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .min_w(px(0.0))
            .child(self.left_panel(cx))
            .child(center);
        if !wide {
            body = body.child(self.inspector(cx)).child(self.rail(cx));
        }

        div()
            .size_full()
            .relative()
            .flex()
            .flex_col()
            .bg(c.background)
            .text_color(c.text)
            .text_size(t.font_size.sm)
            .child(self.topbar(cx))
            .child(body)
            .child(self.status_bar(cx))
            .children(self.context_menu_overlay(window, cx))
            .children(self.toast_overlay(cx))
    }
}
