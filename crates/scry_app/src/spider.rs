//! 爬虫(Spider)页 —— 浏览器驱动站点爬取的独立入口 + 本次发现列表(对齐 Burp 的 Crawl)。
//!
//! 本页负责发起 / 控制爬取并列出本轮**访问过的页**;真正的报文(经 MITM 解密的请求 / 响应)
//! 汇入「代理」页历史(可被扫描器扫)。爬取引擎 = drission(CDP 真实 Chrome),见 [`crate::crawler`]。

use mage_ui::prelude::*;

use crate::crawler::{DEPTH_OPTS, PAGES_OPTS};
use crate::state::ScryApp;
use crate::widgets::divider;

impl ScryApp {
    /// 爬虫页正文:标题说明 + 爬取工具条 + 本次发现列表。
    pub fn spider_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let header = div()
            .flex()
            .flex_col()
            .gap(px(2.0))
            .flex_shrink_0()
            .child(
                div()
                    .text_size(t.font_size.lg)
                    .text_color(c.text)
                    .child(self.lang.t("Spider")),
            )
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("Browser-driven crawl; traffic flows into Proxy history")),
            );

        let crawl_bar = self.crawl_bar(cx);

        let body = if self.crawl_visited.is_empty() {
            EmptyState::new(self.lang.t("Start a crawl to discover pages"))
                .icon(IconName::GitBranch)
                .into_any_element()
        } else {
            let mut list = div()
                .id("spider-list")
                .flex_1()
                .min_h(px(0.0))
                .overflow_y_scroll()
                .flex()
                .flex_col()
                .gap(px(2.0));
            for v in &self.crawl_visited {
                list = list.child(visited_row(&v.url, v.ok, c, t));
            }
            list.into_any_element()
        };

        div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .gap(t.space.md)
            .p(t.space.lg)
            .child(header)
            .child(crawl_bar)
            .child(divider(c))
            .child(body)
    }

    /// 爬虫工具条:Spider 图标 + 种子输入 + 深度 / 页数下拉 + 爬取/停止 + 进度。
    fn crawl_bar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        // 深度下拉。
        let depth_idx = DEPTH_OPTS
            .iter()
            .position(|&v| v == self.crawl_depth)
            .unwrap_or(1);
        let depth_opts: Vec<SharedString> = DEPTH_OPTS
            .iter()
            .map(|v| SharedString::from(v.to_string()))
            .collect();
        let view_dt = cx.entity();
        let view_ds = cx.entity();
        let depth_select = Select::new("crawl-depth", depth_opts, depth_idx)
            .width(px(64.0))
            .open(self.crawl_depth_open)
            .on_toggle(move |_e, _w, app| {
                view_dt.update(app, |this, cx| {
                    this.crawl_depth_open = !this.crawl_depth_open;
                    cx.notify();
                });
            })
            .on_select(move |i, _e, _w, app| {
                view_ds.update(app, |this, cx| this.set_crawl_depth(i, cx));
            });

        // 页数上限下拉。
        let pages_idx = PAGES_OPTS
            .iter()
            .position(|&v| v == self.crawl_pages)
            .unwrap_or(2);
        let pages_opts: Vec<SharedString> = PAGES_OPTS
            .iter()
            .map(|v| SharedString::from(v.to_string()))
            .collect();
        let view_pt = cx.entity();
        let view_ps = cx.entity();
        let pages_select = Select::new("crawl-pages", pages_opts, pages_idx)
            .width(px(80.0))
            .open(self.crawl_pages_open)
            .on_toggle(move |_e, _w, app| {
                view_pt.update(app, |this, cx| {
                    this.crawl_pages_open = !this.crawl_pages_open;
                    cx.notify();
                });
            })
            .on_select(move |i, _e, _w, app| {
                view_ps.update(app, |this, cx| this.set_crawl_pages(i, cx));
            });

        // 爬取 / 停止按钮。
        let action_btn = if self.crawl_busy {
            Button::new("crawl-stop", self.lang.t("Stop"))
                .variant(ButtonVariant::Danger)
                .size(ButtonSize::Sm)
                .icon(IconName::Box)
                .on_click(cx.listener(|this, _e, _w, cx| this.stop_crawl(cx)))
        } else {
            Button::new("crawl-start", self.lang.t("Crawl"))
                .variant(ButtonVariant::Primary)
                .size(ButtonSize::Sm)
                .icon(IconName::GitBranch)
                .on_click(cx.listener(|this, _e, _w, cx| this.start_crawl(cx)))
        };

        let mut bar = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .flex_shrink_0()
            .child(Icon::new(IconName::GitBranch).size(px(15.0)).color(c.primary))
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .flex_shrink_0()
                    .child(self.lang.t("Spider")),
            )
            .child(div().flex_1().min_w(px(120.0)).child(self.crawl_seed.clone()))
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .flex_shrink_0()
                    .child(self.lang.t("Depth")),
            )
            .child(depth_select)
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .flex_shrink_0()
                    .child(self.lang.t("Pages")),
            )
            .child(pages_select)
            .child(action_btn);

        if let Some(prog) = &self.crawl_progress {
            bar = bar.child(
                div()
                    .flex_shrink_0()
                    .text_size(t.font_size.xs)
                    .text_color(if self.crawl_busy { c.warning } else { c.text_muted })
                    .child(prog.clone()),
            );
        }

        bar
    }
}

/// 「本次发现列表」一行:成功 / 失败状态点 + URL(过长截断)。
fn visited_row(url: &str, ok: bool, c: ThemeColors, t: Tokens) -> impl IntoElement {
    let dot = if ok { c.success } else { c.danger };
    let shown = if url.chars().count() > 140 {
        let s: String = url.chars().take(139).collect();
        format!("{s}…")
    } else {
        url.to_string()
    };
    div()
        .flex()
        .items_center()
        .gap(t.space.sm)
        .flex_shrink_0()
        .px(t.space.sm)
        .py(px(4.0))
        .rounded(t.radius.md)
        .overflow_hidden()
        .child(
            div()
                .w(px(7.0))
                .h(px(7.0))
                .rounded(px(99.0))
                .bg(dot)
                .flex_shrink_0(),
        )
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .text_size(t.font_size.xs)
                .text_color(if ok { c.text_muted } else { c.text_subtle })
                .child(shown),
        )
}

