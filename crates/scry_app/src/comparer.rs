//! Comparer 页(对标 Burp Comparer):把两段文本按 行 / 词 / 字符 粒度做 diff,
//! 内联着色展示相同 / 新增 / 删除,并给出相似度与增删统计。
//!
//! diff 内核全在 [`scry_diff`](../../scry_diff)(纯函数、可单测);本文件做 UI 与「视觉分行」着色。

use mage_ui::gpui::Div;
use mage_ui::prelude::*;
use scry_diff::{ChangeTag, DiffReport, Granularity, Span};

use crate::i18n::Lang;
use crate::logger::LogLevel;
use crate::model::MONO;
use crate::state::{ScryApp, Tab};
use crate::widgets::{divider, section_label};

impl ScryApp {
    /// 比较 A、B 两段文本(按当前粒度),产出 diff 报告。
    pub fn run_comparer(&mut self, cx: &mut Context<Self>) {
        let a = self.cmp_a.read(cx).text().to_string();
        let b = self.cmp_b.read(cx).text().to_string();
        let report = scry_diff::diff(&a, &b, self.cmp_gran);
        self.push_log(
            LogLevel::Info,
            "comparer",
            format!(
                "比较 · {} · 相似度 {:.0}% · +{} / -{}",
                self.lang.t(self.cmp_gran.label()),
                report.similarity * 100.0,
                report.inserted_tokens,
                report.deleted_tokens
            ),
        );
        self.cmp_report = Some(report);
        cx.notify();
    }

    /// 交换 A / B 两段内容。
    pub fn swap_comparer(&mut self, cx: &mut Context<Self>) {
        let a = self.cmp_a.read(cx).text().to_string();
        let b = self.cmp_b.read(cx).text().to_string();
        self.cmp_a.update(cx, |st, cx| st.set_text(b, cx));
        self.cmp_b.update(cx, |st, cx| st.set_text(a, cx));
        if self.cmp_report.is_some() {
            self.run_comparer(cx);
        } else {
            cx.notify();
        }
    }

    /// 清空两段与结果。
    pub fn clear_comparer(&mut self, cx: &mut Context<Self>) {
        self.cmp_a.update(cx, |st, cx| st.set_text(String::new(), cx));
        self.cmp_b.update(cx, |st, cx| st.set_text(String::new(), cx));
        self.cmp_report = None;
        cx.notify();
    }

    /// 把一段文本灌进比较器的 A(`to_a=true`)或 B 槽,跳到比较器页并即时重算 diff。
    ///
    /// 供 Proxy 历史右键「请求 / 响应 → 比较器 A / B」与 Repeater 面板头的 →A/→B 按钮复用:
    /// 典型用法是先把一条流灌进 A、再把另一条灌进 B,两槽内容随手可比。
    pub fn send_to_comparer(&mut self, to_a: bool, text: String, cx: &mut Context<Self>) {
        if to_a {
            self.cmp_a.update(cx, |st, cx| st.set_text(text, cx));
        } else {
            self.cmp_b.update(cx, |st, cx| st.set_text(text, cx));
        }
        self.tab = Tab::Comparer;
        // 即时重算:让结果区始终与两槽内容一致(另一槽即便仍是上次/示例内容也照常 diff)。
        self.run_comparer(cx);
        let label = if to_a {
            "Sent to Comparer A"
        } else {
            "Sent to Comparer B"
        };
        self.show_toast(self.lang.t(label).to_string(), cx);
    }

    /// 从系统剪贴板把文本填进比较器 A(`to_a=true`)或 B 槽,并即时重算。
    pub fn paste_comparer_from_clipboard(&mut self, to_a: bool, cx: &mut Context<Self>) {
        match cx.read_from_clipboard().and_then(|it| it.text()) {
            Some(text) if !text.is_empty() => self.send_to_comparer(to_a, text, cx),
            _ => self.show_toast(self.lang.t("Clipboard is empty").to_string(), cx),
        }
    }

    /// Comparer 页主体。
    pub fn comparer_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let lang = self.lang;

        // ── 工具条:比较 / 交换 / 清空 + 粒度分段 + 统计 ──
        let actions = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .child(
                Button::new("cmp-run", lang.t("Compare"))
                    .variant(ButtonVariant::Primary)
                    .size(ButtonSize::Sm)
                    .icon(IconName::Copy)
                    .on_click(cx.listener(|this, _e, _w, cx| this.run_comparer(cx))),
            )
            .child(
                Button::new("cmp-swap", lang.t("Swap A ⇄ B"))
                    .variant(ButtonVariant::Ghost)
                    .size(ButtonSize::Sm)
                    .icon(IconName::Refresh)
                    .on_click(cx.listener(|this, _e, _w, cx| this.swap_comparer(cx))),
            )
            .child(
                Button::new("cmp-paste-a", lang.t("Paste → A"))
                    .variant(ButtonVariant::Ghost)
                    .size(ButtonSize::Sm)
                    .icon(IconName::Copy)
                    .on_click(
                        cx.listener(|this, _e, _w, cx| this.paste_comparer_from_clipboard(true, cx)),
                    ),
            )
            .child(
                Button::new("cmp-paste-b", lang.t("Paste → B"))
                    .variant(ButtonVariant::Ghost)
                    .size(ButtonSize::Sm)
                    .icon(IconName::Copy)
                    .on_click(cx.listener(|this, _e, _w, cx| {
                        this.paste_comparer_from_clipboard(false, cx)
                    })),
            )
            .child(
                Button::new("cmp-clear", lang.t("Clear"))
                    .variant(ButtonVariant::Ghost)
                    .size(ButtonSize::Sm)
                    .icon(IconName::Trash)
                    .on_click(cx.listener(|this, _e, _w, cx| this.clear_comparer(cx))),
            );

        let gran_idx = Granularity::ALL
            .iter()
            .position(|g| *g == self.cmp_gran)
            .unwrap_or(0);
        let view = cx.entity();
        let gran_seg = Segmented::new("cmp-gran")
            .items(Granularity::ALL.map(|g| lang.t(g.label())))
            .selected(gran_idx)
            .on_select(move |i, _e, _w, app| {
                view.update(app, |this, cx| {
                    this.cmp_gran = Granularity::ALL[i];
                    if this.cmp_report.is_some() {
                        this.run_comparer(cx);
                    }
                    cx.notify();
                });
            });

        let left_tools = div()
            .flex()
            .items_center()
            .gap(t.space.md)
            .child(actions)
            .child(gran_seg);

        let stats = self
            .cmp_report
            .as_ref()
            .map(|r| stats_row(r, lang, c, t).into_any_element());

        let toolbar = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.md)
            .flex_shrink_0()
            .child(left_tools)
            .children(stats);

        // ── 两段输入(上半区)──
        let inputs = div()
            .flex()
            .gap(t.space.md)
            .flex_shrink_0()
            .h(px(240.0))
            .child(
                input_panel(lang.t("Item A"), c, t).child(
                    div()
                        .id("cmp-a-scroll")
                        .flex_1()
                        .min_h(px(0.0))
                        .overflow_y_scroll()
                        .child(self.cmp_a.clone()),
                ),
            )
            .child(
                input_panel(lang.t("Item B"), c, t).child(
                    div()
                        .id("cmp-b-scroll")
                        .flex_1()
                        .min_h(px(0.0))
                        .overflow_y_scroll()
                        .child(self.cmp_b.clone()),
                ),
            );

        // ── diff 结果(下半区)──
        let result_body = match &self.cmp_report {
            Some(r) => diff_view(r, lang, c, t).into_any_element(),
            None => EmptyState::new(lang.t("Edit both items, then Compare")).icon(IconName::Copy).into_any_element(),
        };
        let result = div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .gap(t.space.sm)
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
                    .flex_shrink_0()
                    .child(section_label(lang.t("Difference"), c, t))
                    .child(legend(lang, c, t)),
            )
            .child(divider(c))
            .child(result_body);

        div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .gap(t.space.md)
            .p(t.space.lg)
            .child(toolbar)
            .child(inputs)
            .child(result)
    }
}

/// 把片段序列按 `\n` 切成「视觉行」(每行是若干同色片段);用于逐行着色渲染。
fn split_visual_lines(spans: &[Span]) -> Vec<Vec<Span>> {
    let mut lines: Vec<Vec<Span>> = vec![Vec::new()];
    for span in spans {
        for (k, part) in span.text.split('\n').enumerate() {
            if k > 0 {
                lines.push(Vec::new());
            }
            if !part.is_empty() {
                if let Some(line) = lines.last_mut() {
                    line.push(Span {
                        tag: span.tag,
                        text: part.to_string(),
                    });
                }
            }
        }
    }
    lines
}

/// 片段类型 → (前景色, 背景色)。
fn tag_colors(tag: ChangeTag, c: ThemeColors) -> (Hsla, Hsla) {
    match tag {
        ChangeTag::Equal => (c.text_muted, gpui_transparent()),
        ChangeTag::Insert => (c.success, c.success.opacity(0.16)),
        ChangeTag::Delete => (c.danger, c.danger.opacity(0.16)),
    }
}

fn gpui_transparent() -> Hsla {
    Hsla {
        h: 0.0,
        s: 0.0,
        l: 0.0,
        a: 0.0,
    }
}

/// 渲染 diff 结果(逐视觉行 + 行内彩色片段)。
fn diff_view(r: &DiffReport, lang: Lang, c: ThemeColors, t: Tokens) -> impl IntoElement {
    let lines = split_visual_lines(&r.spans);
    let mut rows: Vec<AnyElement> = Vec::with_capacity(lines.len());
    for line in &lines {
        if line.is_empty() {
            rows.push(div().h(px(18.0)).into_any_element());
            continue;
        }
        let mut row = div().flex().flex_row().flex_wrap().items_start();
        for seg in line {
            let (fg, bg) = tag_colors(seg.tag, c);
            row = row.child(
                div()
                    .flex_shrink_0()
                    .text_color(fg)
                    .bg(bg)
                    .rounded(t.radius.sm)
                    .child(SharedString::from(seg.text.clone())),
            );
        }
        rows.push(row.into_any_element());
    }

    if r.identical {
        rows.clear();
        rows.push(
            div()
                .text_color(c.success)
                .child(lang.t("The two items are identical"))
                .into_any_element(),
        );
    }

    div()
        .id("cmp-diff-scroll")
        .flex_1()
        .min_h(px(0.0))
        .overflow_y_scroll()
        .overflow_x_scroll()
        .font_family(MONO)
        .text_size(t.font_size.sm)
        .flex()
        .flex_col()
        .children(rows)
}

/// 顶部统计:相似度 + 新增 / 删除 token 数(+ 完全相同徽标)。
fn stats_row(r: &DiffReport, lang: Lang, c: ThemeColors, t: Tokens) -> impl IntoElement {
    let mut row = div().flex().items_center().gap(t.space.md);
    if r.identical {
        row = row.child(Badge::new(lang.t("Identical"), c.success));
        return row;
    }
    row.child(
        div()
            .text_size(t.font_size.sm)
            .text_color(c.text)
            .child(format!(
                "{} {:.0}%",
                lang.t("Similarity"),
                r.similarity * 100.0
            )),
    )
    .child(
        div()
            .font_family(MONO)
            .text_size(t.font_size.sm)
            .text_color(c.success)
            .child(format!("+{}", r.inserted_tokens)),
    )
    .child(
        div()
            .font_family(MONO)
            .text_size(t.font_size.sm)
            .text_color(c.danger)
            .child(format!("-{}", r.deleted_tokens)),
    )
}

/// 颜色图例(新增 / 删除)。
fn legend(lang: Lang, c: ThemeColors, t: Tokens) -> impl IntoElement {
    let chip = |label: SharedString, color: Hsla| {
        div()
            .flex()
            .items_center()
            .gap(px(4.0))
            .child(div().w(px(8.0)).h(px(8.0)).rounded(t.radius.full).bg(color))
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(label),
            )
    };
    div()
        .flex()
        .items_center()
        .gap(t.space.md)
        .child(chip(lang.t("Added"), c.success))
        .child(chip(lang.t("Removed"), c.danger))
}

/// 输入面板容器(标题 + 内容)。
fn input_panel(title: SharedString, c: ThemeColors, t: Tokens) -> Div {
    div()
        .flex_1()
        .min_w(px(0.0))
        .flex()
        .flex_col()
        .gap(t.space.sm)
        .p(t.space.sm)
        .rounded(t.radius.lg)
        .bg(c.surface)
        .border_1()
        .border_color(c.border)
        .child(
            div()
                .flex_shrink_0()
                .text_size(t.font_size.sm)
                .text_color(c.text)
                .font_weight(FontWeight::SEMIBOLD)
                .child(title),
        )
        .child(divider(c))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visual_lines_split_on_newline() {
        let spans = vec![
            Span {
                tag: ChangeTag::Equal,
                text: "a\nb".to_string(),
            },
            Span {
                tag: ChangeTag::Insert,
                text: "X\n".to_string(),
            },
        ];
        let lines = split_visual_lines(&spans);
        // 行0: "a";行1: "b"+"X";行2: 空(末尾换行)。
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].len(), 1);
        assert_eq!(lines[0][0].text, "a");
        assert_eq!(lines[1].len(), 2);
        assert_eq!(lines[1][1].text, "X");
        assert!(lines[2].is_empty());
    }

    #[test]
    fn visual_lines_single_line() {
        let spans = vec![Span {
            tag: ChangeTag::Equal,
            text: "no newline".to_string(),
        }];
        let lines = split_visual_lines(&spans);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0][0].text, "no newline");
    }
}
