//! Sequencer 页(对标 Burp Sequencer):把一批令牌样本(会话 ID / CSRF 令牌 / API key)
//! 做**随机性 / 熵分析**,评估其可预测性。
//!
//! 计算内核全在 [`scry_seq`](../../scry_seq)(纯函数、可单测);本文件只做 UI:
//! 令牌输入(粘贴 / 载入样例 / 从抓到的 Set-Cookie 提取)→ [`scry_seq::analyze`] → 报告可视化
//! (总体评级 + 关键指标 + 逐字符熵条形图 + FIPS 140-2 自检)。

use mage_ui::gpui::{ClipboardItem, Div};
use mage_ui::prelude::*;
use scry_seq::{PositionEntropy, Quality, SequencerReport};

use crate::i18n::Lang;
use crate::logger::LogLevel;
use crate::model::MONO;
use crate::state::ScryApp;
use crate::widgets::{divider, section_label};

/// 「载入样例」生成的令牌数(160 × 16B = 2560B = 20480bit ≥ 20000 → 足够跑 FIPS)。
const SAMPLE_N: usize = 160;
/// 样例令牌长度(字符)。
const SAMPLE_LEN: usize = 16;
/// 样例随机种子(固定 → 可复现)。
const SAMPLE_SEED: u64 = 0x1234_5678;
/// 逐字符熵条形图最多渲染多少个位置(避免超长令牌刷屏;总熵不受影响)。
const MAX_BARS: usize = 64;

/// 确定性伪随机 base62 令牌生成(演示用,xorshift64,可复现)。每行一个,末尾带换行。
pub fn sample_tokens(n: usize, len: usize, seed: u64) -> String {
    const CS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    // 防全 0(会卡死 xorshift);但不能用 `seed | 1` —— 那会把 42/43 等相邻种子折叠成同一状态,
    // 失去种子区分度。仅当种子恰为 0 时替换为一个固定非零常量。
    let mut state = if seed == 0 {
        0x9E37_79B9_7F4A_7C15
    } else {
        seed
    };
    let mut out = String::with_capacity(n * (len + 1));
    for _ in 0..n {
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let idx = (state % CS.len() as u64) as usize;
            out.push(CS[idx] as char);
        }
        out.push('\n');
    }
    out
}

/// 总体评级 → 主题色(差=红、弱=黄、尚可=青、强=蓝、极强=绿)。
pub fn quality_color(q: Quality, c: ThemeColors) -> Hsla {
    match q {
        Quality::Poor => c.danger,
        Quality::Weak => c.warning,
        Quality::Reasonable => c.accent,
        Quality::Strong => c.primary,
        Quality::Excellent => c.success,
    }
}

/// 单个字符位置的熵 → 条形颜色(越高越绿)。
fn bar_color(bits: f64, c: ThemeColors) -> Hsla {
    if bits >= 5.5 {
        c.success
    } else if bits >= 4.0 {
        c.primary
    } else if bits >= 2.0 {
        c.warning
    } else {
        c.danger
    }
}

impl ScryApp {
    /// 分析输入框里的令牌样本,产出报告。少于 2 个样本则拒绝并提示。
    pub fn run_sequencer(&mut self, cx: &mut Context<Self>) {
        let text = self.seq_input.read(cx).text().to_string();
        let tokens = scry_seq::parse_tokens(&text);
        if tokens.len() < 2 {
            self.seq_report = None;
            self.push_log(
                LogLevel::Warning,
                "seq",
                "序列器:至少需要 2 个令牌样本(每行一个)",
            );
            cx.notify();
            return;
        }
        let report = scry_seq::analyze(&tokens);
        self.push_log(
            LogLevel::Info,
            "seq",
            format!(
                "随机性分析 · {} 样本 · 字符熵 {:.1} bit · {}",
                report.sample_count,
                report.char_entropy_bits,
                self.lang.t(report.quality.label())
            ),
        );
        self.seq_report = Some(report);
        cx.notify();
    }

    /// 载入确定性高熵样例令牌(打开即可演示分析全流程)。
    pub fn load_seq_sample(&mut self, cx: &mut Context<Self>) {
        let s = sample_tokens(SAMPLE_N, SAMPLE_LEN, SAMPLE_SEED);
        self.seq_input.update(cx, |st, cx| st.set_text(s, cx));
        self.seq_report = None;
        self.push_log(
            LogLevel::Info,
            "seq",
            format!("已载入 {SAMPLE_N} 个样例令牌"),
        );
        cx.notify();
    }

    /// 从已抓到的流量里提取 `Set-Cookie` 值作为令牌样本(真实 Burp 工作流)。
    pub fn load_seq_from_flows(&mut self, cx: &mut Context<Self>) {
        let mut vals: Vec<String> = Vec::new();
        for f in &self.flows {
            for (_name, val) in scry_analyze::response_set_cookies(f) {
                if val.len() >= 4 {
                    vals.push(val);
                }
            }
        }
        if vals.is_empty() {
            self.push_log(
                LogLevel::Warning,
                "seq",
                "未从流量中找到可用的 Set-Cookie 令牌",
            );
            cx.notify();
            return;
        }
        let n = vals.len();
        self.seq_input.update(cx, |st, cx| st.set_text(vals.join("\n"), cx));
        self.seq_report = None;
        self.push_log(
            LogLevel::Info,
            "seq",
            format!("从流量提取 {n} 个 Cookie 令牌"),
        );
        cx.notify();
    }

    /// 清空输入与报告。
    pub fn clear_sequencer(&mut self, cx: &mut Context<Self>) {
        self.seq_input.update(cx, |st, cx| st.set_text(String::new(), cx));
        self.seq_report = None;
        cx.notify();
    }

    /// 把当前分析报告整理成文本复制到剪贴板(便于贴进工单 / 笔记)。
    pub fn copy_seq_report(&mut self, cx: &mut Context<Self>) {
        let Some(r) = self.seq_report.as_ref() else {
            self.show_toast(self.lang.t("Analyze first").to_string(), cx);
            return;
        };
        let summary = format_seq_report(r, self.lang);
        cx.write_to_clipboard(ClipboardItem::new_string(summary));
        let msg = self.lang.t("Report copied").to_string();
        self.show_toast(msg, cx);
    }

    /// Sequencer 页主体。
    pub fn sequencer_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let lang = self.lang;

        let n_tokens = scry_seq::parse_tokens(self.seq_input.read(cx).text()).len();

        // ── 工具条:操作按钮 + 令牌计数 ──
        let buttons = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .child(
                Button::new("seq-analyze", lang.t("Analyze"))
                    .variant(ButtonVariant::Primary)
                    .size(ButtonSize::Sm)
                    .icon(IconName::Sort)
                    .on_click(cx.listener(|this, _e, _w, cx| this.run_sequencer(cx))),
            )
            .child(
                Button::new("seq-sample", lang.t("Load sample"))
                    .variant(ButtonVariant::Ghost)
                    .size(ButtonSize::Sm)
                    .icon(IconName::Plus)
                    .on_click(cx.listener(|this, _e, _w, cx| this.load_seq_sample(cx))),
            )
            .child(
                Button::new("seq-from-traffic", lang.t("From traffic"))
                    .variant(ButtonVariant::Ghost)
                    .size(ButtonSize::Sm)
                    .icon(IconName::Globe)
                    .on_click(cx.listener(|this, _e, _w, cx| this.load_seq_from_flows(cx))),
            )
            .child(
                Button::new("seq-copy", lang.t("Copy report"))
                    .variant(ButtonVariant::Ghost)
                    .size(ButtonSize::Sm)
                    .icon(IconName::Copy)
                    .on_click(cx.listener(|this, _e, _w, cx| this.copy_seq_report(cx))),
            )
            .child(
                Button::new("seq-clear", lang.t("Clear"))
                    .variant(ButtonVariant::Ghost)
                    .size(ButtonSize::Sm)
                    .icon(IconName::Trash)
                    .on_click(cx.listener(|this, _e, _w, cx| this.clear_sequencer(cx))),
            );

        let count_text = div()
            .text_size(t.font_size.xs)
            .text_color(c.text_muted)
            .child(format!("{} {}", n_tokens, lang.t("tokens")));

        let toolbar = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.md)
            .flex_shrink_0()
            .child(buttons)
            .child(count_text);

        // ── 左:令牌输入区 ──
        let left = div()
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
            .child(panel_header(
                lang.t("Token samples"),
                lang.t("one token per line"),
                c,
                t,
            ))
            .child(divider(c))
            .child(
                div()
                    .id("seq-input-scroll")
                    .flex_1()
                    .min_h(px(0.0))
                    .overflow_y_scroll()
                    .child(self.seq_input.clone()),
            );

        // ── 右:分析报告区 ──
        let report_body = if let Some(r) = &self.seq_report {
            report_view(r, lang, c, t).into_any_element()
        } else {
            EmptyState::new(lang.t("Paste tokens and Analyze to estimate randomness"))
                .icon(IconName::Sort)
                .into_any_element()
        };
        let right = div()
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
            .child(panel_header(
                lang.t("Analysis"),
                lang.t("entropy & FIPS 140-2"),
                c,
                t,
            ))
            .child(divider(c))
            .child(report_body);

        div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .gap(t.space.md)
            .p(t.space.lg)
            .child(toolbar)
            .child(
                div()
                    .flex()
                    .gap(t.space.md)
                    .flex_1()
                    .min_h(px(0.0))
                    .child(left)
                    .child(right),
            )
    }
}

/// 把分析报告整理成可复制的纯文本摘要(总体评级 + 关键指标 + FIPS 结果)。
fn format_seq_report(r: &SequencerReport, lang: Lang) -> String {
    let mut s = String::new();
    s.push_str("== Scry Sequencer ==\n");
    s.push_str(&format!(
        "{}: {}\n",
        lang.t("Overall quality"),
        lang.t(r.quality.label())
    ));
    s.push_str(&format!(
        "{}: {}  ({}: {})\n",
        lang.t("Samples"),
        r.sample_count,
        lang.t("Unique"),
        r.unique_count
    ));
    s.push_str(&format!(
        "{}: {:.2} bit\n",
        lang.t("Char entropy"),
        r.char_entropy_bits
    ));
    s.push_str(&format!(
        "{}: {:.2} bit\n",
        lang.t("Bit entropy"),
        r.bit_entropy_bits
    ));
    s.push_str(&format!(
        "{}: {:.2} bit\n",
        lang.t("Mean bits/char"),
        r.mean_char_bits
    ));
    s.push_str(&format!(
        "{}: {:.1}%\n",
        lang.t("Ones ratio"),
        r.one_ratio * 100.0
    ));
    if r.fips.evaluated {
        s.push_str("FIPS 140-2:\n");
        for test in &r.fips.tests {
            let res = if test.passed { "PASS" } else { "FAIL" };
            s.push_str(&format!("  [{}] {} — {}\n", res, lang.t(test.name), test.detail));
        }
    } else {
        s.push_str(&format!("FIPS 140-2: n/a ({} bit)\n", r.fips.total_bits));
    }
    s
}

/// 报告主体(可滚动):总体评级 + 重复告警 + 指标 + 逐字符熵 + FIPS。
fn report_view(r: &SequencerReport, lang: Lang, c: ThemeColors, t: Tokens) -> impl IntoElement {
    div()
        .id("seq-report-scroll")
        .flex_1()
        .min_h(px(0.0))
        .overflow_y_scroll()
        .flex()
        .flex_col()
        .gap(t.space.md)
        .child(summary_card(r, lang, c, t))
        .when(r.has_duplicates(), |d| d.child(dup_banner(r, lang, c, t)))
        .child(metrics_card(r, lang, c, t))
        .child(entropy_card(r, lang, c, t))
        .child(fips_card(r, lang, c, t))
}

/// 顶部总体评级卡:大评级徽标 + 三个头条指标。
fn summary_card(r: &SequencerReport, lang: Lang, c: ThemeColors, t: Tokens) -> impl IntoElement {
    let qc = quality_color(r.quality, c);
    let unique_color = if r.has_duplicates() { c.danger } else { c.success };

    let quality_block = div()
        .flex()
        .flex_col()
        .gap(t.space.xs)
        .child(section_label(lang.t("Overall quality"), c, t))
        .child(
            div()
                .flex()
                .items_center()
                .justify_center()
                .px(t.space.md)
                .py(px(6.0))
                .rounded(t.radius.md)
                .bg(qc.opacity(0.16))
                .border_1()
                .border_color(qc.opacity(0.4))
                .text_size(t.font_size.lg)
                .text_color(qc)
                .font_weight(FontWeight::SEMIBOLD)
                .child(lang.t(r.quality.label())),
        );

    div()
        .flex()
        .items_center()
        .gap(t.space.xl)
        .flex_shrink_0()
        .p(t.space.md)
        .rounded(t.radius.lg)
        .bg(c.glass)
        .border_1()
        .border_color(c.glass_border)
        .child(quality_block)
        .child(metric(
            lang.t("Char entropy"),
            format!("{:.1} bit", r.char_entropy_bits),
            c.primary,
            c,
            t,
        ))
        .child(metric(
            lang.t("Samples"),
            r.sample_count.to_string(),
            c.text,
            c,
            t,
        ))
        .child(metric(
            lang.t("Unique"),
            r.unique_count.to_string(),
            unique_color,
            c,
            t,
        ))
}

/// 一个纵排指标(小标题 + 大数值,等宽字体)。
fn metric(
    label: SharedString,
    value: impl Into<SharedString>,
    color: Hsla,
    c: ThemeColors,
    t: Tokens,
) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap(px(2.0))
        .child(
            div()
                .text_size(t.font_size.xs)
                .text_color(c.text_subtle)
                .child(label),
        )
        .child(
            div()
                .font_family(MONO)
                .text_size(t.font_size.lg)
                .text_color(color)
                .font_weight(FontWeight::SEMIBOLD)
                .child(value.into()),
        )
}

/// 重复样本告警条(红)。出现重复 = 令牌可碰撞 / 可预测,直接判 Poor。
fn dup_banner(r: &SequencerReport, lang: Lang, c: ThemeColors, t: Tokens) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .gap(t.space.sm)
        .flex_shrink_0()
        .p(t.space.sm)
        .rounded(t.radius.md)
        .bg(c.danger.opacity(0.12))
        .border_1()
        .border_color(c.danger.opacity(0.4))
        .child(Icon::new(IconName::Zap).size(px(15.0)).color(c.danger))
        .child(
            div()
                .text_size(t.font_size.sm)
                .text_color(c.danger)
                .child(format!(
                    "{}: {} / {}",
                    lang.t("Duplicate samples found"),
                    r.unique_count,
                    r.sample_count
                )),
        )
}

/// 关键指标卡(字符熵 / 比特熵 / 平均 / 置 1 比例 / 长度区间)。
fn metrics_card(r: &SequencerReport, lang: Lang, c: ThemeColors, t: Tokens) -> impl IntoElement {
    let len_range = if r.min_len == r.max_len {
        r.min_len.to_string()
    } else {
        format!("{} – {}", r.min_len, r.max_len)
    };
    card(c, t)
        .child(section_label(lang.t("Metrics"), c, t))
        .child(
            DetailRow::new(IconName::Hash, lang.t("Char entropy"))
                .value(format!("{:.2} bit", r.char_entropy_bits)),
        )
        .child(
            DetailRow::new(IconName::Hash, lang.t("Bit entropy"))
                .value(format!("{:.2} bit", r.bit_entropy_bits)),
        )
        .child(
            DetailRow::new(IconName::Sort, lang.t("Mean bits/char"))
                .value(format!("{:.2} bit", r.mean_char_bits)),
        )
        .child(
            DetailRow::new(IconName::Tag, lang.t("Ones ratio"))
                .value(format!("{:.1}%", r.one_ratio * 100.0)),
        )
        .child(DetailRow::new(IconName::Layers, lang.t("Length")).value(len_range))
}

/// 逐字符熵条形图卡(每个字符位置一条横向条,越长越随机)。
fn entropy_card(r: &SequencerReport, lang: Lang, c: ThemeColors, t: Tokens) -> impl IntoElement {
    let shown = r.char_positions.len().min(MAX_BARS);
    let mut bars: Vec<AnyElement> = Vec::with_capacity(shown);
    for pe in r.char_positions.iter().take(MAX_BARS) {
        bars.push(entropy_bar_row(pe, c, t).into_any_element());
    }
    let mut col = card(c, t).child(
        div()
            .flex()
            .items_center()
            .justify_between()
            .child(section_label(lang.t("Per-character entropy"), c, t))
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(lang.t("bit / position (max 8)")),
            ),
    );
    col = col.children(bars);
    if r.char_positions.len() > MAX_BARS {
        col = col.child(
            div()
                .text_size(t.font_size.xs)
                .text_color(c.text_subtle)
                .child(format!(
                    "… +{} {}",
                    r.char_positions.len() - MAX_BARS,
                    lang.t("more positions")
                )),
        );
    }
    col
}

/// 单个字符位置的熵条:位置号 + 进度条 + 数值。
fn entropy_bar_row(pe: &PositionEntropy, c: ThemeColors, t: Tokens) -> impl IntoElement {
    let ratio = (pe.bits / 8.0).clamp(0.0, 1.0) as f32;
    let track = 220.0_f32;
    let col = bar_color(pe.bits, c);
    div()
        .flex()
        .items_center()
        .gap(t.space.sm)
        .child(
            div()
                .w(px(28.0))
                .flex_shrink_0()
                .font_family(MONO)
                .text_size(t.font_size.xs)
                .text_color(c.text_subtle)
                .child(pe.index.to_string()),
        )
        .child(
            div()
                .w(px(track))
                .h(px(9.0))
                .flex_shrink_0()
                .rounded(t.radius.full)
                .bg(c.background)
                .border_1()
                .border_color(c.glass_border)
                .overflow_hidden()
                .child(div().h_full().w(px(track * ratio)).bg(col)),
        )
        .child(
            div()
                .w(px(50.0))
                .flex_shrink_0()
                .font_family(MONO)
                .text_size(t.font_size.xs)
                .text_color(c.text_muted)
                .child(format!("{:.2}", pe.bits)),
        )
}

/// FIPS 140-2 自检卡:够 20000 bit 列四项结果,否则提示样本不足。
fn fips_card(r: &SequencerReport, lang: Lang, c: ThemeColors, t: Tokens) -> impl IntoElement {
    let mut col = card(c, t).child(section_label("FIPS 140-2", c, t));
    if r.fips.evaluated {
        for test in &r.fips.tests {
            col = col.child(fips_row(test, lang, c, t));
        }
        col = col.child(
            div()
                .text_size(t.font_size.xs)
                .text_color(c.text_subtle)
                .child(lang.t(
                    "FIPS inspects the raw byte stream; text tokens (base62/hex) fail Monobit by the constant high bit — judge by character entropy.",
                )),
        );
    } else {
        col = col.child(
            div()
                .text_size(t.font_size.sm)
                .text_color(c.text_subtle)
                .child(format!(
                    "{} ({} bit)",
                    lang.t("FIPS needs ≥20000 bit; collect more samples"),
                    r.fips.total_bits
                )),
        );
    }
    col
}

/// 一行 FIPS 测试结果:名称 + 数值证据 + PASS/FAIL 徽标。
fn fips_row(test: &scry_seq::FipsTest, lang: Lang, c: ThemeColors, t: Tokens) -> impl IntoElement {
    let (label, color, icon) = if test.passed {
        ("PASS", c.success, IconName::Check)
    } else {
        ("FAIL", c.danger, IconName::Zap)
    };
    let _ = t;
    DetailRow::new(icon, lang.t(test.name))
        .value(test.detail.clone())
        .trailing(Badge::new(label, color))
}

/// 报告内的次级卡片容器(玻璃底,在 surface 面板上突出一层)。
fn card(c: ThemeColors, t: Tokens) -> Div {
    div()
        .flex()
        .flex_col()
        .gap(t.space.xs)
        .flex_shrink_0()
        .p(t.space.sm)
        .rounded(t.radius.lg)
        .bg(c.glass)
        .border_1()
        .border_color(c.glass_border)
}

/// 面板小标题(标题 + 弱化说明)。
fn panel_header(
    title: SharedString,
    hint: SharedString,
    c: ThemeColors,
    t: Tokens,
) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .gap(t.space.sm)
        .flex_shrink_0()
        .child(
            div()
                .text_size(t.font_size.sm)
                .text_color(c.text)
                .font_weight(FontWeight::SEMIBOLD)
                .child(title),
        )
        .child(
            div()
                .text_size(t.font_size.xs)
                .text_color(c.text_subtle)
                .child(hint),
        )
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_tokens_shape_and_quality() {
        let s = sample_tokens(SAMPLE_N, SAMPLE_LEN, SAMPLE_SEED);
        let toks = scry_seq::parse_tokens(&s);
        assert_eq!(toks.len(), SAMPLE_N);
        assert!(toks.iter().all(|x| x.len() == SAMPLE_LEN));
        let r = scry_seq::analyze(&toks);
        // 高熵 base62 样例:无重复、字符熵高、字节数够跑 FIPS。
        assert!(!r.has_duplicates());
        assert!(r.char_entropy_bits > 80.0, "got {}", r.char_entropy_bits);
        assert!(r.quality >= Quality::Strong);
        assert!(r.fips.evaluated);
    }

    #[test]
    fn sample_tokens_deterministic() {
        assert_eq!(sample_tokens(10, 8, 42), sample_tokens(10, 8, 42));
        assert_ne!(sample_tokens(10, 8, 42), sample_tokens(10, 8, 43));
    }

    #[test]
    fn sample_tokens_line_count() {
        let s = sample_tokens(5, 12, 7);
        assert_eq!(s.lines().count(), 5);
        assert!(s.lines().all(|l| l.len() == 12));
    }
}
