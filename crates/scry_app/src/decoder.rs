//! Decoder 页(对标 Burp Decoder):把左侧输入按所选变换(URL / HTML / Base64 / Hex 编解码、
//! MD5/SHA 哈希)转换到右侧输出;「智能解码」自动识别一层编码;「输出转输入」可手动链式多层。
//!
//! 变换内核全在 [`scry_codec`](../../scry_codec)(纯函数、可单测);本文件只做 UI 与状态搬运。

use std::hash::{Hash, Hasher};

use mage_ui::gpui::{ClipboardItem, MouseButton};
use mage_ui::prelude::*;
use scry_codec::{Category, Transform};

use crate::logger::LogLevel;
use crate::state::ScryApp;
use crate::widgets::{divider, section_label};

impl ScryApp {
    /// 对输入应用一个变换,结果写入输出框;解码失败把原因写到状态提示。
    pub fn apply_decoder(&mut self, tf: Transform, cx: &mut Context<Self>) {
        let input = self.dec_input.read(cx).text().to_string();
        let key = self.dec_key.read(cx).text().to_string();
        let iv = self.dec_iv.read(cx).text().to_string();
        match tf.apply_with(&input, &key, &iv) {
            Ok(out) => {
                let n = out.len();
                self.dec_output.update(cx, |st, cx| st.set_text(out, cx));
                self.dec_err = false;
                self.dec_note = Some(format!(
                    "{} · {} {}",
                    self.lang.t(tf.label()),
                    n,
                    self.lang.t("bytes")
                ));
            }
            Err(e) => {
                self.dec_err = true;
                self.dec_note = Some(format!("{}: {}", self.lang.t(tf.label()), e));
                self.push_log(
                    LogLevel::Warning,
                    "decoder",
                    format!("{}失败:{}", self.lang.t(tf.label()), e),
                );
            }
        }
        cx.notify();
    }

    /// 智能解码:自动识别并解开一层编码。
    pub fn smart_decode(&mut self, cx: &mut Context<Self>) {
        let input = self.dec_input.read(cx).text().to_string();
        match scry_codec::smart_decode(&input) {
            Some((tf, out)) => {
                self.dec_output.update(cx, |st, cx| st.set_text(out, cx));
                self.dec_err = false;
                self.dec_note = Some(format!(
                    "{} → {}",
                    self.lang.t("Smart decode"),
                    self.lang.t(tf.label())
                ));
            }
            None => {
                self.dec_err = false;
                self.dec_output.update(cx, |st, cx| st.set_text(String::new(), cx));
                self.dec_note = Some(self.lang.t("Could not detect an encoding").to_string());
            }
        }
        cx.notify();
    }

    /// 把输出搬回输入(便于手动链式多层编解码)。
    pub fn promote_decoder_output(&mut self, cx: &mut Context<Self>) {
        let out = self.dec_output.read(cx).text().to_string();
        if out.is_empty() {
            return;
        }
        self.dec_input.update(cx, |st, cx| st.set_text(out, cx));
        self.dec_output.update(cx, |st, cx| st.set_text(String::new(), cx));
        self.dec_note = Some(self.lang.t("Output promoted to input").to_string());
        self.dec_err = false;
        cx.notify();
    }

    /// 复制输出到剪贴板。
    pub fn copy_decoder_output(&mut self, cx: &mut Context<Self>) {
        let out = self.dec_output.read(cx).text().to_string();
        if out.is_empty() {
            return;
        }
        cx.write_to_clipboard(ClipboardItem::new_string(out));
        let msg = self.lang.t("Copied to clipboard").to_string();
        self.show_toast(msg, cx);
    }

    /// 清空输入与输出。
    pub fn clear_decoder(&mut self, cx: &mut Context<Self>) {
        self.dec_input.update(cx, |st, cx| st.set_text(String::new(), cx));
        self.dec_output.update(cx, |st, cx| st.set_text(String::new(), cx));
        self.dec_note = None;
        self.dec_err = false;
        cx.notify();
    }

    /// 把解码输出同步进只读**可选中高亮**查看器(JSON 美化 + 多色;签名不变则跳过)。
    /// 由 `render`(Decoder 页可见时)调用。
    pub fn sync_decoder_view(&mut self, cx: &mut Context<Self>) {
        let c = cx.theme().colors;
        let dark = cx.theme().mode.is_dark();
        let raw = self.dec_output.read(cx).text().to_string();
        let mut h = std::collections::hash_map::DefaultHasher::new();
        dark.hash(&mut h);
        raw.hash(&mut h);
        let sig = h.finish();
        if self.dec_view_sig == sig {
            return;
        }
        let display = crate::highlight::code_text(&raw);
        let hl = crate::highlight::body_text_highlights(&display, c);
        let input = self.dec_view.clone();
        input.update(cx, |s, cx| {
            s.set_text(display, cx);
            s.set_highlights(hl, cx);
        });
        self.dec_view_sig = sig;
    }

    /// 单个变换按钮。
    fn dec_btn(&self, tf: Transform, cx: &mut Context<Self>) -> impl IntoElement {
        let id = SharedString::from(format!("dec-{}", tf.label()));
        Button::new(id, self.lang.t(tf.label()))
            .variant(ButtonVariant::Ghost)
            .size(ButtonSize::Sm)
            .on_click(cx.listener(move |this, _e, _w, cx| this.apply_decoder(tf, cx)))
    }

    /// Decoder 页主体。
    pub fn decoder_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let lang = self.lang;

        // ── 顶部操作条:智能解码 / 输出转输入 / 清空 + 状态提示 ──
        let actions = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .child(
                Button::new("dec-smart", lang.t("Smart decode"))
                    .variant(ButtonVariant::Primary)
                    .size(ButtonSize::Sm)
                    .icon(IconName::Search)
                    .on_click(cx.listener(|this, _e, _w, cx| this.smart_decode(cx))),
            )
            .child(
                Button::new("dec-promote", lang.t("Output → input"))
                    .variant(ButtonVariant::Ghost)
                    .size(ButtonSize::Sm)
                    .icon(IconName::Refresh)
                    .on_click(cx.listener(|this, _e, _w, cx| this.promote_decoder_output(cx))),
            )
            .child(
                Button::new("dec-clear", lang.t("Clear"))
                    .variant(ButtonVariant::Ghost)
                    .size(ButtonSize::Sm)
                    .icon(IconName::Trash)
                    .on_click(cx.listener(|this, _e, _w, cx| this.clear_decoder(cx))),
            );

        let note = self.dec_note.clone().map(|msg| {
            let col = if self.dec_err { c.danger } else { c.text_muted };
            div()
                .text_size(t.font_size.xs)
                .text_color(col)
                .child(msg)
        });

        let toolbar = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.md)
            .flex_shrink_0()
            .child(actions)
            .children(note);

        // ── 变换按钮条:编解码 / 加解密 / 哈希 三组 ──
        let mut codec_btns: Vec<AnyElement> = Vec::new();
        let mut cipher_btns: Vec<AnyElement> = Vec::new();
        let mut hash_btns: Vec<AnyElement> = Vec::new();
        for &tf in Transform::ALL.iter() {
            let el = self.dec_btn(tf, cx).into_any_element();
            match tf.category() {
                Category::Codec => codec_btns.push(el),
                Category::Cipher => cipher_btns.push(el),
                Category::Hash => hash_btns.push(el),
            }
        }
        // 密钥 / IV 输入行(供加解密 / HMAC 用;非密码变换忽略)。
        let key_row = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .child(
                div()
                    .flex_shrink_0()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(lang.t("Key")),
            )
            .child(div().flex_1().min_w(px(0.0)).child(self.dec_key.clone()))
            .child(
                div()
                    .flex_shrink_0()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(lang.t("IV")),
            )
            .child(div().flex_1().min_w(px(0.0)).child(self.dec_iv.clone()));

        let transforms = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_shrink_0()
            .p(t.space.sm)
            .rounded(t.radius.lg)
            .bg(c.glass)
            .border_1()
            .border_color(c.glass_border)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(t.space.xs)
                    .child(section_label(lang.t("Encode / Decode"), c, t))
                    .child(div().flex().flex_wrap().gap(t.space.sm).children(codec_btns)),
            )
            .child(divider(c))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(t.space.xs)
                    .child(section_label(lang.t("Encrypt / Decrypt (key)"), c, t))
                    .child(key_row)
                    .child(div().flex().flex_wrap().gap(t.space.sm).children(cipher_btns)),
            )
            .child(divider(c))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(t.space.xs)
                    .child(section_label(lang.t("Hash / MAC (one-way)"), c, t))
                    .child(div().flex().flex_wrap().gap(t.space.sm).children(hash_btns)),
            );

        // ── 左:输入区 ──
        let in_len = self.dec_input.read(cx).text().chars().count();
        let left = panel(c, t)
            .child(panel_header(
                lang.t("Input"),
                format!("{} {}", in_len, lang.t("chars")).into(),
                c,
                t,
            ))
            .child(divider(c))
            .child(
                div()
                    .id("dec-in-scroll")
                    .flex_1()
                    .min_h(px(0.0))
                    .overflow_y_scroll()
                    .child(self.dec_input.clone()),
            );

        // ── 右:输出区(只读**可选中高亮**视图;JSON 自动美化着色 + 选中复制)──
        let out_text = self.dec_output.read(cx).text().to_string();
        let out_len = out_text.chars().count();
        let out_body: AnyElement = if out_text.is_empty() {
            div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .child(
                    div()
                        .text_size(t.font_size.sm)
                        .text_color(c.text_subtle)
                        .child(lang.t("Result appears here")),
                )
                .into_any_element()
        } else {
            self.dec_view.clone().into_any_element()
        };
        let right = panel(c, t)
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .flex_shrink_0()
                    .child(panel_header(
                        lang.t("Output"),
                        format!("{} {}", out_len, lang.t("chars")).into(),
                        c,
                        t,
                    ))
                    .child(
                        Button::new("dec-copy", lang.t("Copy"))
                            .variant(ButtonVariant::Ghost)
                            .size(ButtonSize::Sm)
                            .icon(IconName::Copy)
                            .on_click(cx.listener(|this, _e, _w, cx| this.copy_decoder_output(cx))),
                    ),
            )
            .child(divider(c))
            .child(
                div()
                    .id("dec-out-scroll")
                    .flex_1()
                    .min_h(px(0.0))
                    .overflow_y_scroll()
                    .on_mouse_down(
                        MouseButton::Right,
                        cx.listener(|this, _e, _w, cx| {
                            let inp = this.dec_view.clone();
                            this.copy_from_input(inp, cx);
                        }),
                    )
                    .child(out_body),
            );

        div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .gap(t.space.md)
            .p(t.space.lg)
            .child(toolbar)
            .child(transforms)
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

/// 输入 / 输出面板容器(surface 底 + 边框 + 纵向填充)。
fn panel(c: ThemeColors, t: Tokens) -> mage_ui::gpui::Div {
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
}

/// 面板小标题(标题 + 弱化计数说明)。
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
