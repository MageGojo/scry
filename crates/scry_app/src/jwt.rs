//! JWT 页:**JWT 攻击套件**(对标 Burp **JWT Editor** / jwt_tool)。
//!
//! 把 [`scry_jwt`] 纯函数内核提到 GUI:解码任意 JWT(header / payload / 签名 + `alg`),并一键生成
//! 各类攻击令牌——`alg:none` 绕过、HS256 弱密钥伪造、`kid` 头注入、字典爆破弱密钥。生成的令牌
//! 只读可选中,复制后粘回 Repeater / Compose 重放。
//!
//! 全部是**本地纯计算**(无网络、瞬时完成),因此不需要后台 runner / 流式回填:点一下即出结果。
//! 代理右键「发送到 JWT」会从请求(`Authorization: Bearer` / Cookie / body)自动提取首个 JWT 填入。

use mage_ui::gpui::ClipboardItem;
use mage_ui::prelude::*;
use scry_core::HttpFlow;

use crate::state::ScryApp;
use crate::widgets::{divider, section_label};

impl ScryApp {
    /// 代理右键「发送到 JWT」:从一条流里提取首个 JWT 填进输入框,并顺带解出 payload 便于改造。
    pub fn fill_jwt_from_flow(&mut self, flow: &HttpFlow, cx: &mut Context<Self>) {
        let token = extract_jwt_from_flow(flow).unwrap_or_default();
        let found = !token.is_empty();
        self.jwt_input.update(cx, |s, cx| s.set_text(token.clone(), cx));
        self.jwt_out.update(cx, |s, cx| s.set_text(String::new(), cx));
        self.jwt_crack = None;
        if found {
            if let Ok(d) = scry_jwt::decode(&token) {
                self.jwt_payload.update(cx, |s, cx| s.set_text(d.payload, cx));
            }
            self.jwt_msg = Some(self.lang.t("JWT extracted from request").to_string());
        } else {
            self.jwt_msg = Some(self.lang.t("No JWT found in this request").to_string());
        }
        cx.notify();
    }

    /// 「载入」:把当前令牌解出的 payload 灌进可编辑框(便于改 claim 后重签)。
    fn jwt_load_payload(&mut self, cx: &mut Context<Self>) {
        let token = self.jwt_input.read(cx).text().to_string();
        match scry_jwt::decode(&token) {
            Ok(d) => {
                self.jwt_payload.update(cx, |s, cx| s.set_text(d.payload, cx));
                self.jwt_msg = Some(format!("{} alg={}", self.lang.t("Loaded payload ·"), d.alg));
            }
            Err(e) => self.jwt_msg = Some(e),
        }
        cx.notify();
    }

    /// 设置生成结果令牌 + 状态文案。
    fn jwt_set_out(&mut self, token: String, note: &str, cx: &mut Context<Self>) {
        self.jwt_out.update(cx, |s, cx| s.set_text(token, cx));
        self.jwt_msg = Some(note.to_string());
        cx.notify();
    }

    /// alg:none 伪造(空签名绕过)。
    fn jwt_forge_none(&mut self, cx: &mut Context<Self>) {
        let payload = self.jwt_payload.read(cx).text().to_string();
        let tok = scry_jwt::forge_none(&payload);
        let note = self.lang.t("Forged alg:none token").to_string();
        self.jwt_set_out(tok, &note, cx);
    }

    /// HS256 弱密钥伪造(用 secret 签当前 payload)。
    fn jwt_sign_hs256(&mut self, cx: &mut Context<Self>) {
        let payload = self.jwt_payload.read(cx).text().to_string();
        let secret = self.jwt_secret.read(cx).text().to_string();
        let tok = scry_jwt::sign_hs256(&secret, &payload);
        let note = self.lang.t("Signed HS256 token").to_string();
        self.jwt_set_out(tok, &note, cx);
    }

    /// kid 注入(自定义 kid 头 + HS256 签)。
    fn jwt_forge_kid(&mut self, cx: &mut Context<Self>) {
        let payload = self.jwt_payload.read(cx).text().to_string();
        let secret = self.jwt_secret.read(cx).text().to_string();
        let kid = self.jwt_kid.read(cx).text().to_string();
        if kid.trim().is_empty() {
            self.jwt_msg = Some(self.lang.t("Enter a kid value first").to_string());
            cx.notify();
            return;
        }
        let tok = scry_jwt::forge_kid(&secret, &payload, &kid);
        let note = self.lang.t("Forged kid-injection token").to_string();
        self.jwt_set_out(tok, &note, cx);
    }

    /// 字典爆破弱密钥(内置弱密钥表 + secret 框里的额外候选)。
    fn jwt_crack_secret(&mut self, cx: &mut Context<Self>) {
        let token = self.jwt_input.read(cx).text().to_string();
        let extra = self.jwt_secret.read(cx).text().to_string();
        let d = match scry_jwt::decode(&token) {
            Ok(d) => d,
            Err(e) => {
                self.jwt_msg = Some(e);
                cx.notify();
                return;
            }
        };
        if !d.alg.eq_ignore_ascii_case("HS256") {
            self.jwt_crack = None;
            self.jwt_msg = Some(format!("{} (alg={})", self.lang.t("Brute force only supports HS256"), d.alg));
            cx.notify();
            return;
        }
        // 内置表 + 用户在 secret 框填的额外候选。
        let mut cands: Vec<String> = scry_jwt::COMMON_SECRETS.iter().map(|s| s.to_string()).collect();
        if !extra.is_empty() && !cands.iter().any(|c| c == &extra) {
            cands.push(extra);
        }
        match scry_jwt::crack_hs256(&token, &cands) {
            Some(secret) => {
                let shown = if secret.is_empty() {
                    self.lang.t("(empty secret)").to_string()
                } else {
                    secret.clone()
                };
                self.jwt_crack = Some(format!("{} {}", self.lang.t("Weak secret cracked:"), shown));
                // 命中即把密钥回填到 secret 框,方便直接重签伪造令牌。
                self.jwt_secret.update(cx, |s, cx| s.set_text(secret, cx));
            }
            None => {
                self.jwt_crack = Some(format!(
                    "{} ({} candidates)",
                    self.lang.t("No weak secret found"),
                    cands.len()
                ));
            }
        }
        cx.notify();
    }

    /// 复制结果令牌到剪贴板。
    fn jwt_copy_out(&mut self, cx: &mut Context<Self>) {
        let token = self.jwt_out.read(cx).text().to_string();
        if !token.is_empty() {
            cx.write_to_clipboard(ClipboardItem::new_string(token));
            self.show_toast(self.lang.t("Copied to clipboard").to_string(), cx);
        }
    }

    /// JWT 页主体。
    pub fn jwt_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        // 实时解码当前令牌(纯计算,廉价)。
        let token = self.jwt_input.read(cx).text().to_string();
        let decoded = if token.trim().is_empty() {
            None
        } else {
            Some(scry_jwt::decode(&token))
        };

        let toolbar = div()
            .flex()
            .items_center()
            .gap(t.space.md)
            .flex_shrink_0()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .child(Icon::new(IconName::Shield).size(px(15.0)).color(c.text_subtle))
                    .child(
                        div()
                            .text_size(t.font_size.sm)
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(c.text)
                            .child(self.lang.t("JWT attack toolkit")),
                    ),
            )
            .child(
                Button::new("jwt-load", self.lang.t("Load payload"))
                    .ghost()
                    .size(ButtonSize::Sm)
                    .icon(IconName::Download)
                    .on_click(cx.listener(|this, _e, _w, cx| this.jwt_load_payload(cx))),
            );

        let hint = div()
            .flex_shrink_0()
            .text_size(t.font_size.xs)
            .text_color(c.text_subtle)
            .child(self.lang.t(
                "Decode any JWT and forge attack tokens (alg:none / weak HS256 / kid injection / brute force). Use only on authorized targets.",
            ));

        // 左:令牌输入 + 实时解码视图。
        let left = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0))
            .child(section_label(self.lang.t("Token"), c, t))
            .child(self.jwt_input.clone())
            .child(section_label(self.lang.t("Decoded"), c, t))
            .child(self.jwt_decoded_view(decoded.as_ref(), c, t));

        // 右:伪造配置 + 攻击按钮 + 结果。
        let forge_inputs = div()
            .flex()
            .flex_col()
            .gap(px(4.0))
            .flex_shrink_0()
            .child(section_label(self.lang.t("Forge"), c, t))
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("Payload (editable JSON)")),
            )
            .child(self.jwt_payload.clone())
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("HS256 secret")),
            )
            .child(self.jwt_secret.clone())
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("kid (for kid injection)")),
            )
            .child(self.jwt_kid.clone());

        let buttons = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(6.0))
            .flex_shrink_0()
            .child(
                Button::new("jwt-none", self.lang.t("alg:none"))
                    .size(ButtonSize::Sm)
                    .variant(ButtonVariant::Danger)
                    .on_click(cx.listener(|this, _e, _w, cx| this.jwt_forge_none(cx))),
            )
            .child(
                Button::new("jwt-hs256", self.lang.t("Sign HS256"))
                    .size(ButtonSize::Sm)
                    .on_click(cx.listener(|this, _e, _w, cx| this.jwt_sign_hs256(cx))),
            )
            .child(
                Button::new("jwt-kid", self.lang.t("kid injection"))
                    .size(ButtonSize::Sm)
                    .on_click(cx.listener(|this, _e, _w, cx| this.jwt_forge_kid(cx))),
            )
            .child(
                Button::new("jwt-crack", self.lang.t("Brute force secret"))
                    .size(ButtonSize::Sm)
                    .variant(ButtonVariant::Danger)
                    .icon(IconName::Zap)
                    .on_click(cx.listener(|this, _e, _w, cx| this.jwt_crack_secret(cx))),
            );

        let result_header = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.sm)
            .flex_shrink_0()
            .child(section_label(self.lang.t("Result token"), c, t))
            .child(
                Button::new("jwt-copy", self.lang.t("Copy"))
                    .ghost()
                    .size(ButtonSize::Sm)
                    .icon(IconName::Copy)
                    .on_click(cx.listener(|this, _e, _w, cx| this.jwt_copy_out(cx))),
            );

        let mut right = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0))
            .child(forge_inputs)
            .child(buttons)
            .child(result_header)
            .child(self.jwt_out.clone());

        if let Some(crack) = &self.jwt_crack {
            let hit = crack.contains(&*self.lang.t("Weak secret cracked:"));
            right = right.child(
                div()
                    .flex_shrink_0()
                    .p(t.space.sm)
                    .rounded(t.radius.md)
                    .bg(c.surface)
                    .border_1()
                    .border_color(if hit { c.danger } else { c.border })
                    .font_family(crate::model::MONO)
                    .text_size(t.font_size.xs)
                    .text_color(if hit { c.danger } else { c.text_muted })
                    .child(crack.clone()),
            );
        }
        if let Some(msg) = &self.jwt_msg {
            right = right.child(
                div()
                    .flex_shrink_0()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(msg.clone()),
            );
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

    /// 解码视图:alg 徽标 + header / payload / 签名三段(等宽展示)。
    fn jwt_decoded_view(
        &self,
        decoded: Option<&Result<scry_jwt::DecodedJwt, String>>,
        c: ThemeColors,
        t: Tokens,
    ) -> AnyElement {
        let d = match decoded {
            None => {
                return EmptyState::new(self.lang.t("Paste a JWT to decode"))
                    .icon(IconName::Shield)
                    .into_any_element();
            }
            Some(Err(e)) => {
                return div()
                    .flex_1()
                    .p(t.space.sm)
                    .font_family(crate::model::MONO)
                    .text_size(t.font_size.xs)
                    .text_color(c.danger)
                    .child(e.clone())
                    .into_any_element();
            }
            Some(Ok(d)) => d,
        };

        // alg:none / 空签名 = 高危红;其余蓝。
        let alg_danger = d.alg.eq_ignore_ascii_case("none") || d.signature.is_empty();
        let alg_color = if alg_danger { c.danger } else { c.primary };

        div()
            .id("jwt-decoded")
            .flex_1()
            .min_h(px(0.0))
            .overflow_y_scroll()
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
                    .child(Badge::new(
                        format!("alg: {}", if d.alg.is_empty() { "?" } else { &d.alg }),
                        alg_color,
                    ))
                    .when(alg_danger, |el| {
                        el.child(
                            div()
                                .text_size(t.font_size.xs)
                                .text_color(c.danger)
                                .child(self.lang.t("unsigned / none — likely forgeable")),
                        )
                    }),
            )
            .child(jwt_part(self.lang.t("Header"), &d.header, c, t))
            .child(jwt_part(self.lang.t("Payload"), &d.payload, c, t))
            .child(jwt_part(
                self.lang.t("Signature (raw, not verified)"),
                &d.signature,
                c,
                t,
            ))
            .into_any_element()
    }
}

/// 解码视图里的一段(标题 + 等宽内容块)。
fn jwt_part(label: SharedString, content: &str, c: ThemeColors, t: Tokens) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap(px(2.0))
        .child(
            div()
                .text_size(t.font_size.xs)
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(c.text_subtle)
                .child(label),
        )
        .child(
            div()
                .font_family(crate::model::MONO)
                .text_size(t.font_size.xs)
                .text_color(c.text_muted)
                .child(if content.is_empty() {
                    "(empty)".to_string()
                } else {
                    content.to_string()
                }),
        )
}

/// 从一条流里提取首个 JWT(扫请求头值 + Cookie + body;找形如 `eyJ….….…` 的三段 base64url 串)。
fn extract_jwt_from_flow(flow: &HttpFlow) -> Option<String> {
    // 候选文本:各请求头值 + 请求体。
    let mut haystacks: Vec<String> = flow.req_headers.iter().map(|(_, v)| v.clone()).collect();
    haystacks.push(String::from_utf8_lossy(&flow.req_body).into_owned());
    for h in &haystacks {
        if let Some(tok) = find_jwt(h) {
            return Some(tok);
        }
    }
    None
}

/// 在一段文本里找首个 JWT 样式的子串:`eyJ` 开头、至少两个 `.` 分段、各段为 base64url 字符。
fn find_jwt(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let is_tok = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.';
    let mut i = 0;
    while i < bytes.len() {
        if !is_tok(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_tok(bytes[i]) {
            i += 1;
        }
        let cand = &text[start..i];
        // header 段 base64url("{"…) 必以 eyJ 开头;需 >=2 个点(允许末尾空签名)。
        if cand.starts_with("eyJ") && cand.matches('.').count() >= 2 {
            return Some(cand.trim_end_matches('.').to_string() + if cand.ends_with('.') { "." } else { "" });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use scry_core::HttpFlow;

    #[test]
    fn extracts_bearer_token_from_header() {
        let jwt = scry_jwt::sign_hs256("k", r#"{"sub":"1"}"#);
        let f = HttpFlow::request(
            "GET",
            "https",
            "h",
            443,
            "/api",
            vec![("Authorization".into(), format!("Bearer {jwt}"))],
            vec![],
        );
        assert_eq!(extract_jwt_from_flow(&f).as_deref(), Some(jwt.as_str()));
    }

    #[test]
    fn finds_none_token_with_trailing_dot() {
        let tok = scry_jwt::forge_none(r#"{"a":1}"#);
        let wrapped = format!("session={tok}; path=/");
        let got = find_jwt(&wrapped).unwrap();
        assert!(got.starts_with("eyJ"));
        assert!(got.ends_with('.'));
    }

    #[test]
    fn no_jwt_returns_none() {
        let f = HttpFlow::request("GET", "https", "h", 443, "/", vec![], vec![]);
        assert!(extract_jwt_from_flow(&f).is_none());
    }
}
