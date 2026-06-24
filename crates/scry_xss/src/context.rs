//! HTML 上下文识别:给定响应 HTML 与反射标记的字节偏移,判断该处属于哪种注入上下文。
//!
//! 这不是完整 HTML 解析器,而是 dalfox 式的**轻量状态扫描**(从头扫到偏移点,跟踪
//! 注释 / `<script>` / 标签内 / 属性引号 状态),对决定 XSS 逃逸方式足够。

/// 反射点所处的 HTML 上下文。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HtmlContext {
    /// 标签之间的纯文本(`<div>HERE</div>`)。
    HtmlText,
    /// 双引号属性值内(`<input value="HERE">`)。
    AttrDouble,
    /// 单引号属性值内(`<input value='HERE'>`)。
    AttrSingle,
    /// 无引号属性值 / 标签内属性区(`<input value=HERE>`)。
    AttrUnquoted,
    /// URL 型属性值内(`href`/`src`/`action`/… —— 可用 `javascript:` 伪协议),携带定界引号(无引号 = `None`)。
    UrlAttribute(Option<char>),
    /// `<script>` 内的 JS 字符串中(携带定界引号 `"` / `'` / 反引号)。
    ScriptString(char),
    /// `<script>` 内、字符串之外的裸 JS。
    ScriptRaw,
    /// HTML 注释内(`<!-- HERE -->`)。
    Comment,
}

/// 可放 `javascript:` 伪协议的 URL 型属性(小写)。
const URL_ATTRS: &[&str] = &[
    "href",
    "src",
    "action",
    "formaction",
    "xlink:href",
    "poster",
    "data",
    "background",
    "cite",
    "longdesc",
];

impl HtmlContext {
    /// 英文标签(界面 `lang.t()` 翻译)。
    pub fn label(self) -> &'static str {
        match self {
            HtmlContext::HtmlText => "HTML text",
            HtmlContext::AttrDouble => "Attribute (double-quoted)",
            HtmlContext::AttrSingle => "Attribute (single-quoted)",
            HtmlContext::AttrUnquoted => "Attribute (unquoted)",
            HtmlContext::UrlAttribute(_) => "URL attribute",
            HtmlContext::ScriptString(_) => "JavaScript string",
            HtmlContext::ScriptRaw => "JavaScript",
            HtmlContext::Comment => "HTML comment",
        }
    }
}

/// 判断 `html` 中字节偏移 `offset` 处的注入上下文。
pub fn detect_context(html: &str, offset: usize) -> HtmlContext {
    let b = html.as_bytes();
    let lower = html.to_ascii_lowercase();
    let lb = lower.as_bytes();
    let n = offset.min(b.len());

    let mut in_comment = false;
    let mut in_script = false;
    let mut script_str: Option<u8> = None;
    let mut in_tag = false;
    let mut pending_script = false; // 进入 <script 标签,等 `>` 后切到脚本体
    let mut attr_quote: Option<u8> = None;
    let mut after_eq = false; // 刚见 `=`,正在属性值里(引号或无引号)
    let mut attr_name = String::new(); // 正在累积的属性名
    let mut active_attr: Option<String> = None; // 当前所处属性值对应的属性名(小写)

    let mut i = 0;
    while i < n {
        let c = b[i];

        if in_comment {
            if lb[i..].starts_with(b"-->") {
                in_comment = false;
                i += 3;
                continue;
            }
            i += 1;
            continue;
        }

        if in_script {
            if let Some(q) = script_str {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    script_str = None;
                }
                i += 1;
                continue;
            }
            if lb[i..].starts_with(b"</script") {
                in_script = false;
                i += 8;
                continue;
            }
            if c == b'"' || c == b'\'' || c == b'`' {
                script_str = Some(c);
            }
            i += 1;
            continue;
        }

        if !in_tag {
            if lb[i..].starts_with(b"<!--") {
                in_comment = true;
                i += 4;
                continue;
            }
            if c == b'<' && i + 1 < b.len() && (b[i + 1].is_ascii_alphabetic() || b[i + 1] == b'/') {
                in_tag = true;
                attr_quote = None;
                after_eq = false;
                attr_name.clear();
                active_attr = None;
                pending_script = lb[i..].starts_with(b"<script");
                i += 1;
                continue;
            }
            i += 1;
            continue;
        }

        // 标签内
        if let Some(q) = attr_quote {
            if c == q {
                attr_quote = None;
                after_eq = false;
                active_attr = None;
            }
            i += 1;
            continue;
        }
        if c == b'>' {
            in_tag = false;
            if pending_script {
                in_script = true;
                pending_script = false;
            }
            after_eq = false;
            active_attr = None;
            attr_name.clear();
            i += 1;
            continue;
        }
        if c == b'=' {
            after_eq = true;
            active_attr = Some(attr_name.clone());
            attr_name.clear();
            i += 1;
            continue;
        }
        if after_eq && (c == b'"' || c == b'\'') {
            attr_quote = Some(c);
            i += 1;
            continue;
        }
        if c.is_ascii_whitespace() {
            // 属性间空白:无引号值结束 / 一个属性名结束。
            after_eq = false;
            active_attr = None;
            attr_name.clear();
        } else if !after_eq {
            // 累积属性名(用于识别 URL 型属性)。
            attr_name.push(c.to_ascii_lowercase() as char);
        }
        i += 1;
    }

    if in_comment {
        return HtmlContext::Comment;
    }
    if in_script {
        return match script_str {
            Some(q) => HtmlContext::ScriptString(q as char),
            None => HtmlContext::ScriptRaw,
        };
    }
    if in_tag {
        // 是否落在某属性「值」里(带引号,或 `=` 之后的无引号值)。
        let in_value = attr_quote.is_some() || after_eq;
        let is_url = in_value
            && active_attr
                .as_deref()
                .map(|a| URL_ATTRS.contains(&a))
                .unwrap_or(false);
        if is_url {
            return HtmlContext::UrlAttribute(attr_quote.map(|b| b as char));
        }
        return match attr_quote {
            Some(b'"') => HtmlContext::AttrDouble,
            Some(b'\'') => HtmlContext::AttrSingle,
            _ => HtmlContext::AttrUnquoted,
        };
    }
    HtmlContext::HtmlText
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 用 `␣` 占位标记在 HTML 里的反射点,返回其偏移处识别出的上下文。
    fn ctx_at(html: &str, marker: &str) -> HtmlContext {
        let off = html.find(marker).unwrap();
        detect_context(html, off)
    }

    #[test]
    fn html_text_context() {
        assert_eq!(ctx_at("<div>MARK</div>", "MARK"), HtmlContext::HtmlText);
    }

    #[test]
    fn attribute_contexts() {
        // 非 URL 属性 → 普通属性上下文。
        assert_eq!(ctx_at("<input value=\"MARK\">", "MARK"), HtmlContext::AttrDouble);
        assert_eq!(ctx_at("<input value='MARK'>", "MARK"), HtmlContext::AttrSingle);
        assert_eq!(ctx_at("<input value=MARK >", "MARK"), HtmlContext::AttrUnquoted);
    }

    #[test]
    fn url_attribute_context() {
        // href/src 等 URL 属性 → 可用 javascript: 伪协议。
        assert_eq!(
            ctx_at("<a href=\"MARK\">x</a>", "MARK"),
            HtmlContext::UrlAttribute(Some('"'))
        );
        assert_eq!(
            ctx_at("<iframe src=MARK>", "MARK"),
            HtmlContext::UrlAttribute(None)
        );
    }

    #[test]
    fn script_contexts() {
        assert_eq!(
            ctx_at("<script>var a='MARK';</script>", "MARK"),
            HtmlContext::ScriptString('\'')
        );
        assert_eq!(
            ctx_at("<script>var a=\"MARK\";</script>", "MARK"),
            HtmlContext::ScriptString('"')
        );
        assert_eq!(
            ctx_at("<script>var a=MARK;</script>", "MARK"),
            HtmlContext::ScriptRaw
        );
    }

    #[test]
    fn comment_context() {
        assert_eq!(ctx_at("<!-- MARK -->", "MARK"), HtmlContext::Comment);
    }

    #[test]
    fn closed_attribute_returns_to_text() {
        // 标记在闭合标签之后的文本里。
        assert_eq!(ctx_at("<a href=\"x\">MARK</a>", "MARK"), HtmlContext::HtmlText);
    }

    #[test]
    fn script_string_closed_is_raw() {
        // 字符串已闭合,标记落在裸 JS 区。
        assert_eq!(
            ctx_at("<script>var a='x'; MARK</script>", "MARK"),
            HtmlContext::ScriptRaw
        );
    }
}
