//! 报文 body 语法高亮(展示层,纯函数)——给「重放 / 代理」里看到的数据上色。
//!
//! 设计:**逐行分词**(不依赖完整解析器),鲁棒且对压成一行的 JSON 也能整行扫;空白并入
//! 相邻 token 以保持等宽对齐。分词([`tokenize_json_line`] / [`tokenize_form_line`])是纯函数、
//! 返回 `(文本, 类别)` 便于单测;着色([`Palette`])从主题语义色映射,换肤自动跟随。
//! 产出可直接喂 [`mage_ui::CodeView`] 的彩色行元素。

use std::cell::RefCell;
use std::ops::Range;

use mage_ui::prelude::*;

use crate::i18n::Lang;
use crate::model::method_color;

/// token 语义类别(取色 + 单测断言用)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tok {
    /// JSON 键 / 表单字段名。
    Key,
    /// 字符串字面量 / 表单值。
    Str,
    /// 数字字面量。
    Num,
    /// `true` / `false` / `null`。
    Keyword,
    /// 结构符:`{} [] : , & =` 等。
    Punct,
    /// 普通文本 / 空白。
    Plain,
}

/// 高亮取色(从主题语义色映射,换肤自动跟随)。
#[derive(Clone, Copy)]
pub struct Palette {
    key: Hsla,
    string: Hsla,
    number: Hsla,
    keyword: Hsla,
    punct: Hsla,
    plain: Hsla,
}

impl Palette {
    /// 由当前主题色构造一套高亮取色。
    pub fn from_theme(c: ThemeColors) -> Self {
        Self {
            key: c.primary,
            string: c.success,
            number: c.warning,
            keyword: c.accent,
            punct: c.text_subtle,
            plain: c.text_muted,
        }
    }

    fn color(&self, t: Tok) -> Hsla {
        match t {
            Tok::Key => self.key,
            Tok::Str => self.string,
            Tok::Num => self.number,
            Tok::Keyword => self.keyword,
            Tok::Punct => self.punct,
            Tok::Plain => self.plain,
        }
    }
}

/// token 类别 → 主题色(供别处把分词结果映射成颜色,如只读文本框的高亮区间)。
pub fn token_color(tok: Tok, c: ThemeColors) -> Hsla {
    Palette::from_theme(c).color(tok)
}

/// 把**一行**(通常已 pretty 的)JSON 文本切成带类别的 token。
///
/// 字符串后向看一个非空白字符:若是 `:` 则判为 [`Tok::Key`],否则为 [`Tok::Str`]。
/// 空白单独成 [`Tok::Plain`] token(保留缩进/对齐)。
pub fn tokenize_json_line(line: &str) -> Vec<(String, Tok)> {
    let chars: Vec<char> = line.chars().collect();
    let mut out: Vec<(String, Tok)> = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        match ch {
            c if c.is_whitespace() => {
                let start = i;
                while i < chars.len() && chars[i].is_whitespace() {
                    i += 1;
                }
                out.push((chars[start..i].iter().collect(), Tok::Plain));
            }
            '{' | '}' | '[' | ']' | ':' | ',' => {
                out.push((ch.to_string(), Tok::Punct));
                i += 1;
            }
            '"' => {
                let start = i;
                i += 1;
                while i < chars.len() {
                    match chars[i] {
                        '\\' => i += 2, // 跳过转义对(\" \\ 等)
                        '"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
                let end = i.min(chars.len());
                let s: String = chars[start..end].iter().collect();
                // 向后看:跳过空白,下一个非空白若是 ':' → 这是键。
                let mut j = end;
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                let kind = if j < chars.len() && chars[j] == ':' {
                    Tok::Key
                } else {
                    Tok::Str
                };
                out.push((s, kind));
            }
            c if c == '-' || c.is_ascii_digit() => {
                let start = i;
                i += 1;
                while i < chars.len()
                    && (chars[i].is_ascii_digit() || matches!(chars[i], '.' | 'e' | 'E' | '+' | '-'))
                {
                    i += 1;
                }
                out.push((chars[start..i].iter().collect(), Tok::Num));
            }
            c if c.is_ascii_alphabetic() => {
                let start = i;
                while i < chars.len() && chars[i].is_ascii_alphabetic() {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                let kind = match word.as_str() {
                    "true" | "false" | "null" => Tok::Keyword,
                    _ => Tok::Plain,
                };
                out.push((word, kind));
            }
            _ => {
                out.push((ch.to_string(), Tok::Plain));
                i += 1;
            }
        }
    }
    out
}

/// 把 `a=1&b=2` 形态(query / x-www-form-urlencoded)的一行切成 key/punct/value token。
pub fn tokenize_form_line(line: &str) -> Vec<(String, Tok)> {
    let mut out: Vec<(String, Tok)> = Vec::new();
    for (idx, pair) in line.split('&').enumerate() {
        if idx > 0 {
            out.push(("&".to_string(), Tok::Punct));
        }
        match pair.split_once('=') {
            Some((k, v)) => {
                out.push((k.to_string(), Tok::Key));
                out.push(("=".to_string(), Tok::Punct));
                if !v.is_empty() {
                    out.push((v.to_string(), Tok::Str));
                }
            }
            None => out.push((pair.to_string(), Tok::Plain)),
        }
    }
    out
}

/// 一条已**解码 + 分词**的报文行(放进缓存的纯数据;`SharedString` 复用使每帧重建近乎零成本)。
#[derive(Clone)]
enum Line {
    /// 已分词的彩色行(JSON / 表单)。
    Tokens(Vec<(SharedString, Tok)>),
    /// 普通文本行(弱化单色)。
    Plain(SharedString),
    /// 尾注 / 空 body 等(更弱化)。
    Subtle(SharedString),
}

// ── body 解码缓存(性能关键)──
// 选中大响应体(浏览器流量动辄几百 KB)时,`scry_decode` 的 gzip/br 解压 + JSON 美化 + 逐 token 分词
// **不能每帧都做**(滚动 / 500ms 推流都会重渲父视图)。这里按 body 缓存解码结果:
// - key = (body 堆指针, 长度, 语言):`Vec<u8>` 的**堆缓冲区指针在父 Vec 插入/移动时不变**,
//   故滚动期间稳定命中;新流量插表头令旧 body 仍指向原堆,指针照旧有效。
// - 缓存的是 `Vec<Line>`(`SharedString` 驻留),每帧只做 Arc 级廉价克隆 + 建 div,**不再解压/分词**。
/// body 缓存的一项:`((堆指针, 长度, 语言标志), 解码后的行)`。
type BodyCacheEntry = ((usize, usize, bool), Vec<Line>);
thread_local! {
    static BODY_CACHE: RefCell<Vec<BodyCacheEntry>> = const { RefCell::new(Vec::new()) };
}
/// 缓存容量(请求 + 响应 + 重放等几路并存,够用即可)。
const BODY_CACHE_CAP: usize = 8;

/// 实打实解码 + 分词(**仅缓存未命中时调用**)。
fn decode_lines(headers: &[(String, String)], body: &[u8], max: usize, lang: Lang) -> Vec<Line> {
    if body.is_empty() {
        return vec![Line::Subtle(lang.t("(empty body)"))];
    }
    let intern = |toks: Vec<(String, Tok)>| -> Line {
        Line::Tokens(toks.into_iter().map(|(s, k)| (SharedString::from(s), k)).collect())
    };

    // gRPC / Protobuf:按 content-type 渲染为字段树(无 schema 的 wire 解码)。
    let ct = scry_decode::header_get(headers, "content-type")
        .unwrap_or("")
        .to_ascii_lowercase();
    if ct.contains("grpc") || ct.contains("protobuf") {
        let raw = scry_decode::decode_body(headers, body);
        let tree = if ct.contains("grpc") {
            scry_codec::protobuf::decode_grpc_to_text(&raw)
        } else {
            scry_codec::protobuf::decode_to_text(&raw)
        };
        if let Some(tree) = tree {
            return capped_to_lines(&tree, max, body.len(), lang, |line| {
                Line::Plain(SharedString::from(line))
            });
        }
    }

    if let Some(pretty) = scry_decode::display_pretty_json(headers, body) {
        return capped_to_lines(&pretty, max, body.len(), lang, |line| {
            intern(tokenize_json_line(line))
        });
    }

    let text = scry_decode::display_text(headers, body);
    let is_form = scry_decode::header_get(headers, "content-type")
        .map(|ct| ct.to_ascii_lowercase().contains("x-www-form-urlencoded"))
        .unwrap_or(false);
    if is_form {
        return capped_to_lines(&text, max, body.len(), lang, |line| {
            intern(tokenize_form_line(line))
        });
    }

    capped_to_lines(&text, max, body.len(), lang, |line| {
        Line::Plain(SharedString::from(line))
    })
}

/// 把文本切成最多 `max` 行并逐行 `make` 成 [`Line`];超出补「共 N 字节」尾注。
fn capped_to_lines(
    text: &str,
    max: usize,
    raw_len: usize,
    lang: Lang,
    make: impl FnMut(&str) -> Line,
) -> Vec<Line> {
    let mut out: Vec<Line> = text.lines().take(max).map(make).collect();
    if text.lines().count() > max {
        let note = if lang.is_zh() {
            format!("… (共 {raw_len} 字节)")
        } else {
            format!("… ({raw_len} bytes total)")
        };
        out.push(Line::Subtle(SharedString::from(note)));
    }
    out
}

/// 把一条缓存 [`Line`] 渲染成元素(每帧做,廉价:仅 `SharedString` Arc 克隆 + 建 div)。
fn render_line(line: &Line, pal: Palette, c: ThemeColors) -> AnyElement {
    match line {
        Line::Tokens(toks) => {
            if toks.iter().all(|(s, _)| s.is_empty()) {
                return div().child(" ").into_any_element(); // 空行也占一行高
            }
            let mut row = div().flex().flex_row().items_start();
            for (text, kind) in toks {
                if text.is_empty() {
                    continue;
                }
                row = row.child(
                    div()
                        .flex_shrink_0()
                        .text_color(pal.color(*kind))
                        .child(text.clone()),
                );
            }
            row.into_any_element()
        }
        Line::Plain(s) => plain_line(s.clone(), c.text_muted),
        Line::Subtle(s) => plain_line(s.clone(), c.text_subtle),
    }
}

/// 一行纯色文本(回退用)。
fn plain_line(s: impl Into<SharedString>, color: Hsla) -> AnyElement {
    div().text_color(color).child(s.into()).into_any_element()
}

/// body → **彩色**报文行(Pretty 视图)。
///
/// 先解码(去 chunk + 解压 + charset);JSON 走 [`tokenize_json_line`] 着色,表单走
/// [`tokenize_form_line`],其它文本回退弱化单色(保持可读、不强行上色)。
/// **解码结果按 body 缓存**(见 [`decoded_lines_cached`]),每帧只重建廉价的着色 div。
pub fn body_lines(
    headers: &[(String, String)],
    body: &[u8],
    max: usize,
    lang: Lang,
    c: ThemeColors,
) -> Vec<AnyElement> {
    let pal = Palette::from_theme(c);
    let key = (body.as_ptr() as usize, body.len(), lang.is_zh());
    // 确保已缓存(未命中则解码并写入)。
    let cached = BODY_CACHE.with(|cc| cc.borrow().iter().any(|(k, _)| *k == key));
    if !cached {
        let lines = decode_lines(headers, body, max, lang);
        BODY_CACHE.with(|cc| {
            let mut cc = cc.borrow_mut();
            cc.push((key, lines));
            if cc.len() > BODY_CACHE_CAP {
                let drop = cc.len() - BODY_CACHE_CAP;
                cc.drain(0..drop);
            }
        });
    }
    // 从缓存按引用建元素(不克隆整张行表,只在 token 级做 Arc 克隆)。
    BODY_CACHE.with(|cc| {
        let cc = cc.borrow();
        match cc.iter().find(|(k, _)| *k == key) {
            Some((_, lines)) => lines.iter().map(|l| render_line(l, pal, c)).collect(),
            None => Vec::new(),
        }
    })
}

/// 把**任意文本**逐行做 JSON token 着色,产出「字节范围 → 颜色」的高亮区间。
///
/// 供只读可选中文本框(解码器输出 / 无 HTTP 头的纯 body / 代码)在「可选中复制」的同时多色显示:
/// 与传入 `text` 的字节**严格对齐**(逐行 [`tokenize_json_line`] 后累加偏移),非 JSON 文本无可着色 token 即保持基色。
/// 这是旧 `code_lines`(曾产不可选中的 `CodeView` 行)的可选中版替身。
pub fn body_text_highlights(text: &str, c: ThemeColors) -> Vec<(Range<usize>, Hsla)> {
    let mut out: Vec<(Range<usize>, Hsla)> = Vec::new();
    let mut byte = 0usize;
    for line in text.split('\n') {
        let mut loff = byte;
        for (txt, tok) in tokenize_json_line(line) {
            let len = txt.len();
            if !matches!(tok, Tok::Plain) {
                out.push((loff..loff + len, token_color(tok, c)));
            }
            loff += len;
        }
        byte += line.len() + 1; // +1 = 换行符
    }
    out
}

/// 把文本规范成展示形态:合法 JSON → 美化缩进(便于阅读,并与 [`body_text_highlights`] 着色对齐);
/// 否则原样返回。供只读高亮查看器(解码器输出等)用。
pub fn code_text(text: &str) -> String {
    scry_decode::display_pretty_json(&[], text.as_bytes()).unwrap_or_else(|| text.to_string())
}

/// 把一段**原始 HTTP 请求文本**(请求行 + 头 + 空行 + body)渲染成彩色报文行。
///
/// 给 Repeater 请求区的 Pretty(只读)视图用:请求行的方法按方法色、路径常规、版本弱化;
/// 头部 `Key: Value` 双色;body 复用 [`body_lines`](按 content-type 自动 JSON / 表单 / 文本分色)。
pub fn request_lines(raw: &str, max: usize, lang: Lang, c: ThemeColors) -> Vec<AnyElement> {
    let norm = raw.replace("\r\n", "\n");
    let (head, body) = match norm.split_once("\n\n") {
        Some((h, b)) => (h, b),
        None => (norm.as_str(), ""),
    };

    let mut out: Vec<AnyElement> = Vec::new();
    let mut headers: Vec<(String, String)> = Vec::new();
    for (i, line) in head.lines().enumerate() {
        if i == 0 {
            out.push(request_line_el(line, c));
        } else if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            headers.push((k.to_string(), v.to_string()));
            out.push(
                div()
                    .flex()
                    .flex_row()
                    .items_start()
                    .gap(px(6.0))
                    .child(div().flex_shrink_0().text_color(c.accent).child(format!("{k}:")))
                    .child(div().min_w(px(0.0)).text_color(c.text_muted).child(v.to_string()))
                    .into_any_element(),
            );
        } else if !line.trim().is_empty() {
            out.push(plain_line(line.to_string(), c.text_muted));
        }
    }
    // 空行(请求头与 body 之间)。
    out.push(div().child(" ").into_any_element());
    if !body.is_empty() {
        out.extend(body_lines(&headers, body.as_bytes(), max, lang, c));
    }
    out
}

/// 请求行(`METHOD path HTTP/x`):方法按方法色加粗 + 路径常规 + 版本弱化。
fn request_line_el(line: &str, c: ThemeColors) -> AnyElement {
    let mut parts = line.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let ver = parts.next().unwrap_or("");
    let mut row = div()
        .flex()
        .flex_row()
        .items_start()
        .child(
            div()
                .flex_shrink_0()
                .text_color(method_color(method, c))
                .font_weight(FontWeight::SEMIBOLD)
                .child(method.to_string()),
        )
        .child(div().flex_shrink_0().child(" "))
        .child(div().min_w(px(0.0)).text_color(c.text).child(path.to_string()));
    if !ver.is_empty() {
        row = row
            .child(div().flex_shrink_0().child(" "))
            .child(div().flex_shrink_0().text_color(c.text_subtle).child(ver.to_string()));
    }
    row.into_any_element()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 只取 token 类别序列(忽略空白 Plain),便于断言。
    fn kinds(tokens: &[(String, Tok)]) -> Vec<Tok> {
        tokens
            .iter()
            .filter(|(s, k)| !(matches!(k, Tok::Plain) && s.trim().is_empty()))
            .map(|(_, k)| *k)
            .collect()
    }

    #[test]
    fn json_key_value_number() {
        let toks = tokenize_json_line("  \"code\": 0,");
        assert_eq!(kinds(&toks), vec![Tok::Key, Tok::Punct, Tok::Num, Tok::Punct]);
        // 键文本含引号。
        assert!(toks.iter().any(|(s, k)| *k == Tok::Key && s == "\"code\""));
    }

    #[test]
    fn json_string_value() {
        let toks = tokenize_json_line("  \"message\": \"success\",");
        assert_eq!(kinds(&toks), vec![Tok::Key, Tok::Punct, Tok::Str, Tok::Punct]);
        assert!(toks.iter().any(|(s, k)| *k == Tok::Str && s == "\"success\""));
    }

    #[test]
    fn json_keywords_and_brace() {
        assert_eq!(kinds(&tokenize_json_line("{")), vec![Tok::Punct]);
        let toks = tokenize_json_line("  \"ok\": true,");
        assert_eq!(kinds(&toks), vec![Tok::Key, Tok::Punct, Tok::Keyword, Tok::Punct]);
        let toks = tokenize_json_line("  \"x\": null");
        assert_eq!(kinds(&toks), vec![Tok::Key, Tok::Punct, Tok::Keyword]);
    }

    #[test]
    fn json_escaped_quote_in_string() {
        // 值里含转义引号,不应被提前截断。
        let toks = tokenize_json_line(r#"  "q": "a\"b","#);
        assert_eq!(kinds(&toks), vec![Tok::Key, Tok::Punct, Tok::Str, Tok::Punct]);
        assert!(toks.iter().any(|(s, k)| *k == Tok::Str && s == r#""a\"b""#));
    }

    #[test]
    fn json_negative_and_float() {
        let toks = tokenize_json_line("  \"v\": -12.5e3");
        assert_eq!(kinds(&toks), vec![Tok::Key, Tok::Punct, Tok::Num]);
        assert!(toks.iter().any(|(s, k)| *k == Tok::Num && s == "-12.5e3"));
    }

    #[test]
    fn form_pairs() {
        let toks = tokenize_form_line("user=admin&pw=123");
        assert_eq!(
            kinds(&toks),
            vec![Tok::Key, Tok::Punct, Tok::Str, Tok::Punct, Tok::Key, Tok::Punct, Tok::Str]
        );
    }

    #[test]
    fn form_empty_value() {
        let toks = tokenize_form_line("flag=");
        assert_eq!(kinds(&toks), vec![Tok::Key, Tok::Punct]);
    }
}
