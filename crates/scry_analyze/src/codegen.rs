//! 把一条流的**请求**导出成各语言代码片段(对标 Burp/Reqable 的「复制为 curl / Python / fetch…」)。
//!
//! 纯函数、可单测。所有导出都跳过由 URL / 运行时自动管理的头(`Host` / `Content-Length` /
//! `Connection`),避免粘贴后冲突;`curl` 仅跳 `Host`(沿用 [`crate::curl`] 既有行为)。

use scry_core::HttpFlow;

/// 可导出的目标语言 / 形态。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeLang {
    Curl,
    Python,
    /// 浏览器 `fetch`。
    JsFetch,
    /// 浏览器 `XMLHttpRequest`。
    JsXhr,
}

impl CodeLang {
    pub const ALL: [CodeLang; 4] = [
        CodeLang::Curl,
        CodeLang::Python,
        CodeLang::JsFetch,
        CodeLang::JsXhr,
    ];

    /// UI 菜单标签(英文 key,中文走 i18n 表)。
    pub fn label(self) -> &'static str {
        match self {
            CodeLang::Curl => "Copy as curl",
            CodeLang::Python => "Copy as Python",
            CodeLang::JsFetch => "Copy as JavaScript (fetch)",
            CodeLang::JsXhr => "Copy as JavaScript (XHR)",
        }
    }

    /// 生成该语言的请求代码。
    pub fn generate(self, flow: &HttpFlow) -> String {
        match self {
            CodeLang::Curl => crate::curl::to_curl(flow),
            CodeLang::Python => to_python(flow),
            CodeLang::JsFetch => to_js_fetch(flow),
            CodeLang::JsXhr => to_js_xhr(flow),
        }
    }
}

/// 由 URL / 运行时自动管理、导出时应跳过的请求头。
fn is_auto_header(name: &str) -> bool {
    ["host", "content-length", "connection"]
        .iter()
        .any(|h| name.eq_ignore_ascii_case(h))
}

/// 方法是否常规无 body(GET / HEAD)。
fn is_bodyless(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")
}

// ── Python (requests) ────────────────────────────────────────────────

/// 导出为 Python `requests` 脚本。
pub fn to_python(flow: &HttpFlow) -> String {
    let mut s = String::from("import requests\n\n");
    s.push_str(&format!("url = {}\n", py_str(&flow.url())));

    s.push_str("headers = {\n");
    for (k, v) in &flow.req_headers {
        if is_auto_header(k) {
            continue;
        }
        s.push_str(&format!("    {}: {},\n", py_str(k), py_str(v)));
    }
    s.push_str("}\n");

    let has_body = !flow.req_body.is_empty();
    if has_body {
        s.push_str(&format!("data = {}\n", py_bytes(&flow.req_body)));
    }
    s.push_str(&format!(
        "resp = requests.request({}, url, headers=headers{})\n",
        py_str(&flow.method),
        if has_body { ", data=data" } else { "" },
    ));
    s.push_str("print(resp.status_code)\nprint(resp.text)\n");
    s
}

// ── JavaScript fetch ─────────────────────────────────────────────────

/// 导出为浏览器 `fetch` 片段。
pub fn to_js_fetch(flow: &HttpFlow) -> String {
    let mut s = format!("fetch({}, {{\n", js_str(&flow.url()));
    s.push_str(&format!("  method: {},\n", js_str(&flow.method)));
    s.push_str("  headers: {\n");
    let hdrs: Vec<&(String, String)> =
        flow.req_headers.iter().filter(|(k, _)| !is_auto_header(k)).collect();
    for (i, (k, v)) in hdrs.iter().enumerate() {
        let comma = if i + 1 < hdrs.len() { "," } else { "" };
        s.push_str(&format!("    {}: {}{}\n", js_str(k), js_str(v), comma));
    }
    s.push_str("  }");
    if !flow.req_body.is_empty() && !is_bodyless(&flow.method) {
        s.push_str(&format!(
            ",\n  body: {}",
            js_str(&String::from_utf8_lossy(&flow.req_body))
        ));
    }
    s.push_str("\n})\n  .then(r => r.text())\n  .then(console.log);\n");
    s
}

// ── JavaScript XMLHttpRequest ────────────────────────────────────────

/// 导出为浏览器 `XMLHttpRequest` 片段。
pub fn to_js_xhr(flow: &HttpFlow) -> String {
    let mut s = String::from("const xhr = new XMLHttpRequest();\n");
    s.push_str(&format!(
        "xhr.open({}, {});\n",
        js_str(&flow.method),
        js_str(&flow.url())
    ));
    for (k, v) in &flow.req_headers {
        if is_auto_header(k) {
            continue;
        }
        s.push_str(&format!("xhr.setRequestHeader({}, {});\n", js_str(k), js_str(v)));
    }
    s.push_str("xhr.onload = () => console.log(xhr.status, xhr.responseText);\n");
    if flow.req_body.is_empty() || is_bodyless(&flow.method) {
        s.push_str("xhr.send(null);\n");
    } else {
        s.push_str(&format!(
            "xhr.send({});\n",
            js_str(&String::from_utf8_lossy(&flow.req_body))
        ));
    }
    s
}

// ── 字符串字面量转义 ──────────────────────────────────────────────────

/// JavaScript 双引号字符串字面量。
fn js_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Python 双引号字符串字面量(文本)。
fn py_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Python `bytes` 字面量(原样字节,非可打印转 `\xNN`)。
fn py_bytes(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() + 3);
    out.push_str("b\"");
    for &byte in b {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(byte as char),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post_flow() -> HttpFlow {
        HttpFlow::request(
            "POST",
            "https",
            "api.example.com",
            443,
            "/login",
            vec![
                ("Host".to_string(), "api.example.com".to_string()),
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Content-Length".to_string(), "13".to_string()),
            ],
            br#"{"u":"a\b"}"#.to_vec(),
        )
    }

    #[test]
    fn python_skips_auto_headers_and_includes_body() {
        let py = to_python(&post_flow());
        assert!(py.contains("import requests"));
        assert!(py.contains(r#"url = "https://api.example.com/login""#));
        assert!(py.contains(r#""Content-Type": "application/json""#));
        // Host / Content-Length 被跳过。
        assert!(!py.contains("\"Host\""));
        assert!(!py.contains("Content-Length"));
        assert!(py.contains("data = b\""));
        assert!(py.contains(r#"requests.request("POST", url, headers=headers, data=data)"#));
    }

    #[test]
    fn js_fetch_get_has_no_body() {
        let f = HttpFlow::request(
            "GET",
            "https",
            "h",
            443,
            "/a?x=1",
            vec![("Accept".to_string(), "*/*".to_string())],
            vec![],
        );
        let js = to_js_fetch(&f);
        assert!(js.starts_with("fetch(\"https://h/a?x=1\", {"));
        assert!(js.contains("method: \"GET\""));
        assert!(js.contains("\"Accept\": \"*/*\""));
        assert!(!js.contains("body:"));
        assert!(js.contains(".then(r => r.text())"));
    }

    #[test]
    fn js_xhr_sends_body_for_post() {
        let x = to_js_xhr(&post_flow());
        assert!(x.contains("new XMLHttpRequest()"));
        assert!(x.contains(r#"xhr.open("POST", "https://api.example.com/login")"#));
        assert!(x.contains(r#"xhr.setRequestHeader("Content-Type", "application/json")"#));
        assert!(!x.contains("Host"));
        // body 被转义发送(含 \\ 与 \")。
        assert!(x.contains("xhr.send(\""));
        assert!(!x.contains("xhr.send(null)"));
    }

    #[test]
    fn codelang_generate_dispatches() {
        let f = post_flow();
        assert_eq!(CodeLang::Curl.generate(&f), crate::curl::to_curl(&f));
        assert!(CodeLang::Python.generate(&f).contains("import requests"));
        assert!(CodeLang::JsFetch.generate(&f).contains("fetch("));
        assert!(CodeLang::JsXhr.generate(&f).contains("XMLHttpRequest"));
    }

    #[test]
    fn escaping_handles_quotes_and_newlines() {
        assert_eq!(js_str("a\"b\nc"), r#""a\"b\nc""#);
        assert_eq!(py_str("a\"b\nc"), r#""a\"b\nc""#);
        assert_eq!(py_bytes(b"a\"b"), r#"b"a\"b""#);
        assert_eq!(py_bytes(&[0x00, 0xff]), r#"b"\x00\xff""#);
    }
}
