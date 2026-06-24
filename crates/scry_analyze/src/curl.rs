//! 把请求导出为可复制执行的 `curl` 命令(对标 Burp/Reqable 的「复制为 curl」)。

use scry_core::HttpFlow;

/// 把一条流的**请求部分**导出成单行 `curl` 命令(POSIX shell 引号)。
///
/// 约定:
/// - `GET` 省略 `-X`;其它方法显式 `-X <METHOD>`。
/// - 跳过 `Host` 头(由 URL 决定),其余请求头逐个 `-H`。
/// - 有请求体时用 `--data-binary`(原样字节按 UTF-8 宽松成串)。
pub fn to_curl(flow: &HttpFlow) -> String {
    let mut parts: Vec<String> = vec!["curl".to_string()];
    if !flow.method.eq_ignore_ascii_case("GET") {
        parts.push("-X".to_string());
        parts.push(flow.method.clone());
    }
    parts.push(shell_quote(&flow.url()));
    for (k, v) in &flow.req_headers {
        if k.eq_ignore_ascii_case("host") {
            continue;
        }
        parts.push("-H".to_string());
        parts.push(shell_quote(&format!("{k}: {v}")));
    }
    if !flow.req_body.is_empty() {
        parts.push("--data-binary".to_string());
        parts.push(shell_quote(&String::from_utf8_lossy(&flow.req_body)));
    }
    parts.join(" ")
}

/// POSIX 单引号转义:把内部的 `'` 替换成 `'\''`,整体再用单引号包住。
fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_omits_method_and_skips_host() {
        let f = HttpFlow::request(
            "GET",
            "https",
            "example.com",
            443,
            "/a?x=1",
            vec![
                ("Host".to_string(), "example.com".to_string()),
                ("Accept".to_string(), "*/*".to_string()),
            ],
            vec![],
        );
        let c = to_curl(&f);
        assert_eq!(c, "curl 'https://example.com/a?x=1' -H 'Accept: */*'");
    }

    #[test]
    fn post_with_body_and_quote_escaping() {
        let f = HttpFlow::request(
            "POST",
            "https",
            "h",
            443,
            "/login",
            vec![(
                "Content-Type".to_string(),
                "application/json".to_string(),
            )],
            br#"{"u":"o'brien"}"#.to_vec(),
        );
        let c = to_curl(&f);
        assert!(c.starts_with("curl -X POST 'https://h/login'"));
        assert!(c.contains("-H 'Content-Type: application/json'"));
        // 单引号被正确转义为 '\''
        assert!(c.contains(r#"--data-binary '{"u":"o'\''brien"}'"#));
    }
}
