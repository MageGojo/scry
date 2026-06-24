//! 请求参数 / Cookie 提取(查询串、表单体、Cookie 头),均做**百分号解码**。

use scry_core::HttpFlow;

/// 一个已解码的键值对。
pub type Kv = (String, String);

/// 百分号解码:`%XX` → 字节;`plus_as_space=true` 时把 `+` 当空格(表单 / 查询串语义)。
///
/// 非法 `%` 转义(后随非十六进制 / 越界)保守原样保留;最终按 UTF-8 宽松成字符串。
pub fn percent_decode(input: &str, plus_as_space: bool) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 从 origin-form 路径里取查询串(`?` 之后、`#` 之前的部分)。
pub fn query_string(path: &str) -> Option<&str> {
    let after = path.split_once('?')?.1;
    Some(after.split('#').next().unwrap_or(after))
}

/// 解析路径里的查询参数为已解码键值对(查询串里的 `+` 也按空格解)。
pub fn parse_query(path: &str) -> Vec<Kv> {
    match query_string(path) {
        Some(q) => parse_urlencoded(q),
        None => Vec::new(),
    }
}

/// 解析 `a=1&b=2&c` 形态(`application/x-www-form-urlencoded`);键值均百分号解码。
pub fn parse_urlencoded(s: &str) -> Vec<Kv> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k, true), percent_decode(v, true)),
            None => (percent_decode(pair, true), String::new()),
        })
        .collect()
}

/// 若请求是 `application/x-www-form-urlencoded`,解析表单字段;否则返回空。
pub fn form_params(flow: &HttpFlow) -> Vec<Kv> {
    let is_form = flow
        .req_header("content-type")
        .map(|ct| {
            ct.to_ascii_lowercase()
                .contains("application/x-www-form-urlencoded")
        })
        .unwrap_or(false);
    if !is_form {
        return Vec::new();
    }
    parse_urlencoded(&String::from_utf8_lossy(&flow.req_body))
}

/// 解析请求 `Cookie` 头为键值对(`a=1; b=2`)。
pub fn request_cookies(flow: &HttpFlow) -> Vec<Kv> {
    let Some(raw) = flow.req_header("cookie") else {
        return Vec::new();
    };
    raw.split(';')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(|c| match c.split_once('=') {
            Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
            None => (c.to_string(), String::new()),
        })
        .collect()
}

/// 解析响应所有 `Set-Cookie` 头的「名=值」(忽略 Path/Expires 等属性)。
pub fn response_set_cookies(flow: &HttpFlow) -> Vec<Kv> {
    flow.resp_headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, v)| {
            let first = v.split(';').next().unwrap_or("").trim();
            let (name, val) = first.split_once('=')?;
            Some((name.trim().to_string(), val.trim().to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow_with(req_headers: Vec<(String, String)>, body: &[u8]) -> HttpFlow {
        HttpFlow::request(
            "POST",
            "https",
            "h",
            443,
            "/p?a=1&b=hello%20world&flag&q=%E4%BD%A0",
            req_headers,
            body.to_vec(),
        )
    }

    #[test]
    fn percent_and_plus_decode() {
        assert_eq!(percent_decode("a%20b", false), "a b");
        assert_eq!(percent_decode("a+b", true), "a b");
        assert_eq!(percent_decode("a+b", false), "a+b");
        // UTF-8 多字节:%E4%BD%A0 = 你
        assert_eq!(percent_decode("%E4%BD%A0", true), "你");
        // 非法转义保守保留
        assert_eq!(percent_decode("100%done", false), "100%done");
    }

    #[test]
    fn query_parsing_decodes_pairs() {
        let f = flow_with(vec![], b"");
        let q = parse_query(&f.path);
        assert_eq!(
            q,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "hello world".to_string()),
                ("flag".to_string(), String::new()),
                ("q".to_string(), "你".to_string()),
            ]
        );
    }

    #[test]
    fn query_string_strips_fragment() {
        assert_eq!(query_string("/x?a=1#frag"), Some("a=1"));
        assert_eq!(query_string("/x"), None);
    }

    #[test]
    fn form_params_only_when_urlencoded() {
        let h = vec![(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded; charset=utf-8".to_string(),
        )];
        let f = flow_with(h, b"user=admin&pass=p%40ss+1");
        assert_eq!(
            form_params(&f),
            vec![
                ("user".to_string(), "admin".to_string()),
                ("pass".to_string(), "p@ss 1".to_string()),
            ]
        );

        // 非表单 content-type → 空
        let f2 = flow_with(
            vec![("Content-Type".to_string(), "application/json".to_string())],
            b"user=admin",
        );
        assert!(form_params(&f2).is_empty());
    }

    #[test]
    fn cookies_request_and_response() {
        let f = HttpFlow::request(
            "GET",
            "https",
            "h",
            443,
            "/",
            vec![("Cookie".to_string(), "sid=abc; theme=dark".to_string())],
            vec![],
        )
        .with_response(
            200,
            vec![
                (
                    "Set-Cookie".to_string(),
                    "sid=xyz; Path=/; HttpOnly".to_string(),
                ),
                ("Set-Cookie".to_string(), "lang=zh; Max-Age=3600".to_string()),
            ],
            vec![],
            1,
        );
        assert_eq!(
            request_cookies(&f),
            vec![
                ("sid".to_string(), "abc".to_string()),
                ("theme".to_string(), "dark".to_string()),
            ]
        );
        assert_eq!(
            response_set_cookies(&f),
            vec![
                ("sid".to_string(), "xyz".to_string()),
                ("lang".to_string(), "zh".to_string()),
            ]
        );
    }
}
