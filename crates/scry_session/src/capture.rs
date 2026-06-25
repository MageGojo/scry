//! 从登录宏响应里捕获会话:`Set-Cookie` → Cookie 名值对;正则 → 令牌(CSRF/JWT)。

use crate::{header_text, CaptureSpec, Part, Resp, SessionState};
use regex::Regex;

/// 从响应头解析全部 `Set-Cookie` 的名值对(只取 `name=value`,丢弃属性 path/expires…)。
pub fn parse_set_cookie(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, v)| {
            let first = v.split(';').next().unwrap_or("").trim();
            let (k, val) = first.split_once('=')?;
            let k = k.trim();
            if k.is_empty() {
                None
            } else {
                Some((k.to_string(), val.trim().to_string()))
            }
        })
        .collect()
}

/// 用正则从响应(body 或 header)抽取令牌(取第 1 个捕获组;无组取整体匹配)。
pub fn extract_token(resp: &Resp, spec: &CaptureSpec) -> Option<String> {
    let pat = spec.token_regex.as_ref()?;
    if pat.trim().is_empty() {
        return None;
    }
    let re = Regex::new(pat).ok()?;
    let hay = match spec.token_part {
        Part::Body => String::from_utf8_lossy(resp.body).into_owned(),
        Part::Header => header_text(resp.headers),
    };
    let caps = re.captures(&hay)?;
    caps.get(1)
        .or_else(|| caps.get(0))
        .map(|m| m.as_str().to_string())
}

/// 由宏响应 + 捕获规则组出 [`SessionState`]。
pub fn build_session(resp: &Resp, spec: &CaptureSpec) -> SessionState {
    let cookies = if spec.capture_cookies {
        parse_set_cookie(resp.headers)
    } else {
        Vec::new()
    };
    let token = extract_token(resp, spec);
    SessionState { cookies, token }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_set_cookie() {
        let headers = vec![
            (
                "Set-Cookie".into(),
                "session=abc123; Path=/; HttpOnly".into(),
            ),
            ("Set-Cookie".into(), "csrf=zzz; Secure".into()),
            ("Content-Type".into(), "text/html".into()),
        ];
        let c = parse_set_cookie(&headers);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0], ("session".to_string(), "abc123".to_string()));
        assert_eq!(c[1], ("csrf".to_string(), "zzz".to_string()));
    }

    #[test]
    fn extracts_token_from_body() {
        let body = br#"<input name="csrf_token" value="TOKEN-9f8e">"#;
        let resp = Resp::new(200, &[], body);
        let spec = CaptureSpec {
            capture_cookies: true,
            token_regex: Some(r#"csrf_token"\s+value="([^"]+)""#.into()),
            token_part: Part::Body,
        };
        assert_eq!(extract_token(&resp, &spec), Some("TOKEN-9f8e".to_string()));
    }

    #[test]
    fn build_session_combines() {
        let headers = vec![("Set-Cookie".into(), "sid=xyz; Path=/".into())];
        let body = b"token=ABCD;";
        let resp = Resp::new(200, &headers, body);
        let spec = CaptureSpec {
            capture_cookies: true,
            token_regex: Some("token=([A-Z]+)".into()),
            token_part: Part::Body,
        };
        let st = build_session(&resp, &spec);
        assert_eq!(st.cookies, vec![("sid".to_string(), "xyz".to_string())]);
        assert_eq!(st.token, Some("ABCD".to_string()));
        assert!(!st.is_empty());
    }

    #[test]
    fn bad_regex_is_none_not_panic() {
        let resp = Resp::new(200, &[], b"x");
        let spec = CaptureSpec {
            capture_cookies: false,
            token_regex: Some("([".into()), // 非法正则
            token_part: Part::Body,
        };
        assert_eq!(extract_token(&resp, &spec), None);
    }
}
