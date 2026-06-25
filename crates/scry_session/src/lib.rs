//! Scry 会话处理 —— **登录宏 + 会话/令牌捕获注入 + 登出检测** 的纯函数内核。
//!
//! 解决 authenticated 扫描的命门:扫描(SQLi/XSS/Nuclei…)发大量请求,中途会话(Cookie/JWT)过期
//! → 后续请求全部跳登录 / 401 → 误判「无漏洞」。对策对标 Burp **Session Handling Rules + Macros**:
//! 1. **登录宏**:一条(或一段)能重建有效会话的请求(POST /login 拿新 Cookie;或 GET 页面取新 CSRF)。
//! 2. **捕获**:从宏响应里抽出会话 —— `Set-Cookie`(→ Cookie 头)+ 可选的令牌(正则,CSRF/JWT)。
//! 3. **注入**:把会话套到后续每个扫描请求(合并 Cookie 头 / 注入令牌头 / `{{token}}` 占位替换)。
//! 4. **登出检测**:响应像「掉登录」(401/403、重定向到 login、命中正文标记)→ 触发重登。
//!
//! 本 crate 只做**纯函数**(解析 / 抽取 / 注入 / 判定);真正发宏请求由 app 层复用
//! [`scry_proxy::replay`] 完成(与各扫描器同一条 async 路径)。

pub mod capture;
pub mod detect;

pub use capture::{build_session, extract_token, parse_set_cookie};
pub use detect::looks_logged_out;

/// 抽取 / 检测作用的响应部位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Part {
    #[default]
    Body,
    Header,
}

/// 一次响应的只读视图(捕获 / 检测的输入)。
#[derive(Debug, Clone, Copy)]
pub struct Resp<'a> {
    pub status: u16,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
}

impl<'a> Resp<'a> {
    pub fn new(status: u16, headers: &'a [(String, String)], body: &'a [u8]) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

/// 捕获到的会话(Cookie 名值对 + 可选令牌)。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionState {
    pub cookies: Vec<(String, String)>,
    pub token: Option<String>,
}

impl SessionState {
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty() && self.token.is_none()
    }

    /// 拼成 `Cookie` 头值(`k1=v1; k2=v2`);无 cookie 返回 `None`。
    pub fn cookie_header(&self) -> Option<String> {
        if self.cookies.is_empty() {
            return None;
        }
        Some(cookie_header(&self.cookies))
    }

    /// 摘要(展示用):cookie 名列表 + 是否有令牌。
    pub fn summary(&self) -> String {
        let names: Vec<&str> = self.cookies.iter().map(|(k, _)| k.as_str()).collect();
        let mut s = if names.is_empty() {
            "无 cookie".to_string()
        } else {
            format!("cookie: {}", names.join(", "))
        };
        if self.token.is_some() {
            s.push_str(" · token ✓");
        }
        s
    }
}

/// 从宏响应里捕获什么。
#[derive(Debug, Clone)]
pub struct CaptureSpec {
    /// 捕获所有 `Set-Cookie`(组成会话 Cookie)。
    pub capture_cookies: bool,
    /// 令牌捕获正则(取第 1 个捕获组;无组取整体匹配)。
    pub token_regex: Option<String>,
    /// 令牌从响应哪个部位取(body / header)。
    pub token_part: Part,
}

impl Default for CaptureSpec {
    fn default() -> Self {
        Self {
            capture_cookies: true,
            token_regex: None,
            token_part: Part::Body,
        }
    }
}

/// 会话怎么套到后续请求。
#[derive(Debug, Clone, Default)]
pub struct ApplySpec {
    /// 合并会话 Cookie 进请求的 `Cookie` 头。
    pub apply_cookies: bool,
    /// 把令牌注入这个请求头(如 `X-CSRF-Token`);`None` = 不注入头(可改用 `{{token}}` 占位)。
    pub token_header: Option<String>,
}

/// 「掉登录」判定规则。
#[derive(Debug, Clone)]
pub struct LoggedOutSpec {
    /// 这些状态码视为掉登录(默认 401 / 403)。
    pub statuses: Vec<u16>,
    /// 3xx 且 `Location` 含 login/signin/auth 视为掉登录(默认开)。
    pub redirect_to_login: bool,
    /// 响应正文含此串视为掉登录(如「session expired」;空 = 不启用)。
    pub body_contains: Option<String>,
}

impl Default for LoggedOutSpec {
    fn default() -> Self {
        Self {
            statuses: vec![401, 403],
            redirect_to_login: true,
            body_contains: None,
        }
    }
}

/// 把 cookie 名值对拼成 `Cookie` 头值。
pub fn cookie_header(cookies: &[(String, String)]) -> String {
    cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// 把 `{{token}}` / `{{csrf}}` / `{{session}}` 占位替换为捕获的令牌(无令牌则替为空串)。
pub fn substitute(s: &str, st: &SessionState) -> String {
    let tok = st.token.clone().unwrap_or_default();
    s.replace("{{token}}", &tok)
        .replace("{{csrf}}", &tok)
        .replace("{{session}}", &tok)
}

/// 把会话套到一组请求头上,返回**新的头列表**(合并 Cookie + 可选注入令牌头)。
///
/// - Cookie:解析 base 里既有 `Cookie`,叠加会话 cookie(同名会话覆盖),重组为单个 `Cookie` 头。
/// - 令牌头:若 `apply.token_header` 指定且有令牌,设置/覆盖该头。
pub fn inject_headers(
    base: &[(String, String)],
    st: &SessionState,
    apply: &ApplySpec,
) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = base.to_vec();

    if apply.apply_cookies && !st.cookies.is_empty() {
        let existing = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let mut pairs = parse_cookie_pairs(&existing);
        for (k, v) in &st.cookies {
            if let Some(slot) = pairs.iter_mut().find(|(pk, _)| pk == k) {
                slot.1 = v.clone();
            } else {
                pairs.push((k.clone(), v.clone()));
            }
        }
        set_header(&mut headers, "Cookie", cookie_header(&pairs));
    }

    if let (Some(name), Some(tok)) = (&apply.token_header, &st.token) {
        if !name.trim().is_empty() {
            set_header(&mut headers, name.trim(), tok.clone());
        }
    }

    headers
}

// ───────────────────────── 内部工具 ─────────────────────────

/// 设置头(同名大小写不敏感覆盖,否则追加)。
pub(crate) fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: String) {
    if let Some(slot) = headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
        slot.1 = value;
    } else {
        headers.push((name.to_string(), value));
    }
}

/// 解析 `Cookie` 头值为名值对。
fn parse_cookie_pairs(s: &str) -> Vec<(String, String)> {
    s.split(';')
        .filter_map(|kv| {
            let kv = kv.trim();
            let (k, v) = kv.split_once('=')?;
            let k = k.trim();
            if k.is_empty() {
                None
            } else {
                Some((k.to_string(), v.trim().to_string()))
            }
        })
        .collect()
}

/// 把全部响应头拼成 `Key: Value\n` 文本(令牌正则取 Header 部位时用)。
pub(crate) fn header_text(headers: &[(String, String)]) -> String {
    let mut s = String::new();
    for (k, v) in headers {
        s.push_str(k);
        s.push_str(": ");
        s.push_str(v);
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_header_join() {
        let c = vec![("a".into(), "1".into()), ("b".into(), "2".into())];
        assert_eq!(cookie_header(&c), "a=1; b=2");
    }

    #[test]
    fn substitute_token() {
        let st = SessionState {
            cookies: vec![],
            token: Some("abc123".into()),
        };
        assert_eq!(substitute("X-CSRF: {{token}}", &st), "X-CSRF: abc123");
        assert_eq!(substitute("v={{csrf}}", &st), "v=abc123");
    }

    #[test]
    fn inject_merges_cookies() {
        let base = vec![
            ("Host".into(), "h".into()),
            ("Cookie".into(), "old=1; sess=stale".into()),
        ];
        let st = SessionState {
            cookies: vec![("sess".into(), "fresh".into()), ("new".into(), "x".into())],
            token: Some("tok".into()),
        };
        let apply = ApplySpec {
            apply_cookies: true,
            token_header: Some("X-CSRF-Token".into()),
        };
        let out = inject_headers(&base, &st, &apply);
        let cookie = out
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .unwrap();
        // 既有 old 保留,sess 被会话覆盖为 fresh,new 追加。
        assert!(cookie.1.contains("old=1"));
        assert!(cookie.1.contains("sess=fresh"));
        assert!(cookie.1.contains("new=x"));
        assert!(!cookie.1.contains("stale"));
        // 令牌头注入。
        assert!(out
            .iter()
            .any(|(k, v)| k == "X-CSRF-Token" && v == "tok"));
    }

    #[test]
    fn inject_noop_when_empty() {
        let base = vec![("Host".into(), "h".into())];
        let st = SessionState::default();
        let apply = ApplySpec {
            apply_cookies: true,
            token_header: Some("X-CSRF-Token".into()),
        };
        // 无 cookie、无 token → 不改动。
        assert_eq!(inject_headers(&base, &st, &apply), base);
    }
}
