//! 越权 / 访问控制测试(对标 **Burp Autorize / AuthMatrix**)的纯函数内核。
//!
//! 思路:同一请求用**不同身份**重放,比对响应——若**低权限 / 匿名身份也拿到了与高权限身份
//! 相同的成功响应**,说明服务端没做访问控制 = **Broken Access Control**:
//! - 匿名身份命中 → **未授权访问**(Critical);
//! - 低权限身份命中 → **越权 / 权限提升**(High,涵盖水平越权 IDOR 与垂直越权/提权)。
//!
//! 纯函数:身份套用([`apply_identity`])+ 判定([`compare`] / [`evaluate`]);多身份重放由
//! UI / CLI runner 复用 [`scry_proxy::replay`](与抓包同上游)。

use scry_core::{Header, HttpFlow};

use crate::types::{Finding, Severity};

/// 套用匿名身份时要剥离的常见鉴权头(大小写不敏感)。
const AUTH_HEADERS: [&str; 8] = [
    "authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
    "authentication",
    "token",
];

/// 一个测试身份 = 一组要套到请求上的鉴权头(空 = 匿名,套用时剥离常见鉴权头)。
#[derive(Clone, Debug)]
pub struct Identity {
    pub name: String,
    pub headers: Vec<Header>,
}

impl Identity {
    pub fn new(name: impl Into<String>, headers: Vec<Header>) -> Self {
        Self {
            name: name.into(),
            headers,
        }
    }

    /// 匿名身份(套用时剥离所有常见鉴权头)。
    pub fn anonymous() -> Self {
        Self {
            name: "anonymous".to_string(),
            headers: Vec::new(),
        }
    }

    pub fn is_anonymous(&self) -> bool {
        self.headers.is_empty()
    }

    /// 从 `"Header: value"` 文本解析(行 / 分号分隔),给 CLI / UI 用。
    pub fn parse(name: impl Into<String>, spec: &str) -> Self {
        let mut headers = Vec::new();
        for line in spec.split(['\n', ';']) {
            let l = line.trim();
            if l.is_empty() {
                continue;
            }
            if let Some((k, v)) = l.split_once(':') {
                let k = k.trim();
                let v = v.trim();
                if !k.is_empty() {
                    headers.push((k.to_string(), v.to_string()));
                }
            }
        }
        Self {
            name: name.into(),
            headers,
        }
    }
}

/// 把身份套到基准请求:覆盖同名鉴权头;匿名身份则剥离所有常见鉴权头。
/// 响应字段清空,返回的流可直接喂 `replay`。
pub fn apply_identity(base: &HttpFlow, id: &Identity) -> HttpFlow {
    let mut f = base.clone();
    // 删掉本身份将要设置的同名头(避免重复)。
    for (k, _) in &id.headers {
        f.req_headers.retain(|(hk, _)| !hk.eq_ignore_ascii_case(k));
    }
    if id.is_anonymous() {
        f.req_headers
            .retain(|(hk, _)| !AUTH_HEADERS.iter().any(|a| hk.eq_ignore_ascii_case(a)));
    } else {
        for (k, v) in &id.headers {
            f.req_headers.push((k.clone(), v.clone()));
        }
    }
    f.status = 0;
    f.resp_headers.clear();
    f.resp_body.clear();
    f.duration_ms = 0;
    f
}

/// 访问控制判定结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthVerdict {
    /// 正确拦截(401 / 403 / 登录跳转等)。
    Enforced,
    /// 疑似越权:低权 / 匿名身份也拿到了与高权限相同的成功响应。
    Bypass,
    /// 无法判定(响应不同,但非明确拦截)。
    Inconclusive,
}

/// 比对「高权限基准响应」与「测试身份响应」。
pub fn compare(privileged: &HttpFlow, test: &HttpFlow) -> AuthVerdict {
    // 基准本身要成功(2xx)才有比对意义。
    if !(200..300).contains(&privileged.status) {
        return AuthVerdict::Inconclusive;
    }
    let s = test.status;
    if s == 401 || s == 403 || (300..400).contains(&s) {
        // 明确拒绝 / 跳登录 = 拦截到位。
        AuthVerdict::Enforced
    } else if (200..300).contains(&s) {
        if similar(privileged, test) {
            AuthVerdict::Bypass
        } else {
            AuthVerdict::Inconclusive
        }
    } else {
        // 其它 4xx/5xx:没拿到资源,视作拦截。
        AuthVerdict::Enforced
    }
}

/// 响应「足够相似」= 同状态码且响应体长度接近(差 ≤64B 或 ≤10%)。
fn similar(a: &HttpFlow, b: &HttpFlow) -> bool {
    if a.status != b.status {
        return false;
    }
    let la = a.resp_body.len() as i64;
    let lb = b.resp_body.len() as i64;
    let diff = (la - lb).abs();
    diff <= 64 || (la > 0 && diff * 10 <= la)
}

/// 命中越权则给一条 [`Finding`](匿名 = Critical「未授权访问」;低权 = High「越权/提权」)。
pub fn evaluate(
    url: &str,
    test_id: &Identity,
    privileged: &HttpFlow,
    test: &HttpFlow,
) -> Option<Finding> {
    if compare(privileged, test) != AuthVerdict::Bypass {
        return None;
    }
    if test_id.is_anonymous() {
        Some(Finding::new(
            "authz-unauth-access",
            "Unauthenticated access to protected resource",
            Severity::Critical,
            url.to_string(),
            format!(
                "Anonymous request returns the same {} response ({} bytes) as the authorized one — access control not enforced",
                test.status,
                test.resp_body.len()
            ),
        ))
    } else {
        Some(Finding::new(
            "authz-bac",
            "Broken access control (privilege escalation)",
            Severity::High,
            url.to_string(),
            format!(
                "Identity '{}' gets the same {} response ({} bytes) as the privileged one — authorization bypass",
                test_id.name,
                test.status,
                test.resp_body.len()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow_with(headers: Vec<(&str, &str)>) -> HttpFlow {
        HttpFlow::request(
            "GET",
            "https",
            "ex.com",
            443,
            "/api/order/1001",
            headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            vec![],
        )
    }

    fn resp(base: &HttpFlow, status: u16, body: &[u8]) -> HttpFlow {
        base.clone().with_response(
            status,
            vec![("Content-Type".to_string(), "application/json".to_string())],
            body.to_vec(),
            5,
        )
    }

    #[test]
    fn parse_identity_from_spec() {
        let id = Identity::parse("low", "X-Api-Key: K2 ; Authorization: Bearer abc");
        assert_eq!(id.headers.len(), 2);
        assert_eq!(id.headers[0], ("X-Api-Key".to_string(), "K2".to_string()));
        assert!(!id.is_anonymous());
    }

    #[test]
    fn apply_identity_overrides_and_anon_strips() {
        let base = flow_with(vec![("X-Api-Key", "ADMIN"), ("Accept", "*/*")]);
        // 低权身份覆盖 X-Api-Key。
        let low = Identity::parse("low", "X-Api-Key: USER");
        let f = apply_identity(&base, &low);
        assert_eq!(f.req_header("x-api-key"), Some("USER"));
        assert_eq!(f.req_header("accept"), Some("*/*"));
        assert_eq!(f.status, 0);
        // 匿名剥离鉴权头。
        let anon = apply_identity(&base, &Identity::anonymous());
        assert_eq!(anon.req_header("x-api-key"), None);
        assert_eq!(anon.req_header("accept"), Some("*/*"));
    }

    #[test]
    fn compare_verdicts() {
        let base = flow_with(vec![]);
        let priv_ok = resp(&base, 200, &[b'a'; 500]);
        // 403 → Enforced
        assert_eq!(compare(&priv_ok, &resp(&base, 403, b"forbidden")), AuthVerdict::Enforced);
        // 302 → Enforced(跳登录)
        assert_eq!(compare(&priv_ok, &resp(&base, 302, b"")), AuthVerdict::Enforced);
        // 200 同长度 → Bypass
        assert_eq!(compare(&priv_ok, &resp(&base, 200, &[b'a'; 505])), AuthVerdict::Bypass);
        // 200 长度差很大 → Inconclusive
        assert_eq!(compare(&priv_ok, &resp(&base, 200, b"{}")), AuthVerdict::Inconclusive);
        // 基准非 2xx → Inconclusive
        assert_eq!(compare(&resp(&base, 500, b"err"), &resp(&base, 200, b"x")), AuthVerdict::Inconclusive);
    }

    #[test]
    fn evaluate_unauth_is_critical_low_is_high() {
        let base = flow_with(vec![("X-Api-Key", "ADMIN")]);
        let url = base.url();
        let privileged = resp(&base, 200, &[b'a'; 500]);
        // 匿名拿到同样数据 → Critical 未授权访问。
        let anon = Identity::anonymous();
        let anon_resp = resp(&base, 200, &[b'a'; 500]);
        let f = evaluate(&url, &anon, &privileged, &anon_resp).unwrap();
        assert_eq!(f.rule_id, "authz-unauth-access");
        assert_eq!(f.severity, Severity::Critical);
        // 低权拿到同样数据 → High 越权。
        let low = Identity::parse("user", "X-Api-Key: USER");
        let low_resp = resp(&base, 200, &[b'a'; 500]);
        let f2 = evaluate(&url, &low, &privileged, &low_resp).unwrap();
        assert_eq!(f2.rule_id, "authz-bac");
        assert_eq!(f2.severity, Severity::High);
        // 正确拦截 → 无 finding。
        let denied = resp(&base, 403, b"no");
        assert!(evaluate(&url, &low, &privileged, &denied).is_none());
    }
}
