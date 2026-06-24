//! 被动扫描:对已抓到的 [`HttpFlow`] 跑只读规则,产出 [`Finding`]。**不发包、纯函数、可单测。**
//!
//! 降噪约定:安全响应头类规则只对**文档(HTML)响应**判定(贴近 Burp 的「按页面」口径),
//! 避免对每个静态资源都报一遍。

use scry_analyze::parse_query;
use scry_core::HttpFlow;

use crate::types::{Finding, Severity};

/// 对一条流跑全部被动规则。
pub fn scan_flow(f: &HttpFlow) -> Vec<Finding> {
    let mut out = Vec::new();
    if f.status == 0 {
        // 只请求、无响应(如被动抓到的 TLS SNI 占位流)——跳过响应类规则。
        rule_sensitive_query(f, &mut out);
        rule_basic_auth_http(f, &mut out);
        return out;
    }

    rule_security_headers(f, &mut out);
    rule_cookie_flags(f, &mut out);
    rule_cookie_over_http(f, &mut out);
    rule_cors(f, &mut out);
    rule_server_banner(f, &mut out);
    rule_sensitive_query(f, &mut out);
    rule_basic_auth_http(f, &mut out);
    rule_body_signals(f, &mut out);
    out
}

/// 对一批流扫描:汇总 → 按 `(rule_id, url)` 去重 → 按严重度降序(同级按 url)排序。
pub fn scan_flows(flows: &[HttpFlow]) -> Vec<Finding> {
    let mut all: Vec<Finding> = Vec::new();
    for f in flows {
        all.extend(scan_flow(f));
    }
    all.sort_by(|a, b| (a.rule_id, &a.url).cmp(&(b.rule_id, &b.url)));
    all.dedup_by(|a, b| a.rule_id == b.rule_id && a.url == b.url);
    // 严重度降序,其次 url 升序,稳定可读。
    all.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.url.cmp(&b.url)));
    all
}

// ── 规则 ─────────────────────────────────────────────────────────

fn is_html(f: &HttpFlow) -> bool {
    f.content_type()
        .map(|ct| ct.to_ascii_lowercase().contains("html"))
        .unwrap_or(false)
}

/// 响应是否「可被浏览器 MIME 嗅探 / 当脚本执行」(决定 X-Content-Type-Options 是否相关)。
fn is_sniffable(f: &HttpFlow) -> bool {
    match f.content_type() {
        Some(ct) => {
            let ct = ct.to_ascii_lowercase();
            ct.contains("html")
                || ct.contains("json")
                || ct.contains("javascript")
                || ct.contains("xml")
                || ct.contains("css")
                || ct.contains("text/")
        }
        None => false,
    }
}

/// 安全响应头检查。多为**主机级**配置:用 `scheme://host` 作 url,使每个 host 每条头只报一次
/// (经 `scan_flows` 的 `(rule_id, url)` 去重收敛),避免对每个静态资源重复刷屏。
///
/// HSTS / X-Content-Type-Options / Referrer-Policy 对**任意/可嗅探**响应都判(不再限 HTML);
/// CSP / 点击劫持只对 HTML 文档判(渲染上下文相关)。
fn rule_security_headers(f: &HttpFlow, out: &mut Vec<Finding>) {
    let base = format!("{}://{}", f.scheme, f.host);

    if f.scheme == "https" && f.resp_header("strict-transport-security").is_none() {
        out.push(Finding::new(
            "missing-hsts",
            "Missing HSTS header",
            Severity::Medium,
            base.clone(),
            "HTTPS host sends no Strict-Transport-Security header",
        ));
    }
    if is_sniffable(f) && f.resp_header("x-content-type-options").is_none() {
        out.push(Finding::new(
            "missing-xcto",
            "Missing X-Content-Type-Options",
            Severity::Low,
            base.clone(),
            "No 'nosniff' — browser may MIME-sniff the response",
        ));
    }
    if f.resp_header("referrer-policy").is_none() {
        out.push(Finding::new(
            "missing-referrer-policy",
            "Missing Referrer-Policy",
            Severity::Info,
            base.clone(),
            "No Referrer-Policy — the full URL may leak via the Referer header",
        ));
    }

    if is_html(f) {
        let csp = f.resp_header("content-security-policy");
        if csp.is_none() {
            out.push(Finding::new(
                "missing-csp",
                "Missing Content-Security-Policy",
                Severity::Low,
                base.clone(),
                "No CSP header to constrain script/resource origins",
            ));
        }
        let has_frame_ancestors = csp
            .map(|v| v.to_ascii_lowercase().contains("frame-ancestors"))
            .unwrap_or(false);
        if f.resp_header("x-frame-options").is_none() && !has_frame_ancestors {
            out.push(Finding::new(
                "clickjacking",
                "Clickjacking: no frame protection",
                Severity::Medium,
                base,
                "Neither X-Frame-Options nor CSP frame-ancestors present",
            ));
        }
    }
}

/// 取响应所有原始 `Set-Cookie` 值(保留 Secure/HttpOnly/SameSite 等属性)。
fn raw_set_cookies(f: &HttpFlow) -> Vec<&str> {
    f.resp_headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v.as_str())
        .collect()
}

fn cookie_name(raw: &str) -> &str {
    raw.split(';')
        .next()
        .unwrap_or("")
        .split('=')
        .next()
        .unwrap_or("")
        .trim()
}

fn rule_cookie_flags(f: &HttpFlow, out: &mut Vec<Finding>) {
    let url = f.url();
    for raw in raw_set_cookies(f) {
        let low = raw.to_ascii_lowercase();
        let name = cookie_name(raw);
        if f.scheme == "https" && !low.contains("secure") {
            out.push(Finding::new(
                "cookie-no-secure",
                "Cookie without Secure flag",
                Severity::Medium,
                url.clone(),
                format!("Cookie '{name}' set over HTTPS without Secure"),
            ));
        }
        if !low.contains("httponly") {
            out.push(Finding::new(
                "cookie-no-httponly",
                "Cookie without HttpOnly flag",
                Severity::Low,
                url.clone(),
                format!("Cookie '{name}' accessible to JavaScript (no HttpOnly)"),
            ));
        }
        if !low.contains("samesite") {
            out.push(Finding::new(
                "cookie-no-samesite",
                "Cookie without SameSite",
                Severity::Low,
                url.clone(),
                format!("Cookie '{name}' has no SameSite attribute"),
            ));
        }
    }
}

fn rule_cookie_over_http(f: &HttpFlow, out: &mut Vec<Finding>) {
    if f.scheme == "http" && !raw_set_cookies(f).is_empty() {
        out.push(Finding::new(
            "cookie-over-http",
            "Cookie set over plaintext HTTP",
            Severity::High,
            f.url(),
            "Set-Cookie sent over unencrypted HTTP (sniffable)",
        ));
    }
}

fn rule_cors(f: &HttpFlow, out: &mut Vec<Finding>) {
    let Some(acao) = f.resp_header("access-control-allow-origin") else {
        return;
    };
    if acao.trim() != "*" {
        return;
    }
    let creds = f
        .resp_header("access-control-allow-credentials")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if creds {
        out.push(Finding::new(
            "cors-wildcard-credentials",
            "CORS wildcard with credentials",
            Severity::High,
            f.url(),
            "Access-Control-Allow-Origin: * together with Allow-Credentials: true",
        ));
    } else {
        out.push(Finding::new(
            "cors-wildcard",
            "CORS allows any origin",
            Severity::Low,
            f.url(),
            "Access-Control-Allow-Origin: *",
        ));
    }
}

fn rule_server_banner(f: &HttpFlow, out: &mut Vec<Finding>) {
    let base = format!("{}://{}", f.scheme, f.host);
    for h in ["server", "x-powered-by"] {
        if let Some(v) = f.resp_header(h) {
            // 任何技术栈横幅都报(Info);含数字(版本号)时风险更高,额外标注。
            let detail = if v.chars().any(|c| c.is_ascii_digit()) {
                format!("{h}: {v} — version exposed")
            } else {
                format!("{h}: {v}")
            };
            out.push(Finding::new(
                "tech-disclosure",
                "Technology / version disclosure",
                Severity::Info,
                base.clone(),
                detail,
            ));
        }
    }
}

/// 查询串里疑似敏感参数名(凭据 / 令牌)。
const SENSITIVE_PARAMS: [&str; 9] = [
    "password",
    "passwd",
    "pwd",
    "token",
    "api_key",
    "apikey",
    "secret",
    "access_token",
    "auth",
];

fn rule_sensitive_query(f: &HttpFlow, out: &mut Vec<Finding>) {
    for (k, _) in parse_query(&f.path) {
        let lk = k.to_ascii_lowercase();
        if SENSITIVE_PARAMS.iter().any(|p| lk == *p) {
            out.push(Finding::new(
                "sensitive-query-param",
                "Sensitive data in URL query",
                Severity::Medium,
                f.url(),
                format!("Parameter '{k}' carries credentials/token in the URL"),
            ));
        }
    }
}

fn rule_basic_auth_http(f: &HttpFlow, out: &mut Vec<Finding>) {
    if f.scheme != "http" {
        return;
    }
    if let Some(a) = f.req_header("authorization") {
        if a.trim_start().to_ascii_lowercase().starts_with("basic ") {
            out.push(Finding::new(
                "basic-auth-http",
                "HTTP Basic auth over plaintext",
                Severity::High,
                f.url(),
                "Authorization: Basic sent over unencrypted HTTP",
            ));
        }
    }
}

/// 报错信息特征(SQL / 各语言异常栈)。
const ERROR_SIGNATURES: [&str; 8] = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "ora-0",
    "pg_query():",
    "traceback (most recent call last)",
    "java.lang.nullpointerexception",
    "system.data.sqlclient",
];

fn rule_body_signals(f: &HttpFlow, out: &mut Vec<Finding>) {
    if f.resp_body.is_empty() {
        return;
    }
    let text = scry_decode::display_text(&f.resp_headers, &f.resp_body);
    let low = text.to_ascii_lowercase();

    if ERROR_SIGNATURES.iter().any(|s| low.contains(s)) {
        out.push(Finding::new(
            "error-disclosure",
            "Verbose error / stack trace",
            Severity::Medium,
            f.url(),
            "Response body leaks SQL error or exception stack trace",
        ));
    }

    if is_html(f) && (low.contains("<title>index of /") || low.contains(">index of /")) {
        out.push(Finding::new(
            "directory-listing",
            "Directory listing exposed",
            Severity::Medium,
            f.url(),
            "Response looks like an auto-generated directory index",
        ));
    }

    // 反射输入:查询参数值原样出现在 HTML 响应里(潜在反射型 XSS)。
    if is_html(f) {
        for (k, v) in parse_query(&f.path) {
            if v.len() >= 4 && v.chars().any(|c| c.is_ascii_alphabetic()) && text.contains(&v) {
                out.push(Finding::new(
                    "reflected-input",
                    "Reflected parameter in response",
                    Severity::Medium,
                    f.url(),
                    format!("Value of '{k}' is reflected verbatim — test for XSS"),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn html_resp(scheme: &str, headers: Vec<(&str, &str)>, body: &str) -> HttpFlow {
        let mut rh: Vec<(String, String)> = headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        if !rh.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
            rh.push(("Content-Type".to_string(), "text/html".to_string()));
        }
        HttpFlow::request("GET", scheme, "ex.com", if scheme == "https" { 443 } else { 80 }, "/", vec![], vec![])
            .with_response(200, rh, body.as_bytes().to_vec(), 10)
    }

    fn ids(fs: &[Finding]) -> Vec<&'static str> {
        fs.iter().map(|f| f.rule_id).collect()
    }

    #[test]
    fn missing_security_headers_on_html() {
        let f = html_resp("https", vec![], "<html></html>");
        let ids = ids(&scan_flow(&f));
        assert!(ids.contains(&"missing-hsts"));
        assert!(ids.contains(&"missing-xcto"));
        assert!(ids.contains(&"missing-csp"));
        assert!(ids.contains(&"clickjacking"));
    }

    #[test]
    fn full_headers_clean() {
        let f = html_resp(
            "https",
            vec![
                ("Strict-Transport-Security", "max-age=31536000"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Content-Security-Policy", "default-src 'self'"),
            ],
            "<html></html>",
        );
        let ids = ids(&scan_flow(&f));
        assert!(!ids.contains(&"missing-hsts"));
        assert!(!ids.contains(&"missing-csp"));
        assert!(!ids.contains(&"clickjacking"));
    }

    #[test]
    fn cookie_flag_findings() {
        let f = HttpFlow::request("GET", "https", "ex.com", 443, "/", vec![], vec![]).with_response(
            200,
            vec![
                ("Content-Type".to_string(), "text/html".to_string()),
                ("Set-Cookie".to_string(), "sid=abc; Path=/".to_string()),
            ],
            b"<html></html>".to_vec(),
            5,
        );
        let ids = ids(&scan_flow(&f));
        assert!(ids.contains(&"cookie-no-secure"));
        assert!(ids.contains(&"cookie-no-httponly"));
        assert!(ids.contains(&"cookie-no-samesite"));
    }

    #[test]
    fn cookie_over_http_is_high() {
        let f = HttpFlow::request("GET", "http", "ex.com", 80, "/", vec![], vec![]).with_response(
            200,
            vec![("Set-Cookie".to_string(), "sid=abc; Secure; HttpOnly; SameSite=Lax".to_string())],
            vec![],
            5,
        );
        let f2 = scan_flow(&f);
        assert!(ids(&f2).contains(&"cookie-over-http"));
        assert_eq!(
            f2.iter().find(|x| x.rule_id == "cookie-over-http").unwrap().severity,
            Severity::High
        );
    }

    #[test]
    fn cors_wildcard_with_credentials() {
        let f = HttpFlow::request("GET", "https", "ex.com", 443, "/api", vec![], vec![]).with_response(
            200,
            vec![
                ("Access-Control-Allow-Origin".to_string(), "*".to_string()),
                ("Access-Control-Allow-Credentials".to_string(), "true".to_string()),
            ],
            vec![],
            5,
        );
        assert!(ids(&scan_flow(&f)).contains(&"cors-wildcard-credentials"));
    }

    #[test]
    fn sensitive_param_and_basic_auth() {
        let f = HttpFlow::request(
            "GET",
            "http",
            "ex.com",
            80,
            "/login?user=x&password=secret",
            vec![("Authorization".to_string(), "Basic dXNlcjpwYXNz".to_string())],
            vec![],
        );
        let ids = ids(&scan_flow(&f));
        assert!(ids.contains(&"sensitive-query-param"));
        assert!(ids.contains(&"basic-auth-http"));
    }

    #[test]
    fn error_disclosure_and_reflection() {
        let body = "<html>Hello searchterm123 — You have an error in your SQL syntax near</html>";
        let f = html_resp("https", vec![], body);
        // 给个会被反射的查询参数
        let f = HttpFlow {
            path: "/q?term=searchterm123".to_string(),
            ..f
        };
        let ids = ids(&scan_flow(&f));
        assert!(ids.contains(&"error-disclosure"));
        assert!(ids.contains(&"reflected-input"));
    }

    #[test]
    fn tech_disclosure_reports_any_banner() {
        // 带版本号 → 报。
        let f = HttpFlow::request("GET", "https", "ex.com", 443, "/", vec![], vec![]).with_response(
            200,
            vec![
                ("Content-Type".to_string(), "text/html".to_string()),
                ("Server".to_string(), "nginx/1.21.6".to_string()),
            ],
            b"<html></html>".to_vec(),
            5,
        );
        assert!(ids(&scan_flow(&f)).contains(&"tech-disclosure"));

        // 纯产品名(无版本)也报——技术栈泄露(贴近真实 CDN 流量如 Tengine/sffe)。
        let f2 = HttpFlow::request("GET", "https", "ex.com", 443, "/", vec![], vec![]).with_response(
            200,
            vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Server".to_string(), "Tengine".to_string()),
            ],
            b"{}".to_vec(),
            5,
        );
        assert!(ids(&scan_flow(&f2)).contains(&"tech-disclosure"));
    }

    #[test]
    fn security_headers_apply_to_non_html() {
        // 真实场景:JSON 接口 / 静态资源也应查主机级安全头(此前被 HTML 限制漏掉)。
        let f = HttpFlow::request("GET", "https", "api.ex.com", 443, "/v1/info", vec![], vec![])
            .with_response(
                200,
                vec![("Content-Type".to_string(), "application/json".to_string())],
                b"{\"a\":1}".to_vec(),
                5,
            );
        let ids = ids(&scan_flow(&f));
        assert!(ids.contains(&"missing-hsts")); // 任意 HTTPS 响应
        assert!(ids.contains(&"missing-xcto")); // JSON 可被嗅探
        assert!(ids.contains(&"missing-referrer-policy"));
        assert!(!ids.contains(&"missing-csp")); // CSP 仅对 HTML
        assert!(!ids.contains(&"clickjacking")); // 仅对 HTML
    }

    #[test]
    fn scan_flows_dedupes_and_sorts() {
        let f = html_resp("https", vec![], "<html></html>");
        let flows = vec![f.clone(), f.clone()];
        let res = scan_flows(&flows);
        // 同 (rule_id,url) 去重:两条相同流不应翻倍。
        let hsts = res.iter().filter(|x| x.rule_id == "missing-hsts").count();
        assert_eq!(hsts, 1);
        // 排序:严重度降序(第一条 severity >= 最后一条)。
        assert!(res.first().unwrap().severity >= res.last().unwrap().severity);
    }
}
