//! 主动探测:由基准流**生成变异请求**(纯函数,不发送),并对探测响应做**命中判定**。
//!
//! 发送由 UI 侧 runner 复用 [`scry_proxy::replay`] 完成(后台 tokio);本模块只负责「构造」与「判定」,
//! 全部纯函数、可单测,确保攻击 payload 的拼装 / 命中规则可回归。

use scry_analyze::{parse_query, percent_decode};
use scry_core::HttpFlow;

use crate::types::{Finding, Severity};

/// 探测类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeKind {
    /// error-based SQL 注入(值后追加单引号)。
    SqliError,
    /// 反射型 XSS(注入唯一脚本 marker)。
    XssReflect,
    /// 路径穿越 / 本地文件包含(注入 `../../etc/passwd`)。
    PathTraversal,
}

/// 唯一 XSS 探测载荷(含可识别 marker + 未转义标签)。
const XSS_PAYLOAD: &str = "scry7h3x<svg/onload=1>";
/// 路径穿越载荷。
const TRAVERSAL_PAYLOAD: &str = "../../../../../../../../etc/passwd";

/// 一个待发送的探测:变异请求流 + 元信息。
#[derive(Clone, Debug)]
pub struct Probe {
    pub kind: ProbeKind,
    /// 被注入的参数名。
    pub param: String,
    /// 实际注入的载荷值。
    pub payload: String,
    /// 变异后的请求流(响应已清空,可直接喂 replay)。
    pub flow: HttpFlow,
}

/// 由基准流生成主动探测请求(当前覆盖**查询参数**注入点)。
pub fn generate_probes(base: &HttpFlow) -> Vec<Probe> {
    let mut out = Vec::new();
    for (k, v) in parse_query(&base.path) {
        for kind in [
            ProbeKind::SqliError,
            ProbeKind::XssReflect,
            ProbeKind::PathTraversal,
        ] {
            let payload = match kind {
                ProbeKind::SqliError => format!("{v}'"),
                ProbeKind::XssReflect => XSS_PAYLOAD.to_string(),
                ProbeKind::PathTraversal => TRAVERSAL_PAYLOAD.to_string(),
            };
            let new_path = mutate_query(&base.path, &k, &payload);
            let mut flow = base.clone();
            flow.path = new_path;
            flow.status = 0;
            flow.resp_headers.clear();
            flow.resp_body.clear();
            flow.duration_ms = 0;
            out.push(Probe {
                kind,
                param: k.clone(),
                payload,
                flow,
            });
        }
    }
    out
}

/// 对探测响应做命中判定 → 命中则给一条 [`Finding`]。
pub fn evaluate(probe: &Probe, resp: &HttpFlow) -> Option<Finding> {
    let text = if resp.resp_body.is_empty() {
        String::new()
    } else {
        scry_decode::display_text(&resp.resp_headers, &resp.resp_body)
    };
    let low = text.to_ascii_lowercase();
    match probe.kind {
        ProbeKind::SqliError => SQLI_SIGNATURES
            .iter()
            .any(|s| low.contains(s))
            .then(|| {
                Finding::new(
                    "active-sqli",
                    "SQL injection (error-based)",
                    Severity::High,
                    resp.url(),
                    format!("Param '{}' triggers a SQL error when a quote is appended", probe.param),
                )
            }),
        ProbeKind::XssReflect => {
            if !text.contains("<svg/onload") {
                return None;
            }
            // 关键:反射 ≠ XSS。只有响应是 **HTML** 才会被浏览器当标签执行 → 判 High;
            // JSON / 纯文本等非 HTML 上下文里的反射不可利用,降为 Info(提示去核实 sink),避免误报。
            let is_html = resp
                .content_type()
                .map(|ct| ct.to_ascii_lowercase().contains("html"))
                .unwrap_or(false);
            if is_html {
                Some(Finding::new(
                    "active-xss",
                    "Reflected XSS",
                    Severity::High,
                    resp.url(),
                    format!(
                        "Param '{}' reflects the script payload unescaped in an HTML response",
                        probe.param
                    ),
                ))
            } else {
                Some(Finding::new(
                    "active-reflection",
                    "Reflected value (non-HTML)",
                    Severity::Info,
                    resp.url(),
                    format!(
                        "Param '{}' is reflected unescaped, but the response is {} (not HTML) — verify the sink before calling it XSS",
                        probe.param,
                        resp.content_type().unwrap_or("an unknown type")
                    ),
                ))
            }
        }
        ProbeKind::PathTraversal => {
            let hit = text.contains("root:x:0:0") || (low.contains("root:") && low.contains(":0:0:"));
            hit.then(|| {
                Finding::new(
                    "active-traversal",
                    "Path traversal / LFI",
                    Severity::Critical,
                    resp.url(),
                    format!("Param '{}' returns /etc/passwd contents", probe.param),
                )
            })
        }
    }
}

/// SQL 报错特征(命中即认为 error-based 注入)。
const SQLI_SIGNATURES: [&str; 6] = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "ora-0",
    "pg_query():",
    "sqlite3::",
];

/// query 编码:仅保留 RFC3986 unreserved,其余百分号编码(确保 payload 安全到达参数)。
fn encode_query_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 把 `path` 查询串里 `target_key` 的值替换为 `new_value`(编码后),保留其它参数原样。
/// 无查询串时追加一个该参数。
fn mutate_query(path: &str, target_key: &str, new_value: &str) -> String {
    let (base, query) = match path.split_once('?') {
        Some((b, q)) => (b, q),
        None => {
            return format!(
                "{path}?{}={}",
                encode_query_component(target_key),
                encode_query_component(new_value)
            )
        }
    };
    let mut parts: Vec<String> = Vec::new();
    let mut replaced = false;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let raw_key = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
        let dec_key = percent_decode(raw_key, true);
        if dec_key == target_key && !replaced {
            parts.push(format!("{raw_key}={}", encode_query_component(new_value)));
            replaced = true;
        } else {
            parts.push(pair.to_string());
        }
    }
    format!("{base}?{}", parts.join("&"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> HttpFlow {
        HttpFlow::request(
            "GET",
            "https",
            "ex.com",
            443,
            "/search?q=hello&page=2",
            vec![],
            vec![],
        )
    }

    #[test]
    fn generates_three_kinds_per_param() {
        let probes = generate_probes(&base());
        // 2 个参数 × 3 种探测 = 6。
        assert_eq!(probes.len(), 6);
        assert_eq!(
            probes.iter().filter(|p| p.kind == ProbeKind::SqliError).count(),
            2
        );
    }

    #[test]
    fn mutation_preserves_other_params() {
        let probes = generate_probes(&base());
        // 注入 q 的 SQLi 探测:page=2 应保留,q 值变成 hello' 的编码。
        let p = probes
            .iter()
            .find(|p| p.kind == ProbeKind::SqliError && p.param == "q")
            .unwrap();
        assert!(p.flow.path.contains("page=2"));
        assert!(p.flow.path.contains("q=hello%27"));
        // 变异流响应已清空。
        assert_eq!(p.flow.status, 0);
    }

    #[test]
    fn evaluate_detects_sqli() {
        let probes = generate_probes(&base());
        let p = probes.iter().find(|p| p.kind == ProbeKind::SqliError).unwrap();
        let resp = p.flow.clone().with_response(
            500,
            vec![("Content-Type".to_string(), "text/html".to_string())],
            b"You have an error in your SQL syntax; check the manual".to_vec(),
            10,
        );
        let finding = evaluate(p, &resp).unwrap();
        assert_eq!(finding.rule_id, "active-sqli");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn evaluate_detects_xss_and_traversal() {
        let probes = generate_probes(&base());
        let xss = probes.iter().find(|p| p.kind == ProbeKind::XssReflect).unwrap();
        let resp = xss.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "text/html".to_string())],
            b"<html>scry7h3x<svg/onload=1></html>".to_vec(),
            10,
        );
        assert_eq!(evaluate(xss, &resp).unwrap().rule_id, "active-xss");

        let trav = probes.iter().find(|p| p.kind == ProbeKind::PathTraversal).unwrap();
        let resp2 = trav.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "text/plain".to_string())],
            b"root:x:0:0:root:/root:/bin/bash\n".to_vec(),
            10,
        );
        let f = evaluate(trav, &resp2).unwrap();
        assert_eq!(f.rule_id, "active-traversal");
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn xss_reflection_in_json_is_info_not_high() {
        // 实战教训(apizero.cn /api/video-parse):值被原样回显但 content-type=application/json,
        // 浏览器不当 HTML 渲染 → 不可利用,应降为 Info「反射」而非 High「XSS」。
        let probes = generate_probes(&base());
        let xss = probes.iter().find(|p| p.kind == ProbeKind::XssReflect).unwrap();
        let resp = xss.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "application/json".to_string())],
            b"{\"got\":\"scry7h3x<svg/onload=1>\"}".to_vec(),
            10,
        );
        let f = evaluate(xss, &resp).unwrap();
        assert_eq!(f.rule_id, "active-reflection");
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn evaluate_no_false_positive_on_clean_response() {
        let probes = generate_probes(&base());
        let p = &probes[0];
        let resp = p.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "text/html".to_string())],
            b"<html>all good</html>".to_vec(),
            10,
        );
        assert!(evaluate(p, &resp).is_none());
    }
}
