//! 注入点发现与变异请求构造(与 `scry_sqli::points` 同款通用原语:查询参数 + 表单字段)。
//!
//! [`build_probe`] 把某注入点的值换成给定载荷,产出一条仅请求的 [`HttpFlow`](响应清空,可直接喂
//! `scry_proxy::replay`);值放回前做百分号编码,确保含尖括号 / 引号的脚本载荷安全到达。

use scry_analyze::{form_params, parse_query, percent_decode};
use scry_core::HttpFlow;

/// 注入点所在位置。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Location {
    /// URL 查询串参数。
    Query,
    /// `application/x-www-form-urlencoded` 请求体字段。
    Body,
}

impl Location {
    pub fn label(self) -> &'static str {
        match self {
            Location::Query => "query",
            Location::Body => "body",
        }
    }
}

/// 一个候选注入点(参数名 + 原始已解码值 + 位置)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InjectionPoint {
    pub location: Location,
    pub name: String,
    pub value: String,
}

impl InjectionPoint {
    /// 展示标签,如 `query: q`。
    pub fn label(&self) -> String {
        format!("{}: {}", self.location.label(), self.name)
    }
}

/// 从一条请求里发现全部候选注入点(查询参数 + 表单字段;保序)。
pub fn injection_points(req: &HttpFlow) -> Vec<InjectionPoint> {
    let mut out = Vec::new();
    for (name, value) in parse_query(&req.path) {
        out.push(InjectionPoint {
            location: Location::Query,
            name,
            value,
        });
    }
    for (name, value) in form_params(req) {
        out.push(InjectionPoint {
            location: Location::Body,
            name,
            value,
        });
    }
    out
}

/// 把 `point` 的值替换为 `new_value`,产出仅请求的变异流(响应清空)。
pub fn build_probe(req: &HttpFlow, point: &InjectionPoint, new_value: &str) -> HttpFlow {
    let mut f = req.clone();
    f.status = 0;
    f.resp_headers.clear();
    f.resp_body.clear();
    f.duration_ms = 0;
    match point.location {
        Location::Query => f.path = set_query_value(&req.path, &point.name, new_value),
        Location::Body => {
            let body = String::from_utf8_lossy(&req.req_body);
            let new_body = set_param_value(&body, &point.name, new_value);
            f.req_body = new_body.into_bytes();
            set_content_length(&mut f.req_headers, f.req_body.len());
        }
    }
    f
}

/// query 编码:仅保留 RFC3986 unreserved,其余百分号编码。
fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 在 `a=1&b=2` 形态里替换 `target` 的值(编码后),其它保留;不存在则追加。
fn set_param_value(query: &str, target: &str, new_value: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut replaced = false;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let raw_key = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
        if percent_decode(raw_key, true) == target && !replaced {
            parts.push(format!("{raw_key}={}", encode_component(new_value)));
            replaced = true;
        } else {
            parts.push(pair.to_string());
        }
    }
    if !replaced {
        parts.push(format!(
            "{}={}",
            encode_component(target),
            encode_component(new_value)
        ));
    }
    parts.join("&")
}

/// 在 origin-form 路径里替换查询参数值(无查询串时追加)。
fn set_query_value(path: &str, target: &str, new_value: &str) -> String {
    match path.split_once('?') {
        Some((base, query)) => format!("{base}?{}", set_param_value(query, target, new_value)),
        None => format!(
            "{path}?{}={}",
            encode_component(target),
            encode_component(new_value)
        ),
    }
}

/// 设置 / 覆盖 `Content-Length`。
fn set_content_length(headers: &mut Vec<(String, String)>, len: usize) {
    if let Some(h) = headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    {
        h.1 = len.to_string();
    } else {
        headers.push(("Content-Length".to_string(), len.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_points_and_builds_probe() {
        let req = HttpFlow::request("GET", "https", "ex.com", 443, "/s?q=hi&p=2", vec![], vec![]);
        let pts = injection_points(&req);
        assert_eq!(pts.len(), 2);
        assert_eq!(pts[0].name, "q");
        let probe = build_probe(&req, &pts[0], "\"><svg/onload=alert(1)>");
        assert!(probe.path.contains("p=2"));
        // 尖括号 / 引号被编码到达。
        assert!(probe.path.contains("q=%22%3E%3Csvg"));
        assert_eq!(probe.status, 0);
    }
}
