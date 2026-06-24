//! 注入点发现与变异请求构造。
//!
//! 注入点 = 一个可被替换值的参数(当前覆盖**查询参数** + **`x-www-form-urlencoded` 表单字段**)。
//! [`build_probe`] 把某注入点的值换成给定载荷,产出一条**仅请求**的 [`HttpFlow`](响应清空,
//! 可直接喂 `scry_proxy::replay`)。值在放回前做百分号编码,确保含引号 / 空格 / 括号的注入串安全到达。

use scry_analyze::{form_params, parse_query, percent_decode};
use scry_core::HttpFlow;

/// 注入点所在位置。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Location {
    /// URL 查询串参数(`?a=1`)。
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
    /// 原始值(已百分号解码;构造载荷时在它后面拼注入串)。
    pub value: String,
}

impl InjectionPoint {
    /// 展示标签,如 `query: id`。
    pub fn label(&self) -> String {
        format!("{}: {}", self.location.label(), self.name)
    }
}

/// 从一条请求里发现全部候选注入点(查询参数 + 表单字段;保序、可含同名)。
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

/// query 编码:仅保留 RFC3986 unreserved 字符,其余百分号编码(确保注入串原样到达参数)。
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

/// 在 `a=1&b=2` 形态的查询串里,把 `target` 的值替换为编码后的 `new_value`;
/// 其它参数原样保留;`target` 不存在则追加一项。
fn set_param_value(query: &str, target: &str, new_value: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut replaced = false;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let raw_key = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
        let dec_key = percent_decode(raw_key, true);
        if dec_key == target && !replaced {
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

/// 设置 / 覆盖 `Content-Length` 头为 `len`(改了请求体后必须更新,否则上游按旧长度截断)。
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

    fn get_flow() -> HttpFlow {
        HttpFlow::request("GET", "https", "ex.com", 443, "/item?id=7&cat=books", vec![], vec![])
    }

    fn post_form() -> HttpFlow {
        HttpFlow::request(
            "POST",
            "https",
            "ex.com",
            443,
            "/login",
            vec![(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            )],
            b"user=admin&pass=secret".to_vec(),
        )
    }

    #[test]
    fn finds_query_and_body_points() {
        let q = injection_points(&get_flow());
        assert_eq!(q.len(), 2);
        assert_eq!(q[0].location, Location::Query);
        assert_eq!(q[0].name, "id");
        assert_eq!(q[0].value, "7");

        let f = injection_points(&post_form());
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|p| p.location == Location::Body));
        assert_eq!(f[0].name, "user");
        assert_eq!(f[1].value, "secret");
    }

    #[test]
    fn build_probe_query_encodes_and_keeps_others() {
        let req = get_flow();
        let pt = &injection_points(&req)[0]; // id
        let probe = build_probe(&req, pt, "7' AND 1=1-- -");
        // 其它参数保留
        assert!(probe.path.contains("cat=books"));
        // 注入串被编码(空格 → %20,引号 → %27)
        assert!(probe.path.contains("id=7%27%20AND%201%3D1"));
        // 变异流响应已清空
        assert_eq!(probe.status, 0);
        assert!(probe.resp_body.is_empty());
    }

    #[test]
    fn build_probe_body_updates_content_length() {
        let req = post_form();
        let pt = &injection_points(&req)[0]; // user
        let probe = build_probe(&req, pt, "admin' OR '1'='1");
        let body = String::from_utf8(probe.req_body.clone()).unwrap();
        assert!(body.contains("pass=secret"));
        assert!(body.contains("user=admin%27"));
        let cl = probe
            .req_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| v.clone());
        assert_eq!(cl, Some(probe.req_body.len().to_string()));
    }

    #[test]
    fn set_query_value_appends_when_missing() {
        let p = set_query_value("/x", "id", "1");
        assert_eq!(p, "/x?id=1");
    }
}
