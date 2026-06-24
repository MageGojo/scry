//! history 过滤条件 + 全文搜索。
//!
//! 全文搜索覆盖 url / 请求头 / 响应头 / **解码后**的请求与响应 body(用 `scry_decode::body_text`
//! 解压 + charset 还原,因此 gzip / GBK 等也能搜到明文)。

use scry_core::HttpFlow;
use scry_decode::{body_text, content_kind, ContentKind};

/// history 过滤条件;所有字段为「不限」(None / 空)时放行全部。
#[derive(Debug, Clone, Default)]
pub struct FlowFilter {
    /// host 子串(大小写不敏感)。
    pub host_contains: Option<String>,
    /// 限定请求方法(大小写不敏感,如 `["GET","POST"]`);空 = 不限。
    pub methods: Vec<String>,
    /// 状态码下界 / 上界(含)。
    pub status_min: Option<u16>,
    pub status_max: Option<u16>,
    /// 限定响应内容类别;空 = 不限。
    pub kinds: Vec<ContentKind>,
    /// 全文搜索关键字(在 url / 头 / 解码后 body 里找,大小写不敏感)。
    pub query: Option<String>,
}

impl FlowFilter {
    /// 判断一条流是否满足全部条件。
    pub fn matches(&self, flow: &HttpFlow) -> bool {
        if let Some(h) = &self.host_contains {
            if !flow
                .host
                .to_ascii_lowercase()
                .contains(&h.to_ascii_lowercase())
            {
                return false;
            }
        }
        if !self.methods.is_empty()
            && !self
                .methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&flow.method))
        {
            return false;
        }
        if let Some(lo) = self.status_min {
            if flow.status < lo {
                return false;
            }
        }
        if let Some(hi) = self.status_max {
            if flow.status > hi {
                return false;
            }
        }
        if !self.kinds.is_empty() && !self.kinds.contains(&content_kind(&flow.resp_headers)) {
            return false;
        }
        if let Some(q) = &self.query {
            if !flow_contains(flow, q) {
                return false;
            }
        }
        true
    }
}

/// 在一条流的 url / 头 / 解码后 body 里(大小写不敏感)查找关键字;空关键字视为命中。
pub fn flow_contains(flow: &HttpFlow, needle: &str) -> bool {
    let n = needle.to_ascii_lowercase();
    if n.is_empty() {
        return true;
    }
    if flow.url().to_ascii_lowercase().contains(&n) {
        return true;
    }
    if headers_contain(&flow.req_headers, &n) || headers_contain(&flow.resp_headers, &n) {
        return true;
    }
    // body 先解码(解压 + charset)再找,gzip/GBK 等也能命中明文。
    if body_text(&flow.req_headers, &flow.req_body)
        .to_ascii_lowercase()
        .contains(&n)
    {
        return true;
    }
    if body_text(&flow.resp_headers, &flow.resp_body)
        .to_ascii_lowercase()
        .contains(&n)
    {
        return true;
    }
    false
}

fn headers_contain(headers: &[(String, String)], needle_lower: &str) -> bool {
    headers.iter().any(|(k, v)| {
        k.to_ascii_lowercase().contains(needle_lower) || v.to_ascii_lowercase().contains(needle_lower)
    })
}

/// 用过滤条件筛一批流,返回命中的引用(保持原顺序)。
pub fn filter_flows<'a>(flows: &'a [HttpFlow], filter: &FlowFilter) -> Vec<&'a HttpFlow> {
    flows.iter().filter(|f| filter.matches(f)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn sample() -> Vec<HttpFlow> {
        vec![
            HttpFlow::request("GET", "https", "api.example.com", 443, "/users", vec![], vec![])
                .with_response(
                    200,
                    vec![("Content-Type".into(), "application/json".into())],
                    br#"{"name":"alice"}"#.to_vec(),
                    10,
                ),
            HttpFlow::request("POST", "https", "login.example.com", 443, "/auth", vec![], b"pw=secret".to_vec())
                .with_response(
                    401,
                    vec![("Content-Type".into(), "text/html".into())],
                    b"<html>denied</html>".to_vec(),
                    20,
                ),
            HttpFlow::request("GET", "http", "cdn.other.com", 80, "/a.png", vec![], vec![])
                .with_response(
                    200,
                    vec![("Content-Type".into(), "image/png".into())],
                    vec![0x89, 0x50, 0x4e, 0x47],
                    5,
                ),
        ]
    }

    #[test]
    fn empty_filter_passes_all() {
        let flows = sample();
        let f = FlowFilter::default();
        assert_eq!(filter_flows(&flows, &f).len(), 3);
    }

    #[test]
    fn host_method_status_kind_filters() {
        let flows = sample();

        let by_host = FlowFilter {
            host_contains: Some("example.com".into()),
            ..Default::default()
        };
        assert_eq!(filter_flows(&flows, &by_host).len(), 2);

        let by_method = FlowFilter {
            methods: vec!["post".into()],
            ..Default::default()
        };
        assert_eq!(filter_flows(&flows, &by_method).len(), 1);

        let by_status = FlowFilter {
            status_min: Some(400),
            status_max: Some(499),
            ..Default::default()
        };
        assert_eq!(filter_flows(&flows, &by_status).len(), 1);

        let by_kind = FlowFilter {
            kinds: vec![ContentKind::Image],
            ..Default::default()
        };
        assert_eq!(filter_flows(&flows, &by_kind).len(), 1);
    }

    #[test]
    fn fulltext_search_url_and_body() {
        let flows = sample();
        // body 关键字
        let q = FlowFilter {
            query: Some("alice".into()),
            ..Default::default()
        };
        assert_eq!(filter_flows(&flows, &q).len(), 1);
        // url 关键字
        let q2 = FlowFilter {
            query: Some("/auth".into()),
            ..Default::default()
        };
        assert_eq!(filter_flows(&flows, &q2).len(), 1);
    }

    #[test]
    fn fulltext_search_decodes_gzip_body() {
        let plain = b"sensitive-token-xyz";
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(plain).unwrap();
        let gz = e.finish().unwrap();
        let f = HttpFlow::request("GET", "https", "h", 443, "/", vec![], vec![]).with_response(
            200,
            vec![
                ("Content-Type".into(), "text/plain".into()),
                ("Content-Encoding".into(), "gzip".into()),
            ],
            gz,
            1,
        );
        assert!(flow_contains(&f, "sensitive-token"));
    }
}
