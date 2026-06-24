//! 把一条 [`HttpFlow`] 压成轻量摘要,供 history 表 / 快速浏览(不持有大 body)。

use scry_core::HttpFlow;
use scry_decode::{content_kind, ContentKind};

/// 一条流的摘要(派生信息,不含 body 字节)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSummary {
    pub ts: i64,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub status: u16,
    /// 响应 MIME 主体(去掉 `; charset=` 等参数,小写);无则空串。
    pub mime: String,
    /// 按响应 Content-Type 归类(给 UI 着色 / 决定是否当文本展示)。
    pub kind: ContentKind,
    pub req_body_len: usize,
    pub resp_body_len: usize,
    pub duration_ms: u64,
    /// 响应尚未到达(`status == 0`,save-first 的半条流)。
    pub pending: bool,
}

impl FlowSummary {
    /// 由一条流派生摘要。
    pub fn of(flow: &HttpFlow) -> Self {
        let mime = flow
            .content_type()
            .map(|ct| {
                ct.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        Self {
            ts: flow.ts,
            method: flow.method.clone(),
            scheme: flow.scheme.clone(),
            host: flow.host.clone(),
            port: flow.port,
            path: flow.path.clone(),
            status: flow.status,
            mime,
            kind: content_kind(&flow.resp_headers),
            req_body_len: flow.req_body.len(),
            resp_body_len: flow.resp_body.len(),
            duration_ms: flow.duration_ms,
            pending: flow.status == 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_extracts_mime_and_kind() {
        let f = HttpFlow::request("GET", "https", "api.example.com", 443, "/v1/x", vec![], vec![])
            .with_response(
                200,
                vec![(
                    "Content-Type".to_string(),
                    "application/json; charset=utf-8".to_string(),
                )],
                br#"{"ok":true}"#.to_vec(),
                42,
            );
        let s = FlowSummary::of(&f);
        assert_eq!(s.method, "GET");
        assert_eq!(s.host, "api.example.com");
        assert_eq!(s.status, 200);
        assert_eq!(s.mime, "application/json");
        assert_eq!(s.kind, ContentKind::Json);
        assert_eq!(s.resp_body_len, 11);
        assert_eq!(s.duration_ms, 42);
        assert!(!s.pending);
    }

    #[test]
    fn pending_flow_when_no_response() {
        let f = HttpFlow::request("GET", "http", "h", 80, "/", vec![], vec![]);
        let s = FlowSummary::of(&f);
        assert!(s.pending);
        assert_eq!(s.status, 0);
        assert_eq!(s.mime, "");
        assert_eq!(s.kind, ContentKind::Binary);
    }
}
