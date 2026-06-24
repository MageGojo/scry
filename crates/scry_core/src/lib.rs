//! Scry 共享类型层:被 proxy / storage / app 共用的纯数据结构,**不含 IO**。
//!
//! 核心是 [`HttpFlow`]:一次完整的 HTTP(S) 请求 / 响应往返,既是落盘单元,也是 UI 展示单元。

use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::time::{SystemTime, UNIX_EPOCH};

/// 一个 HTTP 头部(name, value)。
pub type Header = (String, String);

/// 一次完整的 HTTP(S) 往返。
///
/// 约定:
/// - `req_*` 在收到请求时即可填充并**先落盘**;`status == 0` 表示「响应尚未到达」。
/// - body 以原始字节存储(可能是压缩 / 二进制),展示层按需解码。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpFlow {
    /// 请求发生时刻(Unix 毫秒)。
    pub ts: i64,
    pub method: String,
    /// "http" | "https"。
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// 路径 + 查询串(如 `/api/x?a=1`)。
    pub path: String,
    pub req_headers: Vec<Header>,
    pub req_body: Vec<u8>,
    /// 响应状态码;`0` = 尚未收到响应。
    pub status: u16,
    pub resp_headers: Vec<Header>,
    pub resp_body: Vec<u8>,
    /// 往返耗时(毫秒)。
    pub duration_ms: u64,
}

impl HttpFlow {
    /// 新建一条「仅请求」的流(响应留空,供 save-first)。
    pub fn request(
        method: impl Into<String>,
        scheme: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        path: impl Into<String>,
        req_headers: Vec<Header>,
        req_body: Vec<u8>,
    ) -> Self {
        Self {
            ts: now_millis(),
            method: method.into(),
            scheme: scheme.into(),
            host: host.into(),
            port,
            path: path.into(),
            req_headers,
            req_body,
            status: 0,
            resp_headers: Vec::new(),
            resp_body: Vec::new(),
            duration_ms: 0,
        }
    }

    /// 填入响应部分。
    pub fn with_response(
        mut self,
        status: u16,
        resp_headers: Vec<Header>,
        resp_body: Vec<u8>,
        duration_ms: u64,
    ) -> Self {
        self.status = status;
        self.resp_headers = resp_headers;
        self.resp_body = resp_body;
        self.duration_ms = duration_ms;
        self
    }

    /// 完整 URL(含默认端口省略规则)。
    pub fn url(&self) -> String {
        let default_port = matches!(
            (self.scheme.as_str(), self.port),
            ("http", 80) | ("https", 443)
        );
        if default_port {
            format!("{}://{}{}", self.scheme, self.host, self.path)
        } else {
            format!("{}://{}:{}{}", self.scheme, self.host, self.port, self.path)
        }
    }

    /// 去重指纹:`sha1(method | url | sha1(req_body))`。
    pub fn fingerprint(&self) -> String {
        let body_hash = sha1_hex(&self.req_body);
        sha1_hex(format!("{}|{}|{}", self.method, self.url(), body_hash).as_bytes())
    }

    /// 大小写不敏感地取某个请求头。
    pub fn req_header(&self, name: &str) -> Option<&str> {
        header_get(&self.req_headers, name)
    }

    /// 大小写不敏感地取某个响应头。
    pub fn resp_header(&self, name: &str) -> Option<&str> {
        header_get(&self.resp_headers, name)
    }

    /// 响应 `Content-Type`(若有)。
    pub fn content_type(&self) -> Option<&str> {
        self.resp_header("content-type")
    }

    /// 响应体大小(字节)。
    pub fn resp_len(&self) -> usize {
        self.resp_body.len()
    }
}

fn header_get<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// WebSocket 消息方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WsDirection {
    /// 客户端 → 服务端(出站)。
    ClientToServer,
    /// 服务端 → 客户端(入站)。
    ServerToClient,
}

impl WsDirection {
    /// 展示用箭头(▲ 出站 / ▼ 入站)。
    pub fn arrow(self) -> &'static str {
        match self {
            WsDirection::ClientToServer => "\u{25b2}",
            WsDirection::ServerToClient => "\u{25bc}",
        }
    }
}

/// 一条 WebSocket 消息(分片已聚合)。区别于请求/响应对的 [`HttpFlow`]:
/// WS 升级后是双向帧流,每条消息单向、可重复(心跳),故**不去重**。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessage {
    /// 消息时刻(Unix 毫秒)。
    pub ts: i64,
    /// 关联同一 WS 连接(握手时分配的递增序号)。
    pub conn_id: i64,
    pub host: String,
    pub path: String,
    pub direction: WsDirection,
    /// opcode 文本标签(Text/Binary/Ping/Pong/Close)。
    pub opcode: String,
    /// 消息负载(已解 mask;文本 / 二进制原始字节)。
    pub payload: Vec<u8>,
}

impl WsMessage {
    pub fn new(
        conn_id: i64,
        host: impl Into<String>,
        path: impl Into<String>,
        direction: WsDirection,
        opcode: impl Into<String>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            ts: now_millis(),
            conn_id,
            host: host.into(),
            path: path.into(),
            direction,
            opcode: opcode.into(),
            payload,
        }
    }
}

/// 当前时间(Unix 毫秒)。
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 计算字节串的 SHA-1 十六进制摘要。
pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    let digest = h.finalize();
    let mut out = String::with_capacity(40);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_omits_default_port() {
        let f = HttpFlow::request("GET", "https", "example.com", 443, "/a", vec![], vec![]);
        assert_eq!(f.url(), "https://example.com/a");
    }

    #[test]
    fn url_keeps_custom_port() {
        let f = HttpFlow::request("GET", "http", "example.com", 8080, "/a", vec![], vec![]);
        assert_eq!(f.url(), "http://example.com:8080/a");
    }

    #[test]
    fn fingerprint_is_stable_and_distinct() {
        let a = HttpFlow::request("GET", "https", "h", 443, "/x", vec![], b"body".to_vec());
        let b = HttpFlow::request("GET", "https", "h", 443, "/x", vec![], b"body".to_vec());
        let c = HttpFlow::request("POST", "https", "h", 443, "/x", vec![], b"body".to_vec());
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_ne!(a.fingerprint(), c.fingerprint());
    }
}
