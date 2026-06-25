//! HTTP 请求走私(Request Smuggling)检测 —— CL.TE / TE.CL,基于 PortSwigger 的**计时**技术。
//!
//! 原理:发一个「前端按某头、后端按另一头」解析就会卡住的畸形请求 —— 若目标前后端对
//! `Content-Length` / `Transfer-Encoding` 的取舍不一致(易受走私攻击),其中一端会等待永不到达的
//! 字节 → 响应**显著延迟**(接近读超时);正常服务器要么快速返回要么快速 4xx。对比基线耗时即可判定。
//!
//! 必须发**原始字节**(同时带 CL + TE、构造非常规 chunk),不能经 [`crate::build_origin_request`]
//! (它会规范化头、强制 `Connection: close`),故走底层 socket。判定 / payload 构造是纯函数、可单测。

use crate::mitm::build_client_config;
use crate::upstream::{connect_via, UpstreamProxy};
use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

/// 走私类型(前端 / 后端解析取舍的组合)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmuggleKind {
    /// 前端 `Content-Length`、后端 `Transfer-Encoding`。
    ClTe,
    /// 前端 `Transfer-Encoding`、后端 `Content-Length`。
    TeCl,
}

impl SmuggleKind {
    pub fn label(self) -> &'static str {
        match self {
            SmuggleKind::ClTe => "CL.TE",
            SmuggleKind::TeCl => "TE.CL",
        }
    }
}

/// 正常基线请求(快速返回,作往返耗时基准)。
pub fn build_baseline(host: &str, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").into_bytes()
}

/// 构造计时检测 payload(让易受攻击的 CL/TE 解析组合卡住 → 等待 → 超时延迟)。
///
/// 参考 PortSwigger「Finding HTTP request smuggling vulnerabilities via differential responses /
/// timing techniques」的经典 timing 载荷。
pub fn build_payload(kind: SmuggleKind, host: &str, path: &str) -> Vec<u8> {
    match kind {
        // CL.TE:前端用 CL=4 只转发 "1\r\nA",后端用 chunked 读到 chunk(size 1,"A")后等待下一 chunk → 卡住。
        SmuggleKind::ClTe => format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\nX"
        )
        .into_bytes(),
        // TE.CL:前端用 chunked 读到 "0\r\n\r\n" 即结束,后端用 CL=6 仍等 6 字节正文 → 卡住。
        SmuggleKind::TeCl => format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX"
        )
        .into_bytes(),
    }
}

/// 计时判定:探测请求是否「显著比基线慢且接近读超时」(后端被卡住)= 疑似走私。
pub fn judge(baseline: Duration, probe: Duration, read_timeout: Duration) -> bool {
    let delta = Duration::from_millis(5000);
    probe >= baseline + delta && probe + Duration::from_millis(500) >= read_timeout
}

/// 走私探测配置。
#[derive(Debug, Clone)]
pub struct SmuggleConfig {
    pub upstream: Option<UpstreamProxy>,
    pub connect_timeout: Duration,
    /// 读响应超时:被卡住的连接会一直读不到东西到此超时(= 延迟信号)。
    pub read_timeout: Duration,
}

impl Default for SmuggleConfig {
    fn default() -> Self {
        Self {
            upstream: None,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(8),
        }
    }
}

/// 发原始字节并计时:从开始连接到收到首字节(或读超时)的总耗时。
async fn send_raw_timed(
    host: &str,
    port: u16,
    secure: bool,
    bytes: &[u8],
    cfg: &SmuggleConfig,
) -> Result<Duration> {
    let start = Instant::now();
    let tcp = tokio::time::timeout(
        cfg.connect_timeout,
        connect_via(host, port, cfg.upstream.as_ref()),
    )
    .await??;
    let mut rbuf = [0u8; 256];
    if secure {
        let connector = TlsConnector::from(Arc::new(build_client_config()?));
        let sn = ServerName::try_from(host.to_string())?;
        let mut tls = connector.connect(sn, tcp).await?;
        tls.write_all(bytes).await?;
        tls.flush().await?;
        let _ = tokio::time::timeout(cfg.read_timeout, tls.read(&mut rbuf)).await;
    } else {
        let mut tcp = tcp;
        tcp.write_all(bytes).await?;
        tcp.flush().await?;
        let _ = tokio::time::timeout(cfg.read_timeout, tcp.read(&mut rbuf)).await;
    }
    Ok(start.elapsed())
}

/// 探测一个目标端点的 CL.TE / TE.CL 走私(计时法)。返回**疑似命中**的类型(可能为空)。
pub async fn probe(
    host: &str,
    port: u16,
    secure: bool,
    path: &str,
    cfg: &SmuggleConfig,
) -> Vec<SmuggleKind> {
    // 基线:正常请求的往返耗时(含连接 + TLS 握手,与探测同口径,差值抵消)。
    let baseline = match send_raw_timed(host, port, secure, &build_baseline(host, path), cfg).await {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let mut hits = Vec::new();
    for kind in [SmuggleKind::ClTe, SmuggleKind::TeCl] {
        if let Ok(d) =
            send_raw_timed(host, port, secure, &build_payload(kind, host, path), cfg).await
        {
            if judge(baseline, d, cfg.read_timeout) {
                hits.push(kind);
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_is_get_with_close() {
        let s = String::from_utf8(build_baseline("h.com", "/a")).unwrap();
        assert!(s.starts_with("GET /a HTTP/1.1\r\n"));
        assert!(s.contains("Host: h.com"));
        assert!(s.contains("Connection: close"));
    }

    #[test]
    fn clte_payload_has_both_length_headers() {
        let s = String::from_utf8(build_payload(SmuggleKind::ClTe, "x", "/")).unwrap();
        assert!(s.starts_with("POST / HTTP/1.1\r\n"));
        assert!(s.contains("Content-Length: 4"));
        assert!(s.contains("Transfer-Encoding: chunked"));
        // chunk 部分:size 1 + "A" + 悬挂的 "X"。
        assert!(s.ends_with("\r\n\r\n1\r\nA\r\nX"));
    }

    #[test]
    fn tecl_payload_has_both_length_headers() {
        let s = String::from_utf8(build_payload(SmuggleKind::TeCl, "x", "/")).unwrap();
        assert!(s.contains("Content-Length: 6"));
        assert!(s.contains("Transfer-Encoding: chunked"));
        assert!(s.ends_with("\r\n\r\n0\r\n\r\nX"));
    }

    #[test]
    fn judge_flags_only_significant_delay_near_timeout() {
        let to = Duration::from_secs(8);
        // 探测接近超时、远慢于基线 → 疑似。
        assert!(judge(Duration::from_millis(200), Duration::from_millis(7800), to));
        // 探测与基线相近 → 否。
        assert!(!judge(Duration::from_millis(200), Duration::from_millis(400), to));
        // 慢但没接近超时 → 否(抗慢服务器误报)。
        assert!(!judge(Duration::from_secs(2), Duration::from_secs(3), to));
    }

    #[test]
    fn labels() {
        assert_eq!(SmuggleKind::ClTe.label(), "CL.TE");
        assert_eq!(SmuggleKind::TeCl.label(), "TE.CL");
    }
}
