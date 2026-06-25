//! HTTP 竞态 / single-packet 攻击(对标 Burp Repeater「并行发送组」/ Turbo Intruder)。
//!
//! 竞态类漏洞(超额提现、优惠券复用、限购击穿、TOCTOU)只有把**多个相同请求挤进极小的时间
//! 窗口**才能稳定触发。本模块实现两种发送方式:
//!
//! - [`RaceMode::LastByteSync`](最后字节同步,**默认 / single-packet 精髓**):先并发建立 N 条连接、
//!   各自把请求**写到只剩最后 1 个字节**(服务器已收到几乎完整的请求,只差扳机),再用一道
//!   [`tokio::sync::Barrier`] 等所有连接就绪,**同时**放出最后那个字节 → N 个请求几乎同一刻被后端
//!   开始处理。这是 HTTP/1.1 上最可靠的竞态手法(Burp「单包攻击」的 h1 等价物)。
//! - [`RaceMode::Parallel`](朴素并行):预连接后同时发**完整**请求,作为对「拆分/分块敏感」端点的兜底。
//!
//! 发送走底层 socket(明文直接 TCP / HTTPS 走与抓包同一套 [`build_client_config`] 的 rustls),
//! 经设置页上游代理出网。判定 [`summarize`] 是纯函数、可单测:响应**不一致**(状态码或长度不全相同)
//! = 疑似竞态命中,**需人工确认**(竞态本身具有偶发性)。
//!
//! ⚠️ 会向目标真实并发发包,**只对你已获授权的目标使用**。

use crate::mitm::{build_client_config, read_message};
use crate::replay::ReplayRequest;
use crate::upstream::{connect_via, UpstreamProxy};
use anyhow::Result;
use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Barrier;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

/// 并发连接数上限(防误填把目标打爆 + 控资源)。
pub const RACE_MAX: usize = 64;

/// 竞态发送方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaceMode {
    /// 最后字节同步(single-packet 精髓):withhold 最后 1 字节,barrier 后同时放。
    LastByteSync,
    /// 朴素并行:预连接后同时发完整请求。
    Parallel,
}

impl RaceMode {
    pub fn label(self) -> &'static str {
        match self {
            RaceMode::LastByteSync => "last-byte-sync",
            RaceMode::Parallel => "parallel",
        }
    }
}

/// 一路竞态请求的结果。
#[derive(Debug, Clone)]
pub struct RaceResult {
    /// 第几路(0..n),便于排序对齐。
    pub idx: usize,
    /// 响应状态码(0 = 出错,见 `error`)。
    pub status: u16,
    /// 响应体字节数。
    pub body_len: usize,
    /// 从 barrier 放行到收到完整响应的毫秒数(同步质量参考)。
    pub elapsed_ms: u64,
    /// 出错信息(连接 / 握手 / 读响应失败);成功为 `None`。
    pub error: Option<String>,
}

/// 竞态发送配置。
#[derive(Debug, Clone)]
pub struct RaceConfig {
    pub mode: RaceMode,
    /// 上游代理(与抓包 / 重放同源);None = 直连。
    pub upstream: Option<UpstreamProxy>,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
}

impl Default for RaceConfig {
    fn default() -> Self {
        Self {
            mode: RaceMode::LastByteSync,
            upstream: None,
            connect_timeout: Duration::from_secs(15),
            read_timeout: Duration::from_secs(30),
        }
    }
}

/// 对一组竞态结果的统计判定(纯函数,可单测)。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RaceSummary {
    /// 总路数。
    pub total: usize,
    /// 成功拿到响应的路数。
    pub ok: usize,
    /// 出错路数。
    pub errors: usize,
    /// 各状态码出现次数(按出现次数降序、状态码升序)。
    pub status_counts: Vec<(u16, usize)>,
    /// 成功响应里不同 body 长度的种类数。
    pub distinct_len: usize,
    /// 响应**不一致**(状态码或长度不全相同)= 疑似竞态,需人工确认。
    pub diverged: bool,
    /// 最快与最慢响应到达的毫秒差(越小同步越好)。
    pub window_ms: u64,
}

/// 统计一组竞态结果(纯函数)。
pub fn summarize(results: &[RaceResult]) -> RaceSummary {
    let total = results.len();
    let oks: Vec<&RaceResult> = results.iter().filter(|r| r.error.is_none()).collect();
    let ok = oks.len();
    let errors = total - ok;

    let mut counts: BTreeMap<u16, usize> = BTreeMap::new();
    for r in &oks {
        *counts.entry(r.status).or_default() += 1;
    }
    let mut status_counts: Vec<(u16, usize)> = counts.into_iter().collect();
    status_counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    let mut lens: Vec<usize> = oks.iter().map(|r| r.body_len).collect();
    lens.sort_unstable();
    lens.dedup();
    let distinct_len = lens.len();

    // (状态码, 长度)对去重 > 1 → 响应有差异 = 疑似竞态。
    let mut pairs: Vec<(u16, usize)> = oks.iter().map(|r| (r.status, r.body_len)).collect();
    pairs.sort_unstable();
    pairs.dedup();
    let diverged = pairs.len() > 1;

    let window_ms = if ok > 0 {
        let mn = oks.iter().map(|r| r.elapsed_ms).min().unwrap_or(0);
        let mx = oks.iter().map(|r| r.elapsed_ms).max().unwrap_or(0);
        mx.saturating_sub(mn)
    } else {
        0
    };

    RaceSummary {
        total,
        ok,
        errors,
        status_counts,
        distinct_len,
        diverged,
        window_ms,
    }
}

/// 计算「先写多少 / 留多少当扳机」的切分点:最后字节同步 = 留最后 1 字节;并行 = 全部一次性发。
fn split_point(len: usize, mode: RaceMode) -> usize {
    match mode {
        RaceMode::LastByteSync if len > 1 => len - 1,
        _ => 0,
    }
}

/// 一路连接(明文 TCP / TLS),手动委托 AsyncRead/AsyncWrite 以便跨 barrier 持有同一连接。
enum Conn {
    Plain(TcpStream),
    // TlsStream 体积大,装箱避免 `large_enum_variant`。
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_flush(cx),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// 单路:连接 + (TLS 握手) + 写 head(留扳机)→ barrier 同步 → 放扳机 → 读响应。
#[allow(clippy::too_many_arguments)]
async fn race_conn(
    idx: usize,
    host: String,
    port: u16,
    secure: bool,
    head: Arc<Vec<u8>>,
    tail: Arc<Vec<u8>>,
    upstream: Option<UpstreamProxy>,
    connector: Option<TlsConnector>,
    connect_timeout: Duration,
    read_timeout: Duration,
    barrier: Arc<Barrier>,
) -> RaceResult {
    let err = |e: String| RaceResult {
        idx,
        status: 0,
        body_len: 0,
        elapsed_ms: 0,
        error: Some(e),
    };

    // ── 第一阶段:建连 + 握手 + 写到只剩扳机字节 ──
    let primed: Result<Conn> = async {
        let tcp = tokio::time::timeout(connect_timeout, connect_via(&host, port, upstream.as_ref()))
            .await??;
        if secure {
            let connector = connector
                .clone()
                .ok_or_else(|| anyhow::anyhow!("缺少 TLS connector"))?;
            let sn = ServerName::try_from(host.clone())?;
            let mut tls = connector.connect(sn, tcp).await?;
            if !head.is_empty() {
                tls.write_all(&head).await?;
                tls.flush().await?;
            }
            Ok(Conn::Tls(Box::new(tls)))
        } else {
            let mut tcp = tcp;
            if !head.is_empty() {
                tcp.write_all(&head).await?;
                tcp.flush().await?;
            }
            Ok(Conn::Plain(tcp))
        }
    }
    .await;

    // 无论成败都必须到 barrier 报到一次(否则其余 N-1 路会在 barrier 上死等)。
    let mut stream = match primed {
        Ok(c) => c,
        Err(e) => {
            barrier.wait().await;
            return err(format!("{e:#}"));
        }
    };

    // ── 同步点:所有连接就绪后一起放扳机 ──
    barrier.wait().await;
    let start = Instant::now();
    let fired: Result<(u16, usize)> = async {
        stream.write_all(&tail).await?;
        stream.flush().await?;
        let msg = tokio::time::timeout(read_timeout, read_message(&mut stream, true)).await??;
        Ok((msg.status, msg.body.len()))
    }
    .await;

    match fired {
        Ok((status, body_len)) => RaceResult {
            idx,
            status,
            body_len,
            elapsed_ms: start.elapsed().as_millis() as u64,
            error: None,
        },
        Err(e) => RaceResult {
            idx,
            status: 0,
            body_len: 0,
            elapsed_ms: start.elapsed().as_millis() as u64,
            error: Some(format!("{e:#}")),
        },
    }
}

/// 对一个请求发起 `count` 路竞态(按 `cfg.mode` 同步),返回按 `idx` 排序的各路结果。
///
/// 需在 tokio 运行时内调用(内部 [`tokio::spawn`] 多路并发)。
pub async fn run_race(req: &ReplayRequest, count: usize, cfg: &RaceConfig) -> Vec<RaceResult> {
    let n = count.clamp(1, RACE_MAX);
    let wire = req.to_wire();
    if wire.is_empty() {
        return Vec::new();
    }
    let sp = split_point(wire.len(), cfg.mode);
    let head = Arc::new(wire[..sp].to_vec());
    let tail = Arc::new(wire[sp..].to_vec());
    let barrier = Arc::new(Barrier::new(n));

    // HTTPS 复用与抓包同一套 rustls 客户端配置;失败则各路自报错(不让整批 panic)。
    let connector = if req.is_https() {
        build_client_config()
            .ok()
            .map(|c| TlsConnector::from(Arc::new(c)))
    } else {
        None
    };

    let mut handles = Vec::with_capacity(n);
    for idx in 0..n {
        let host = req.host.clone();
        let port = req.port;
        let secure = req.is_https();
        let head = head.clone();
        let tail = tail.clone();
        let upstream = cfg.upstream.clone();
        let connector = connector.clone();
        let barrier = barrier.clone();
        let (ct, rt) = (cfg.connect_timeout, cfg.read_timeout);
        handles.push(tokio::spawn(async move {
            race_conn(
                idx, host, port, secure, head, tail, upstream, connector, ct, rt, barrier,
            )
            .await
        }));
    }

    let mut out = Vec::with_capacity(n);
    for (i, h) in handles.into_iter().enumerate() {
        match h.await {
            Ok(r) => out.push(r),
            Err(e) => out.push(RaceResult {
                idx: i,
                status: 0,
                body_len: 0,
                elapsed_ms: 0,
                error: Some(format!("task join 失败:{e}")),
            }),
        }
    }
    out.sort_by_key(|r| r.idx);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn ok_result(idx: usize, status: u16, body_len: usize, ms: u64) -> RaceResult {
        RaceResult {
            idx,
            status,
            body_len,
            elapsed_ms: ms,
            error: None,
        }
    }

    #[test]
    fn split_point_withholds_last_byte_only_for_sync() {
        assert_eq!(split_point(10, RaceMode::LastByteSync), 9);
        assert_eq!(split_point(1, RaceMode::LastByteSync), 0);
        assert_eq!(split_point(0, RaceMode::LastByteSync), 0);
        assert_eq!(split_point(10, RaceMode::Parallel), 0);
    }

    #[test]
    fn summarize_uniform_not_diverged() {
        let rs = vec![
            ok_result(0, 200, 12, 30),
            ok_result(1, 200, 12, 33),
            ok_result(2, 200, 12, 31),
        ];
        let s = summarize(&rs);
        assert_eq!(s.total, 3);
        assert_eq!(s.ok, 3);
        assert_eq!(s.errors, 0);
        assert!(!s.diverged);
        assert_eq!(s.distinct_len, 1);
        assert_eq!(s.status_counts, vec![(200, 3)]);
        assert_eq!(s.window_ms, 3); // 33 - 30
    }

    #[test]
    fn summarize_diverged_by_status() {
        // 5 路:2 个 200(限购击穿)+ 3 个 429,状态不一致 = 疑似竞态。
        let rs = vec![
            ok_result(0, 200, 8, 10),
            ok_result(1, 200, 8, 12),
            ok_result(2, 429, 5, 11),
            ok_result(3, 429, 5, 13),
            ok_result(4, 429, 5, 9),
        ];
        let s = summarize(&rs);
        assert!(s.diverged);
        // 按次数降序:429(3) 在前,200(2) 在后。
        assert_eq!(s.status_counts, vec![(429, 3), (200, 2)]);
    }

    #[test]
    fn summarize_diverged_by_length_same_status() {
        let rs = vec![ok_result(0, 200, 10, 5), ok_result(1, 200, 99, 6)];
        let s = summarize(&rs);
        assert!(s.diverged);
        assert_eq!(s.distinct_len, 2);
    }

    #[test]
    fn summarize_counts_errors_excluded_from_ok() {
        let rs = vec![
            ok_result(0, 200, 4, 5),
            RaceResult {
                idx: 1,
                status: 0,
                body_len: 0,
                elapsed_ms: 0,
                error: Some("connect refused".into()),
            },
        ];
        let s = summarize(&rs);
        assert_eq!(s.total, 2);
        assert_eq!(s.ok, 1);
        assert_eq!(s.errors, 1);
        assert!(!s.diverged); // 仅 1 个成功响应
    }

    /// 端到端:本地 HTTP server 接 N 条连接,run_race(最后字节同步)发 4 路,断言 4 路 200 + 服务端确实收到 4 个完整请求。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn run_race_last_byte_sync_e2e() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let n = 4usize;

        let server = tokio::spawn(async move {
            let mut served = 0usize;
            for _ in 0..n {
                let (mut sock, _) = listener.accept().await.unwrap();
                // 读到完整请求头(只有最后字节到达后才会出现 \r\n\r\n)。
                let mut got = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    let r = sock.read(&mut buf).await.unwrap();
                    if r == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..r]);
                    if got.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let body = b"ok";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
                sock.write_all(body).await.unwrap();
                sock.flush().await.unwrap();
                served += 1;
            }
            served
        });

        let req = ReplayRequest {
            method: "GET".into(),
            scheme: "http".into(),
            host: addr.ip().to_string(),
            port: addr.port(),
            path: "/race".into(),
            headers: vec![("Host".into(), addr.ip().to_string())],
            body: vec![],
        };
        let cfg = RaceConfig {
            mode: RaceMode::LastByteSync,
            read_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let results = run_race(&req, n, &cfg).await;

        assert_eq!(results.len(), n);
        for (i, r) in results.iter().enumerate() {
            assert_eq!(r.idx, i, "结果按 idx 排序");
            assert!(r.error.is_none(), "第 {i} 路应成功:{:?}", r.error);
            assert_eq!(r.status, 200);
            assert_eq!(r.body_len, 2);
        }
        let s = summarize(&results);
        assert_eq!(s.ok, n);
        assert!(!s.diverged);
        assert_eq!(server.await.unwrap(), n);
    }
}
