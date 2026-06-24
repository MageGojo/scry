//! 上游代理(upstream proxy)—— scry 解密后不直连真实服务器,而是把「到目标的连接」
//! 交给指定的上游代理(HTTP CONNECT / SOCKS5)出网。对标 mitmproxy 的 `--mode=upstream`。
//!
//! 为什么需要:在「sing-box / Quantumult X 链式抓包」架构里,scry 作为 MITM 居中解密,
//! 其上游必须再交回代理客户端(机场节点)才能翻墙出网;墙内直连出不去。
//! 一份能力两个客户端通吃:upstream 指向 sing-box 本地入站,或指向 QX 的本地端口均可。
//!
//! 关键:目标以**域名字符串**形式交给上游(CONNECT `host:port`、SOCKS5 ATYP=域名),
//! 由上游**远程解析 DNS** —— 既翻墙正确,又规避本地 DNS 污染(正是过去 SNI=IP 上游握手失败的解药)。

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 上游代理配置。`None`(不配)= 直连。
#[derive(Debug, Clone)]
pub enum UpstreamProxy {
    /// HTTP CONNECT 代理(最通用:sing-box mixed/http 入站、QX 本地 HTTP 端口、Burp 等)。
    Http {
        /// 代理监听地址 `host:port`(如 `127.0.0.1:8889`)。
        addr: String,
        /// 可选 Basic 认证 (用户, 密码)。
        auth: Option<(String, String)>,
    },
    /// SOCKS5 代理(sing-box socks 入站、QX SOCKS 端口等)。
    Socks5 {
        /// 代理监听地址 `host:port`。
        addr: String,
        /// 可选用户名/密码认证(RFC 1929)。
        auth: Option<(String, String)>,
    },
}

impl UpstreamProxy {
    /// 上游代理监听地址(用于日志 / 展示)。
    pub fn addr(&self) -> &str {
        match self {
            UpstreamProxy::Http { addr, .. } => addr,
            UpstreamProxy::Socks5 { addr, .. } => addr,
        }
    }

    /// 协议名(用于日志 / 展示)。
    pub fn kind(&self) -> &'static str {
        match self {
            UpstreamProxy::Http { .. } => "http",
            UpstreamProxy::Socks5 { .. } => "socks5",
        }
    }

    /// 从 URL 字符串解析:`http://[user:pass@]host:port` / `socks5://[user:pass@]host:port`。
    /// 无 scheme 时默认 `http`;`socks`/`socks5h` 视同 `socks5`。
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let (scheme, rest) = match s.split_once("://") {
            Some((sc, r)) => (sc.to_ascii_lowercase(), r),
            None => ("http".to_string(), s),
        };
        let (auth, hostport) = match rest.rsplit_once('@') {
            Some((cred, hp)) => {
                let (u, p) = cred.split_once(':').unwrap_or((cred, ""));
                (Some((u.to_string(), p.to_string())), hp)
            }
            None => (None, rest),
        };
        if !hostport.contains(':') {
            bail!("上游代理地址需为 host:port(得到 {hostport:?})");
        }
        let addr = hostport.to_string();
        match scheme.as_str() {
            "http" | "https" => Ok(UpstreamProxy::Http { addr, auth }),
            "socks5" | "socks" | "socks5h" => Ok(UpstreamProxy::Socks5 { addr, auth }),
            other => bail!("不支持的上游代理协议:{other}(可用 http / socks5)"),
        }
    }

    /// 从环境变量 `SCRY_UPSTREAM` 读取(GUI/CLI 统一配置入口);未设或解析失败返回 `None`。
    pub fn from_env() -> Option<Self> {
        let s = std::env::var("SCRY_UPSTREAM").ok()?;
        if s.trim().is_empty() {
            return None;
        }
        match Self::parse(&s) {
            Ok(u) => Some(u),
            Err(e) => {
                tracing::warn!("SCRY_UPSTREAM 解析失败,忽略:{e}");
                None
            }
        }
    }
}

/// 建立一条到 `target_host:target_port` 的 TCP 隧道:
/// - `upstream = None` → 直连(本地解析目标域名);
/// - `Http` → 连上游发 `CONNECT`,200 后隧道即到目标(域名交上游解析);
/// - `Socks5` → 连上游做 SOCKS5 握手 + CONNECT(ATYP=域名,交上游解析)。
///
/// 返回的 [`TcpStream`] 对调用方透明:在其上照常做 TLS(HTTPS)或明文读写(HTTP)。
pub async fn connect_via(
    target_host: &str,
    target_port: u16,
    upstream: Option<&UpstreamProxy>,
) -> Result<TcpStream> {
    match upstream {
        None => TcpStream::connect((target_host, target_port))
            .await
            .with_context(|| format!("直连目标 {target_host}:{target_port} 失败")),
        Some(UpstreamProxy::Http { addr, auth }) => {
            http_connect(addr, auth.as_ref(), target_host, target_port).await
        }
        Some(UpstreamProxy::Socks5 { addr, auth }) => {
            socks5_connect(addr, auth.as_ref(), target_host, target_port).await
        }
    }
}

/// HTTP CONNECT 隧道:连上游 → `CONNECT host:port` →(可选 Basic 认证)→ 校验 200。
async fn http_connect(
    proxy_addr: &str,
    auth: Option<&(String, String)>,
    host: &str,
    port: u16,
) -> Result<TcpStream> {
    let mut s = TcpStream::connect(proxy_addr)
        .await
        .with_context(|| format!("连接上游 HTTP 代理 {proxy_addr} 失败"))?;

    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some((u, p)) = auth {
        let token = base64_encode(format!("{u}:{p}").as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;
    s.flush().await?;

    // 读 CONNECT 响应直到头结束(\r\n\r\n)。
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 512];
    loop {
        let n = s.read(&mut tmp).await.context("读上游 CONNECT 响应失败")?;
        if n == 0 {
            bail!("上游 HTTP 代理在 CONNECT 响应前关闭连接");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            // 隧道建立前上游不应提前发目标数据;若有多余字节按异常处理,避免静默丢数据。
            if p + 4 != buf.len() {
                bail!("上游在 CONNECT 隧道建立时返回了多余字节,不支持");
            }
            break;
        }
        if buf.len() > 64 * 1024 {
            bail!("上游 CONNECT 响应头过大");
        }
    }
    let code = parse_status_code(&buf).context("解析上游 CONNECT 响应状态行失败")?;
    if code != 200 {
        bail!("上游 HTTP 代理 CONNECT {host}:{port} 失败,状态码 {code}");
    }
    Ok(s)
}

/// SOCKS5 CONNECT(RFC 1928 + 1929 用户密码),目标用域名(ATYP=0x03)交上游解析。
async fn socks5_connect(
    proxy_addr: &str,
    auth: Option<&(String, String)>,
    host: &str,
    port: u16,
) -> Result<TcpStream> {
    let mut s = TcpStream::connect(proxy_addr)
        .await
        .with_context(|| format!("连接上游 SOCKS5 代理 {proxy_addr} 失败"))?;

    // 1) 方法协商:声明「无认证(0x00)」,配了认证再加「用户密码(0x02)」。
    if auth.is_some() {
        s.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        s.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    s.flush().await?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel)
        .await
        .context("读 SOCKS5 方法选择失败")?;
    if sel[0] != 0x05 {
        bail!("上游不是 SOCKS5(版本 {:#x})", sel[0]);
    }
    match sel[1] {
        0x00 => {} // 无认证
        0x02 => {
            let (u, p) = auth.context("上游要求用户密码认证,但未配置")?;
            // RFC 1929:VER=1 | ULEN | UNAME | PLEN | PASSWD。
            let mut a = vec![0x01u8, u.len() as u8];
            a.extend_from_slice(u.as_bytes());
            a.push(p.len() as u8);
            a.extend_from_slice(p.as_bytes());
            s.write_all(&a).await?;
            s.flush().await?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar)
                .await
                .context("读 SOCKS5 认证结果失败")?;
            if ar[1] != 0x00 {
                bail!("上游 SOCKS5 用户密码认证被拒");
            }
        }
        m => bail!("上游 SOCKS5 不接受我方认证方法(返回 {:#x})", m),
    }

    // 2) CONNECT:VER=5 CMD=1 RSV=0 ATYP=3(域名) LEN host PORT(大端)。
    if host.len() > 255 {
        bail!("SOCKS5 目标域名过长(>255)");
    }
    let mut reqb = vec![0x05u8, 0x01, 0x00, 0x03, host.len() as u8];
    reqb.extend_from_slice(host.as_bytes());
    reqb.extend_from_slice(&port.to_be_bytes());
    s.write_all(&reqb).await?;
    s.flush().await?;

    // 3) 响应:VER REP RSV ATYP BND.ADDR BND.PORT。读 4 字节头 + 按 ATYP 读地址 + 2 端口并丢弃。
    let mut head = [0u8; 4];
    s.read_exact(&mut head)
        .await
        .context("读 SOCKS5 响应失败")?;
    if head[0] != 0x05 {
        bail!("SOCKS5 响应版本异常 {:#x}", head[0]);
    }
    if head[1] != 0x00 {
        bail!("上游 SOCKS5 CONNECT {host}:{port} 失败,REP={:#x}", head[1]);
    }
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        a => bail!("SOCKS5 响应未知 ATYP {:#x}", a),
    };
    let mut skip = vec![0u8; addr_len + 2];
    s.read_exact(&mut skip)
        .await
        .context("读 SOCKS5 绑定地址失败")?;
    Ok(s)
}

/// 解析 HTTP 状态行的状态码(`HTTP/1.1 200 ...`)。
fn parse_status_code(buf: &[u8]) -> Option<u16> {
    let line_end = find(buf, b"\r\n")?;
    let line = std::str::from_utf8(&buf[..line_end]).ok()?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// 在 `hay` 中查找子序列 `needle` 的起始位置。
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// 标准 base64 编码(仅用于 HTTP Basic 代理认证,避免引入额外依赖)。
fn base64_encode(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parse_upstream_urls() {
        match UpstreamProxy::parse("http://127.0.0.1:8889").unwrap() {
            UpstreamProxy::Http { addr, auth } => {
                assert_eq!(addr, "127.0.0.1:8889");
                assert!(auth.is_none());
            }
            _ => panic!("应为 Http"),
        }
        match UpstreamProxy::parse("socks5://user:pass@127.0.0.1:1080").unwrap() {
            UpstreamProxy::Socks5 { addr, auth } => {
                assert_eq!(addr, "127.0.0.1:1080");
                assert_eq!(auth, Some(("user".to_string(), "pass".to_string())));
            }
            _ => panic!("应为 Socks5"),
        }
        // 无 scheme 默认 http。
        assert!(matches!(
            UpstreamProxy::parse("127.0.0.1:8888").unwrap(),
            UpstreamProxy::Http { .. }
        ));
        // 缺端口报错。
        assert!(UpstreamProxy::parse("http://127.0.0.1").is_err());
        // 不支持的协议报错。
        assert!(UpstreamProxy::parse("ftp://h:1").is_err());
    }

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(
            base64_encode(b"Aladdin:open sesame"),
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    /// 直连:`connect_via(None)` 应能连到本地 server 并收数据。
    #[tokio::test]
    async fn direct_connect_no_upstream() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            s.write_all(b"hi").await.unwrap();
        });
        let host = addr.ip().to_string();
        let mut s = connect_via(&host, addr.port(), None).await.unwrap();
        let mut buf = [0u8; 2];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");
        srv.await.unwrap();
    }

    /// HTTP CONNECT 上游:模拟收到 CONNECT 回 200、随后透传的代理,验证隧道收发。
    #[tokio::test]
    async fn http_connect_upstream_tunnel() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let paddr = proxy.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut c, _) = proxy.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 256];
            loop {
                let n = c.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if find(&buf, b"\r\n\r\n").is_some() {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&buf);
            assert!(req.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            c.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            // 隧道回显。
            let mut t = [0u8; 16];
            let n = c.read(&mut t).await.unwrap();
            c.write_all(&t[..n]).await.unwrap();
        });
        let up = UpstreamProxy::Http {
            addr: format!("{paddr}"),
            auth: None,
        };
        let mut s = connect_via("example.com", 443, Some(&up)).await.unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.await.unwrap();
    }

    /// SOCKS5 上游:模拟无认证握手 + CONNECT(域名) + 回显隧道。
    #[tokio::test]
    async fn socks5_upstream_tunnel() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let paddr = proxy.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut c, _) = proxy.accept().await.unwrap();
            let mut m = [0u8; 3];
            c.read_exact(&mut m).await.unwrap();
            assert_eq!(m, [0x05, 0x01, 0x00]);
            c.write_all(&[0x05, 0x00]).await.unwrap();
            let mut h = [0u8; 4];
            c.read_exact(&mut h).await.unwrap();
            assert_eq!(h, [0x05, 0x01, 0x00, 0x03]);
            let mut l = [0u8; 1];
            c.read_exact(&mut l).await.unwrap();
            let mut hostb = vec![0u8; l[0] as usize];
            c.read_exact(&mut hostb).await.unwrap();
            assert_eq!(&hostb, b"example.com");
            let mut port = [0u8; 2];
            c.read_exact(&mut port).await.unwrap();
            assert_eq!(u16::from_be_bytes(port), 443);
            c.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut t = [0u8; 16];
            let n = c.read(&mut t).await.unwrap();
            c.write_all(&t[..n]).await.unwrap();
        });
        let up = UpstreamProxy::Socks5 {
            addr: format!("{paddr}"),
            auth: None,
        };
        let mut s = connect_via("example.com", 443, Some(&up)).await.unwrap();
        s.write_all(b"hey").await.unwrap();
        let mut buf = [0u8; 3];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hey");
        server.await.unwrap();
    }
}
