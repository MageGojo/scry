//! TLS 指纹计算(JA3 + JA4)—— 从 rustls **实际吐出**的 ClientHello 字节算真实指纹。
//!
//! 为什么不去「猜」:让 rustls 真产出一份 ClientHello(内存里、不连网),再按规范从**真实字节**解析,
//! 这样 UI 显示的就是 scry 上游握手的**线上真实指纹**,可直接和指纹回显站(如 tls.peet.ws)对照。
//!
//! 两条必须如实记录的现实:
//! 1. **rustls 0.23 每次握手都随机化 ClientHello 扩展顺序**(抗固化,类似现代浏览器)。
//!    → JA3 的「扩展段」逐连接变化、**JA3 不稳定**;而 **JA4 对密码 / 扩展排序后再哈希,稳定**。
//!    因此 UI 以 **JA4 为准**,JA3 仅作单次采样参考。
//! 2. 本套 [`tls_profile`](crate::tls_profile) 只改 rustls 可控的密码 / 曲线**顺序** + ALPN;
//!    JA4 故意忽略顺序 → 各档 JA4 仅 ALPN 段有别。要让 JA3/JA4 真正**等于** Chrome(套件集合、
//!    GREASE、application_settings 等扩展、精确布局)需换 BoringSSL(`boring` / `rquest`),
//!    rustls 做不到,列为后续。

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use md5::Md5;
use sha2::{Digest, Sha256};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConnection;

use crate::tls_profile::TlsProfile;

/// 一个 profile 的 TLS 指纹(JA3 + JA4)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// JA4(TLS 客户端)——排序后哈希,**稳定**,推荐作为对照基准。
    pub ja4: String,
    /// JA3 明文串(单次采样;rustls 随机化扩展顺序 → 每连接不同)。
    pub ja3: String,
    /// JA3 = `md5(ja3)` 十六进制(同样为单次采样)。
    pub ja3_hash: String,
}

/// 计算某 profile 的指纹(基于 rustls 真实生成的 ClientHello)。
pub fn fingerprint_for(profile: TlsProfile) -> Result<Fingerprint> {
    let hello = client_hello_bytes(profile)?;
    let f = parse_client_hello(&hello).context("解析自生成 ClientHello 失败")?;
    Ok(f.fingerprint())
}

/// 进程级缓存版:UI 渲染按 profile 取指纹,避免每帧重复构造 ClientHello。
///
/// 注意:JA3 本身逐连接随机,这里缓存的是「某次采样」;JA4 稳定,缓存无副作用。
pub fn fingerprint_for_cached(profile: TlsProfile) -> Option<Fingerprint> {
    static CACHE: Mutex<Vec<(u8, Fingerprint)>> = Mutex::new(Vec::new());
    let key = profile.as_u8();
    if let Ok(mut c) = CACHE.lock() {
        if let Some((_, f)) = c.iter().find(|(k, _)| *k == key) {
            return Some(f.clone());
        }
        if let Ok(f) = fingerprint_for(profile) {
            c.push((key, f.clone()));
            return Some(f);
        }
        return None;
    }
    fingerprint_for(profile).ok()
}

/// 让 rustls 产出该 profile 的 ClientHello 原始字节(内存内,不连网、不握手)。
fn client_hello_bytes(profile: TlsProfile) -> Result<Vec<u8>> {
    let cfg = crate::mitm::build_client_config_for(profile)?;
    // 域名随便填:它只进 SNI,不影响指纹结构。
    let name = ServerName::try_from("example.com").context("构造 ServerName 失败")?;
    let mut conn =
        ClientConnection::new(Arc::new(cfg), name).context("构造 ClientConnection 失败")?;
    // 新建连接即排队 ClientHello;首个 write_tls 即把它写出(单记录,< 16KiB)。
    let mut buf = Vec::new();
    conn.write_tls(&mut buf).context("写出 ClientHello 失败")?;
    Ok(buf)
}

/// 从 ClientHello 解析出的指纹原料(数值,GREASE 已剔除)。
struct HelloFields {
    legacy_version: u16,
    supported_versions: Vec<u16>,
    ciphers: Vec<u16>,
    /// 扩展类型(出现顺序,GREASE 已剔除)。
    extensions: Vec<u16>,
    curves: Vec<u16>,
    point_formats: Vec<u8>,
    sig_algs: Vec<u16>,
    /// 首个 ALPN 协议(原始字节,如 b"h2");无则 None。
    alpn_first: Option<Vec<u8>>,
    sni_present: bool,
}

impl HelloFields {
    fn fingerprint(&self) -> Fingerprint {
        let (ja3, ja3_hash) = self.ja3();
        Fingerprint {
            ja4: self.ja4(),
            ja3,
            ja3_hash,
        }
    }

    /// JA3:`SSLVersion,Ciphers,Extensions,Curves,PointFormats`(十进制,GREASE 已剔除)+ md5。
    fn ja3(&self) -> (String, String) {
        let dec_u16 = |v: &[u16]| {
            v.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join("-")
        };
        let pf = self
            .point_formats
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join("-");
        let s = format!(
            "{},{},{},{},{}",
            self.legacy_version,
            dec_u16(&self.ciphers),
            dec_u16(&self.extensions),
            dec_u16(&self.curves),
            pf,
        );
        let mut h = Md5::new();
        h.update(s.as_bytes());
        let hash = hex(&h.finalize());
        (s, hash)
    }

    /// JA4(TLS,TCP):`t{ver}{sni}{nc}{ne}{alpn} _ {sorted_ciphers12} _ {sorted_ext+sigalg12}`。
    fn ja4(&self) -> String {
        let ver = ja4_version(self);
        let sni = if self.sni_present { "d" } else { "i" };
        let nc = format!("{:02}", self.ciphers.len().min(99));
        let ne = format!("{:02}", self.extensions.len().min(99));
        let alpn = ja4_alpn(self.alpn_first.as_deref());
        let a = format!("t{ver}{sni}{nc}{ne}{alpn}");

        // JA4_b:密码套件按 16 进制串**排序**后 sha256 取前 12。
        let b = if self.ciphers.is_empty() {
            "000000000000".to_string()
        } else {
            let mut cs: Vec<String> = self.ciphers.iter().map(|c| hex4(*c)).collect();
            cs.sort();
            sha256_12(&cs.join(","))
        };

        // JA4_c:扩展(排除 SNI 0x0000 与 ALPN 0x0010)排序 + "_" + 签名算法(原序)。
        let mut exts: Vec<String> = self
            .extensions
            .iter()
            .filter(|e| **e != 0x0000 && **e != 0x0010)
            .map(|e| hex4(*e))
            .collect();
        exts.sort();
        let sig: Vec<String> = self.sig_algs.iter().map(|s| hex4(*s)).collect();
        let c = if exts.is_empty() && sig.is_empty() {
            "000000000000".to_string()
        } else if sig.is_empty() {
            sha256_12(&exts.join(","))
        } else {
            sha256_12(&format!("{}_{}", exts.join(","), sig.join(",")))
        };

        format!("{a}_{b}_{c}")
    }
}

/// JA4 版本段:取 supported_versions(剔 GREASE)的最大值,无则用 legacy_version。
fn ja4_version(f: &HelloFields) -> &'static str {
    let v = f
        .supported_versions
        .iter()
        .copied()
        .max()
        .unwrap_or(f.legacy_version);
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

/// JA4 的 ALPN 段:首个 ALPN 的首字符 + 末字符(均 alnum 时);无 ALPN → "00"。
fn ja4_alpn(first: Option<&[u8]>) -> String {
    match first {
        None | Some([]) => "00".to_string(),
        Some(p) => {
            let a = p[0];
            let b = p[p.len() - 1];
            if a.is_ascii_alphanumeric() && b.is_ascii_alphanumeric() {
                format!("{}{}", a as char, b as char)
            } else {
                "99".to_string()
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn hex4(v: u16) -> String {
    format!("{v:04x}")
}

fn sha256_12(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let full = hex(&h.finalize());
    full[..12].to_string()
}

/// GREASE 值判定(RFC 8701:形如 0x?A?A 且两字节相等)。
fn is_grease(v: u16) -> bool {
    (v >> 8) == (v & 0xff) && (v & 0x0f) == 0x0a
}

/// 解析一条 TLS 记录里的 ClientHello。健壮:越界即返回 `None`。
fn parse_client_hello(buf: &[u8]) -> Option<HelloFields> {
    // record: content_type(1)=0x16 handshake + legacy_version(2) + length(2)
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let rec = buf.get(5..5 + rec_len)?;
    // handshake: msg_type(1)=0x01 ClientHello + length(3)
    if rec.len() < 4 || rec[0] != 0x01 {
        return None;
    }
    let body_len = ((rec[1] as usize) << 16) | ((rec[2] as usize) << 8) | rec[3] as usize;
    let b = rec.get(4..4 + body_len)?;
    parse_body(b)
}

fn parse_body(b: &[u8]) -> Option<HelloFields> {
    let legacy_version = u16::from_be_bytes([*b.first()?, *b.get(1)?]);
    let mut p = 2 + 32; // legacy_version(2) + random(32)

    let sid_len = *b.get(p)? as usize;
    p += 1 + sid_len;

    let cs_len = u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]) as usize;
    p += 2;
    let ciphers = read_u16_list(b.get(p..p + cs_len)?);
    p += cs_len;

    let comp_len = *b.get(p)? as usize;
    p += 1 + comp_len;

    let mut extensions = Vec::new();
    let mut curves = Vec::new();
    let mut point_formats = Vec::new();
    let mut sig_algs = Vec::new();
    let mut supported_versions = Vec::new();
    let mut alpn_first = None;
    let mut sni_present = false;

    if p + 2 <= b.len() {
        let ext_total = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
        p += 2;
        let ext_end = (p + ext_total).min(b.len());
        while p + 4 <= ext_end {
            let etype = u16::from_be_bytes([b[p], b[p + 1]]);
            let elen = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
            p += 4;
            let edata = b.get(p..p + elen)?;
            if !is_grease(etype) {
                extensions.push(etype);
            }
            match etype {
                0x0000 => sni_present = true,
                0x000a => curves = read_named_groups(edata),
                0x000b => point_formats = read_point_formats(edata),
                0x000d => sig_algs = read_len2_u16_list(edata),
                0x0010 => alpn_first = read_first_alpn(edata),
                0x002b => supported_versions = read_supported_versions(edata),
                _ => {}
            }
            p += elen;
        }
    }

    Some(HelloFields {
        legacy_version,
        supported_versions,
        ciphers,
        extensions,
        curves,
        point_formats,
        sig_algs,
        alpn_first,
        sni_present,
    })
}

/// 一串 2 字节大端值 → `Vec<u16>`,剔除 GREASE。
fn read_u16_list(d: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= d.len() {
        let v = u16::from_be_bytes([d[i], d[i + 1]]);
        if !is_grease(v) {
            out.push(v);
        }
        i += 2;
    }
    out
}

/// 带 2 字节长度前缀的 u16 列表(supported_groups / signature_algorithms 同构)。
fn read_len2_u16_list(d: &[u8]) -> Vec<u16> {
    if d.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([d[0], d[1]]) as usize;
    read_u16_list(d.get(2..2 + list_len).unwrap_or(&[]))
}

fn read_named_groups(d: &[u8]) -> Vec<u16> {
    read_len2_u16_list(d)
}

/// supported_versions(ClientHello):len(1) + 版本[u16…]。
fn read_supported_versions(d: &[u8]) -> Vec<u16> {
    if d.is_empty() {
        return Vec::new();
    }
    let list_len = d[0] as usize;
    read_u16_list(d.get(1..1 + list_len).unwrap_or(&[]))
}

/// ec_point_formats:len(1) + 格式[u8…]。
fn read_point_formats(d: &[u8]) -> Vec<u8> {
    if d.is_empty() {
        return Vec::new();
    }
    let pf_len = d[0] as usize;
    d.get(1..1 + pf_len).unwrap_or(&[]).to_vec()
}

/// ALPN 扩展:list_len(2) + 条目[ len(1) + proto ];返回首个 proto 字节。
fn read_first_alpn(d: &[u8]) -> Option<Vec<u8>> {
    if d.len() < 3 {
        return None;
    }
    let proto_len = d[2] as usize;
    d.get(3..3 + proto_len).map(|s| s.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_detection() {
        for g in [0x0a0au16, 0x1a1a, 0x2a2a, 0xdada, 0xfafa] {
            assert!(is_grease(g), "{g:#06x} 应判为 GREASE");
        }
        for ok in [0x0000u16, 0x1301, 0xc02b, 0x000a, 0x001d] {
            assert!(!is_grease(ok), "{ok:#06x} 不应判为 GREASE");
        }
    }

    #[test]
    fn ja4_helpers() {
        assert_eq!(ja4_alpn(Some(b"h2")), "h2");
        assert_eq!(ja4_alpn(Some(b"http/1.1")), "h1");
        assert_eq!(ja4_alpn(None), "00");
        assert_eq!(hex4(0x1301), "1301");
        // sha256("") 前 12。
        assert_eq!(sha256_12(""), "e3b0c44298fc");
    }

    #[test]
    fn parses_synthetic_hello_and_strips_grease() {
        let f = parse_client_hello(&synthetic_hello()).expect("应解析成功");
        assert_eq!(f.legacy_version, 0x0303);
        assert_eq!(f.ciphers, vec![0x1301, 0x1302]);
        assert_eq!(
            f.extensions,
            vec![0x000a, 0x000b, 0x000d, 0x0010, 0x0000, 0x002b]
        );
        assert_eq!(f.curves, vec![0x001d, 0x0017]);
        assert_eq!(f.point_formats, vec![0u8]);
        assert_eq!(f.sig_algs, vec![0x0403, 0x0804]);
        assert_eq!(f.alpn_first.as_deref(), Some(&b"h2"[..]));
        assert!(f.sni_present);

        assert_eq!(f.supported_versions, vec![0x0304, 0x0303]);

        let (ja3, ja3_hash) = f.ja3();
        assert_eq!(ja3, "771,4865-4866,10-11-13-16-0-43,29-23,0");
        assert_eq!(ja3_hash.len(), 32);

        // JA4_a:tcp + 1.3(由 supported_versions) + SNI(d) + 2 ciphers + 6 exts + ALPN h2。
        let ja4 = f.ja4();
        assert!(ja4.starts_with("t13d0206h2_"), "实际: {ja4}");
        // JA4_c 扩展段排除 SNI/ALPN → 只剩 000a,000b,000d(排序),再 "_" + 签名算法。
        let parts: Vec<&str> = ja4.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 12);
    }

    /// 端到端:rustls 真生成 ClientHello → 指纹。JA4 稳定且各档仅 ALPN 段有别(本档只改顺序)。
    #[test]
    fn ja4_stable_across_runs_and_profiles() {
        // 同一档多次:JA4 必须稳定(尽管 JA3 因扩展随机会变)。
        let a = fingerprint_for(TlsProfile::Chrome).unwrap();
        let b = fingerprint_for(TlsProfile::Chrome).unwrap();
        assert_eq!(a.ja4, b.ja4, "JA4 应跨连接稳定");

        let def = fingerprint_for(TlsProfile::Default).unwrap();
        let chrome = fingerprint_for(TlsProfile::Chrome).unwrap();
        // 都以 t13 开头(TLS1.3 over TCP)。
        assert!(def.ja4.starts_with("t13"));
        assert!(chrome.ja4.starts_with("t13"));
        // Default ALPN=http/1.1 → 段尾 h1;Chrome 提议 h2 → h2 → JA4 不同。
        assert_ne!(def.ja4, chrome.ja4, "ALPN 不同应让 JA4 不同");
    }

    /// 构造一份带 GREASE、含 SNI/ALPN/曲线/点格式/签名算法/supported_versions 的最小 ClientHello。
    fn synthetic_hello() -> Vec<u8> {
        // supported_groups(000a) = [GREASE 1a1a, x25519 001d, secp256r1 0017]
        let groups = [0x1a1au16, 0x001d, 0x0017];
        let sg = ext_with_len2_list(0x000a, &groups);
        // ec_point_formats(000b) = [0]
        let pf = ext_raw(0x000b, &[0x01, 0x00]);
        // signature_algorithms(000d) = [0403, 0804]
        let sigs = [0x0403u16, 0x0804];
        let sa = ext_with_len2_list(0x000d, &sigs);
        // ALPN(0010): list_len(2) + [len(1)=2 + "h2"]
        let alpn_body = {
            let mut e = vec![0x02u8];
            e.extend_from_slice(b"h2");
            let mut body = (e.len() as u16).to_be_bytes().to_vec();
            body.extend_from_slice(&e);
            body
        };
        let alpn = ext_raw(0x0010, &alpn_body);
        // SNI(0000) 空体占位。
        let sni = ext_raw(0x0000, &[]);
        // supported_versions(002b): len(1) + [0304, 0303]
        let sv_body = {
            let vers = [0x0304u16, 0x0303];
            let mut body = vec![(vers.len() * 2) as u8];
            for v in vers {
                body.extend_from_slice(&v.to_be_bytes());
            }
            body
        };
        let sv = ext_raw(0x002b, &sv_body);
        // GREASE 扩展(0a0a)空体,应被剔除。
        let grease = ext_raw(0x0a0a, &[]);

        let mut exts = Vec::new();
        for e in [grease, sg, pf, sa, alpn, sni, sv] {
            exts.extend_from_slice(&e);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id len
        let suites = [0x0a0au16, 0x1301, 0x1302]; // 含 GREASE
        body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
        for s in suites {
            body.extend_from_slice(&s.to_be_bytes());
        }
        body.extend_from_slice(&[0x01, 0x00]); // compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![0x01];
        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// 扩展:type(2) + len(2) + 原始体。
    fn ext_raw(etype: u16, data: &[u8]) -> Vec<u8> {
        let mut e = etype.to_be_bytes().to_vec();
        e.extend_from_slice(&(data.len() as u16).to_be_bytes());
        e.extend_from_slice(data);
        e
    }

    /// 扩展体 = len2 前缀 + u16 列表(supported_groups / signature_algorithms 同构)。
    fn ext_with_len2_list(etype: u16, vals: &[u16]) -> Vec<u8> {
        let mut list = ((vals.len() * 2) as u16).to_be_bytes().to_vec();
        for v in vals {
            list.extend_from_slice(&v.to_be_bytes());
        }
        ext_raw(etype, &list)
    }
}
