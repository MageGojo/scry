//! QUIC(HTTP/3)被动可见性 —— 检测 QUIC 长包 + 解密 **Initial** 包提取 TLS SNI / ALPN。
//!
//! scry 的内核是 TCP 上的 TLS 终止式 MITM,QUIC 走 UDP、无法经 HTTP CONNECT 代理 → **无法主动 MITM**
//! (真 h3 MITM 需要 UDP 接入路径,见 `docs/设计-Reqable对标补全.md` §6)。但 QUIC 的 **Initial 包**用
//! 一个**公开盐**派生密钥(RFC 9001 §5.2),因此**无需任何密钥即可解密 Initial、取出明文 ClientHello**
//! —— 这正是 Wireshark 展示 QUIC SNI 的原理。本 crate 实现这条「被动可见」路径,供:
//!
//! - `scry_sniff`:在网卡上抓 **UDP/443** 帧 → 喂 [`extract_handshake_info`] → 历史里出一条 h3 流(SNI/ALPN);
//! - `scry_proxy`:`pub use scry_quic as quic` re-export,保留 `scry_proxy::quic::*` 路径(example / 文档兼容)。
//!
//! API 概览:
//! - [`is_long_header`] / [`is_initial`] / [`parse_long_header`]:识别 QUIC 长包 / Initial、取版本 + 连接 ID;
//! - [`derive_client_initial`]:由 DCID 派生 Initial 客户端密钥(HKDF);
//! - [`extract_handshake_info`] / [`extract_sni`]:解密 Initial → 重组 CRYPTO → 解析 ClientHello → SNI + ALPN。
//!
//! 纯函数、可单测(密钥派生对 RFC 9001 Appendix A.1 向量;端到端走自构造 Initial 往返)。
//! 仅支持 QUIC v1(`0x00000001`,salt 已知);其它版本返回 `None`。

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use sha2::{Digest, Sha256};

/// QUIC v1 Initial 盐(RFC 9001 §5.2)。
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// QUIC 长包的解析结果(明文长头部分)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongHeader {
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
}

/// QUIC Initial 解出的握手信息。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicHello {
    pub sni: Option<String>,
    pub alpn: Vec<String>,
}

// ───────────────────────── HKDF(TLS 1.3) ─────────────────────────

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const B: usize = 64;
    let mut k = [0u8; B];
    if key.len() > B {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; B];
    let mut opad = [0x5cu8; B];
    for i in 0..B {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < length {
        let mut data = Vec::with_capacity(t.len() + info.len() + 1);
        data.extend_from_slice(&t);
        data.extend_from_slice(info);
        data.push(counter);
        t = hmac_sha256(prk, &data).to_vec();
        out.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
    }
    out.truncate(length);
    out
}

/// TLS 1.3 HKDF-Expand-Label(空 context)。
fn hkdf_expand_label(secret: &[u8], label: &str, length: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0); // context length 0
    hkdf_expand(secret, &info, length)
}

/// 由 client DCID 派生 Initial **客户端**密钥:`(key[16], iv[12], hp[16])`(RFC 9001 §5.2)。
pub fn derive_client_initial(dcid: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let initial_secret = hmac_sha256(&INITIAL_SALT_V1, dcid); // HKDF-Extract
    let client_secret = hkdf_expand_label(&initial_secret, "client in", 32);
    let key = hkdf_expand_label(&client_secret, "quic key", 16);
    let iv = hkdf_expand_label(&client_secret, "quic iv", 12);
    let hp = hkdf_expand_label(&client_secret, "quic hp", 16);
    (key, iv, hp)
}

// ───────────────────────── QUIC 包解析 ─────────────────────────

/// 读 QUIC 变长整数(RFC 9000 §16),返回 `(值, 字节数)`。
fn read_varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    if b.len() < len {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for &byte in &b[1..len] {
        v = (v << 8) | byte as u64;
    }
    Some((v, len))
}

/// 是否为 QUIC **长包**(header form 位 = 1)。
pub fn is_long_header(pkt: &[u8]) -> bool {
    pkt.first().map(|b| b & 0x80 != 0).unwrap_or(false)
}

/// 是否为 QUIC **Initial** 包(长包 + 固定位 + 类型位 = 00)。
pub fn is_initial(pkt: &[u8]) -> bool {
    matches!(pkt.first(), Some(b) if b & 0x80 != 0 && b & 0x40 != 0 && (b & 0x30) == 0x00)
}

/// 解析 QUIC 长包头(明文部分):版本 + DCID + SCID。非长包 / 截断返回 `None`。
pub fn parse_long_header(pkt: &[u8]) -> Option<LongHeader> {
    if pkt.len() < 6 || !is_long_header(pkt) {
        return None;
    }
    let version = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);
    let mut i = 5usize;
    let dcid_len = *pkt.get(i)? as usize;
    i += 1;
    let dcid = pkt.get(i..i + dcid_len)?.to_vec();
    i += dcid_len;
    let scid_len = *pkt.get(i)? as usize;
    i += 1;
    let scid = pkt.get(i..i + scid_len)?.to_vec();
    Some(LongHeader { version, dcid, scid })
}

fn aes_ecb_block(key: &[u8], block: &[u8]) -> Option<[u8; 16]> {
    if key.len() != 16 || block.len() < 16 {
        return None;
    }
    let cipher = Aes128::new_from_slice(key).ok()?;
    let mut ga = GenericArray::clone_from_slice(&block[..16]);
    cipher.encrypt_block(&mut ga);
    let mut out = [0u8; 16];
    out.copy_from_slice(&ga);
    Some(out)
}

fn aes128_gcm_open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    if key.len() != 16 || nonce.len() != 12 {
        return None;
    }
    let cipher = Aes128Gcm::new_from_slice(key).ok()?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
}

/// 解密 QUIC v1 Initial 包并提取握手信息(SNI + ALPN)。失败 / 非 Initial / 非 v1 → `None`。
pub fn extract_handshake_info(pkt: &[u8]) -> Option<QuicHello> {
    if !is_initial(pkt) {
        return None;
    }
    let hdr = parse_long_header(pkt)?;
    if hdr.version != 1 {
        return None; // 仅 v1(salt 已知)
    }
    // 定位 token / length / packet-number 偏移。
    let mut i = 5 + 1 + hdr.dcid.len() + 1 + hdr.scid.len();
    let (token_len, adv) = read_varint(pkt.get(i..)?)?;
    i += adv + token_len as usize;
    let (length, adv) = read_varint(pkt.get(i..)?)?;
    i += adv;
    let pn_offset = i;
    let length = length as usize;
    if pkt.len() < pn_offset + length {
        return None;
    }

    let (key, iv, hp) = derive_client_initial(&hdr.dcid);

    // 头保护:采样在 pn_offset + 4 处取 16 字节 → AES-ECB → mask。
    let sample_off = pn_offset + 4;
    let sample = pkt.get(sample_off..sample_off + 16)?;
    let mask = aes_ecb_block(&hp, sample)?;

    let mut pkt = pkt.to_vec();
    pkt[0] ^= mask[0] & 0x0f; // 长包只动低 4 位
    let pn_len = ((pkt[0] & 0x03) + 1) as usize;
    for j in 0..pn_len {
        pkt[pn_offset + j] ^= mask[1 + j];
    }
    let mut pn = 0u64;
    for j in 0..pn_len {
        pn = (pn << 8) | pkt[pn_offset + j] as u64;
    }

    // nonce = iv XOR 右对齐的 packet number。
    let mut nonce = iv;
    let pn_be = pn.to_be_bytes();
    for j in 0..8 {
        nonce[12 - 8 + j] ^= pn_be[j];
    }

    let header_end = pn_offset + pn_len;
    let aad = pkt[..header_end].to_vec();
    let ct = &pkt[header_end..pn_offset + length];
    let plaintext = aes128_gcm_open(&key, &nonce, &aad, ct)?;

    let crypto = reassemble_crypto(&plaintext)?;
    let hello = parse_client_hello(&crypto)?;
    // 解析成功(哪怕无 SNI/ALPN)也返回 Some,让调用方知道这是一条 h3 流。
    Some(hello)
}

/// 便捷:只取 SNI。
pub fn extract_sni(pkt: &[u8]) -> Option<String> {
    extract_handshake_info(pkt).and_then(|h| h.sni)
}

/// 从解密后的 Initial 载荷重组 CRYPTO 帧数据(容忍 PADDING / PING;遇其它帧类型停止)。
fn reassemble_crypto(payload: &[u8]) -> Option<Vec<u8>> {
    let mut chunks: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut i = 0usize;
    while i < payload.len() {
        let (ftype, adv) = read_varint(&payload[i..])?;
        i += adv;
        match ftype {
            0x00 | 0x01 => {} // PADDING / PING:无 body
            0x06 => {
                let (off, adv) = read_varint(payload.get(i..)?)?;
                i += adv;
                let (len, adv) = read_varint(payload.get(i..)?)?;
                i += adv;
                let len = len as usize;
                let data = payload.get(i..i + len)?.to_vec();
                i += len;
                chunks.push((off, data));
            }
            // ACK / 其它帧:首个客户端 Initial 通常只含 CRYPTO + PADDING;遇到就停止重组。
            _ => break,
        }
    }
    if chunks.is_empty() {
        return None;
    }
    chunks.sort_by_key(|(o, _)| *o);
    let mut out = Vec::new();
    for (off, data) in chunks {
        let off = off as usize;
        if off > out.len() {
            break; // 有空洞,后续不连续
        }
        if off == out.len() {
            out.extend_from_slice(&data);
        }
    }
    Some(out)
}

/// 解析 TLS ClientHello,取 SNI + ALPN。`hs` = 重组后的握手字节(应以 ClientHello 起头)。
fn parse_client_hello(hs: &[u8]) -> Option<QuicHello> {
    if hs.len() < 4 || hs[0] != 0x01 {
        return None; // 非 ClientHello
    }
    let len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
    let body = hs.get(4..4 + len)?;
    let mut i = 0usize;
    i += 2; // legacy_version
    i += 32; // random
    let sid_len = *body.get(i)? as usize;
    i += 1 + sid_len;
    let cs_len = u16::from_be_bytes([*body.get(i)?, *body.get(i + 1)?]) as usize;
    i += 2 + cs_len;
    let cm_len = *body.get(i)? as usize;
    i += 1 + cm_len;
    let ext_total = u16::from_be_bytes([*body.get(i)?, *body.get(i + 1)?]) as usize;
    i += 2;
    let ext_end = (i + ext_total).min(body.len());

    let mut hello = QuicHello::default();
    while i + 4 <= ext_end {
        let etype = u16::from_be_bytes([body[i], body[i + 1]]);
        let elen = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        i += 4;
        let ext = match body.get(i..i + elen) {
            Some(e) => e,
            None => break,
        };
        match etype {
            0x0000 => hello.sni = parse_sni_ext(ext),
            0x0010 => hello.alpn = parse_alpn_ext(ext),
            _ => {}
        }
        i += elen;
    }
    Some(hello)
}

/// SNI 扩展:`list_len(2) | name_type(1) | name_len(2) | name`(取首个 host_name)。
fn parse_sni_ext(ext: &[u8]) -> Option<String> {
    if ext.len() < 5 {
        return None;
    }
    let name_type = ext[2];
    let name_len = u16::from_be_bytes([ext[3], ext[4]]) as usize;
    if name_type != 0 || 5 + name_len > ext.len() {
        return None;
    }
    String::from_utf8(ext[5..5 + name_len].to_vec()).ok()
}

/// ALPN 扩展:`list_len(2) | [proto_len(1) | proto]*`。
fn parse_alpn_ext(ext: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if ext.len() < 2 {
        return out;
    }
    let mut i = 2usize; // 跳过 list_len
    while i < ext.len() {
        let l = ext[i] as usize;
        i += 1;
        if i + l > ext.len() {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&ext[i..i + l]) {
            out.push(s.to_string());
        }
        i += l;
    }
    out
}

// ───────────────────── 测试 / 示例构造器(doc(hidden),非稳定 API) ─────────────────────
// 自构造一个合法 v1 客户端 Initial 包,供本 crate 与 `scry_sniff` 的测试 / `examples/quic_sni` 复用,
// 避免在多个 crate 里重复手搓 QUIC/TLS 字节。`#[doc(hidden)]` 表示不对外承诺稳定性。

/// QUIC 变长整数编码(测试用)。
#[doc(hidden)]
pub fn enc_varint(v: u64) -> Vec<u8> {
    if v < 64 {
        vec![v as u8]
    } else if v < 16384 {
        (v as u16 | 0x4000).to_be_bytes().to_vec()
    } else {
        (v as u32 | 0x8000_0000).to_be_bytes().to_vec()
    }
}

/// 构造一个带 SNI + ALPN 的最小 TLS ClientHello 握手消息(测试用)。
#[doc(hidden)]
pub fn build_client_hello(sni: &str, alpn: &[&str]) -> Vec<u8> {
    let mut exts = Vec::new();
    // SNI (0x0000)
    let mut sni_list = Vec::new();
    sni_list.push(0u8); // name_type host_name
    sni_list.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    sni_list.extend_from_slice(sni.as_bytes());
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(&sni_list);
    exts.extend_from_slice(&0x0000u16.to_be_bytes());
    exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_ext);
    // ALPN (0x0010)
    let mut alpn_list = Vec::new();
    for p in alpn {
        alpn_list.push(p.len() as u8);
        alpn_list.extend_from_slice(p.as_bytes());
    }
    let mut alpn_ext = Vec::new();
    alpn_ext.extend_from_slice(&(alpn_list.len() as u16).to_be_bytes());
    alpn_ext.extend_from_slice(&alpn_list);
    exts.extend_from_slice(&0x0010u16.to_be_bytes());
    exts.extend_from_slice(&(alpn_ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&alpn_ext);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session_id len
    body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
    body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    body.push(1); // compression methods len
    body.push(0); // null
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut hs = vec![0x01u8]; // ClientHello
    let l = (body.len() as u32).to_be_bytes();
    hs.extend_from_slice(&l[1..4]); // 3-byte length
    hs.extend_from_slice(&body);
    hs
}

/// 把一段 Initial 载荷(明文)封成加密 + 头保护后的 QUIC v1 客户端 Initial 包(测试用)。
#[doc(hidden)]
pub fn build_initial_packet(dcid: &[u8], payload: &[u8]) -> Vec<u8> {
    let (key, iv, hp) = derive_client_initial(dcid);
    let pn: u32 = 1;
    let pn_len = 4usize; // 用 4 字节 pn(b0 低 2 位 = 0b11)

    let mut header = Vec::new();
    header.push(0xc0 | 0x03); // 长包 + 固定位 + Initial(0x00) + pn_len-1=3
    header.extend_from_slice(&1u32.to_be_bytes()); // version 1
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.push(0); // scid len 0
    header.extend_from_slice(&enc_varint(0)); // token len 0
    let length_val = (pn_len + payload.len() + 16) as u64; // pn + payload + GCM tag
    header.extend_from_slice(&enc_varint(length_val));
    let pn_offset = header.len();
    header.extend_from_slice(&pn.to_be_bytes()); // 4 字节 pn(明文)

    let mut nonce = iv.clone();
    let pn_be = (pn as u64).to_be_bytes();
    for j in 0..8 {
        nonce[12 - 8 + j] ^= pn_be[j];
    }
    let aad = header.clone();
    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: payload, aad: &aad })
        .unwrap();

    let mut pkt = header.clone();
    pkt.extend_from_slice(&ct);

    // 头保护:采样 pn_offset+4 处 16 字节。
    let sample_off = pn_offset + 4;
    let sample = pkt[sample_off..sample_off + 16].to_vec();
    let mask = aes_ecb_block(&hp, &sample).unwrap();
    pkt[0] ^= mask[0] & 0x0f;
    for j in 0..pn_len {
        pkt[pn_offset + j] ^= mask[1 + j];
    }
    pkt
}

/// 高层便捷:构造一个含给定 `sni` / `alpn` 的合法 v1 客户端 Initial 数据报(测试 / 示例用)。
///
/// `dcid` 可任意(密钥由它派生);包会被 padding 到足够取 16 字节头保护采样。
#[doc(hidden)]
pub fn build_test_initial(dcid: &[u8], sni: &str, alpn: &[&str]) -> Vec<u8> {
    let ch = build_client_hello(sni, alpn);
    // CRYPTO 帧:type 0x06, offset 0, len(varint), data。
    let mut payload = vec![0x06, 0x00];
    payload.extend_from_slice(&enc_varint(ch.len() as u64));
    payload.extend_from_slice(&ch);
    while payload.len() < 64 {
        payload.push(0x00); // PADDING(保证 pn 之后能取到 16 字节采样)
    }
    build_initial_packet(dcid, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9001 Appendix A.1:DCID=0x8394c8f03e515708 → 客户端 key/iv/hp 的官方向量。
    #[test]
    fn rfc9001_client_initial_keys() {
        let dcid = hex("8394c8f03e515708");
        let (key, iv, hp) = derive_client_initial(&dcid);
        assert_eq!(key, hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(iv, hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(hp, hex("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn hmac_sha256_known_vector() {
        // RFC 4231 Test Case 2: key="Jefe", data="what do ya want for nothing?"。
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            mac.to_vec(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn long_header_and_initial_detection() {
        // 构造:b0=0xc0(长包+固定位+Initial), version=1, dcid_len=4 aabbccdd, scid_len=0。
        let pkt = hex("c0 00000001 04 aabbccdd 00");
        assert!(is_long_header(&pkt));
        assert!(is_initial(&pkt));
        let h = parse_long_header(&pkt).unwrap();
        assert_eq!(h.version, 1);
        assert_eq!(h.dcid, hex("aabbccdd"));
        assert!(h.scid.is_empty());
        // 短包(header form=0)不是长包。
        assert!(!is_long_header(&[0x40, 0x00]));
    }

    #[test]
    fn parse_client_hello_sni_and_alpn() {
        let ch = build_client_hello("example.com", &["h3", "h3-29"]);
        let hello = parse_client_hello(&ch).unwrap();
        assert_eq!(hello.sni.as_deref(), Some("example.com"));
        assert_eq!(hello.alpn, vec!["h3".to_string(), "h3-29".to_string()]);
    }

    /// 端到端:自构造一个合法 v1 客户端 Initial(含 ClientHello 的 CRYPTO 帧),加密 + 头保护,
    /// 再走 [`extract_handshake_info`] 解密还原,断言 SNI / ALPN 一致。
    #[test]
    fn end_to_end_extract_sni_from_initial() {
        let dcid = hex("8394c8f03e515708");
        let pkt = build_test_initial(&dcid, "scry.test", &["h3"]);
        let hello = extract_handshake_info(&pkt).expect("should decrypt");
        assert_eq!(hello.sni.as_deref(), Some("scry.test"));
        assert_eq!(hello.alpn, vec!["h3".to_string()]);
        assert_eq!(extract_sni(&pkt).as_deref(), Some("scry.test"));
    }

    #[test]
    fn non_initial_returns_none() {
        // 短包(header form=0):非 Initial。
        assert!(extract_handshake_info(&[0x40, 0x00, 0x01]).is_none());
        // 空 / 截断。
        assert!(extract_handshake_info(&[]).is_none());
    }
}
