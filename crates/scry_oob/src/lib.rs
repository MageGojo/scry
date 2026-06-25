//! Scry OOB(带外 / out-of-band)带外检测 —— **interactsh 协议客户端内核**。
//!
//! 盲漏洞(盲 SSRF / 盲 XXE / 盲 RCE / 盲 SQLi / 盲打 XSS)在响应里看不到任何回显,
//! 唯一可靠的确认方式是「让目标服务器主动回连一个我们控制的带外域名」:在 payload 里塞入
//! 一个唯一子域 `<id>.<server>`,若目标真的发生注入并对该域名发起 DNS / HTTP 请求,
//! 带外服务器(interactsh)就会记录这次交互 → 我们轮询拿到 → 确认漏洞 + 关联到具体探测点。
//!
//! 本 crate 只做**协议 + 密码学**(纯 CPU,可单测),不做任何网络 IO:
//! - [`OobSession::generate`]:生成 RSA-2048 密钥对 + 关联 id + secret。
//! - [`OobSession::register_body`] / [`register_url`](OobSession::register_url):构造注册请求(交 UI runner 经 `replay::send` 发出)。
//! - [`OobSession::new_payload`]:生成一次性带外域名(注入到 payload 里)。
//! - [`OobSession::poll_url`] / [`parse_poll`](OobSession::parse_poll):构造轮询请求 + **解密**轮询响应为 [`Interaction`] 列表。
//!
//! 与 interactsh 官方客户端线缆兼容:
//! - 注册体 `public-key` = base64(PKIX PEM 文本);`secret-key` = 会话密钥;`correlation-id` = 20 字符前缀。
//! - 带外域名 = `correlation-id(20) + 随机(13)` 共 33 字符 + `.<server>`。
//! - 轮询响应:`aes_key` = base64(RSA-OAEP-SHA256 加密的 AES-256 密钥);`data[i]` = base64(IV(16) || AES-256-CFB 密文)。

use rand::Rng;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::collections::HashMap;
use thiserror::Error;

/// interactsh 公共带外服务器(任选其一;墙内需经上游代理才连得上)。
pub const PUBLIC_SERVERS: [&str; 6] = [
    "oast.fun",
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.me",
];

/// 默认带外服务器。
pub fn default_server() -> &'static str {
    PUBLIC_SERVERS[0]
}

/// 关联 id 长度(每个带外域名的前缀,服务器据此把交互归到本会话)。
const CORRELATION_LEN: usize = 20;
/// 带外域名前缀总长(关联 id + 随机后缀);interactsh 约定 33。
const UNIQUE_LEN: usize = 33;
/// id 字符集(小写字母 + 数字,DNS 安全)。
const ID_CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// 带外协议 / 密码学错误。
#[derive(Debug, Error)]
pub enum OobError {
    #[error("RSA 密钥生成失败: {0}")]
    KeyGen(String),
    #[error("RSA 公钥编码失败: {0}")]
    PubKey(String),
    #[error("轮询响应不是合法 JSON: {0}")]
    Json(String),
    #[error("base64 解码失败")]
    Base64,
    #[error("RSA-OAEP 解密 aes_key 失败: {0}")]
    RsaDecrypt(String),
    #[error("AES-256-CFB 解密交互记录失败")]
    AesDecrypt,
    #[error("AES 密钥长度非法(期望 32 字节,实为 {0})")]
    AesKeyLen(usize),
}

/// 一个一次性带外 payload —— 注入到漏洞 payload 里的唯一域名 + 其 33 字符 id(关联用)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OobPayload {
    /// 完整带外主机名(如 `cidxxxxxxxxxxxxxrand.oast.fun`),用于拼进 payload。
    pub host: String,
    /// 33 字符唯一前缀(= host 的首个 label),用于把轮询到的交互关联回探测点。
    pub id: String,
}

impl OobPayload {
    /// 便捷:`http://<host>/` 形式的回连 URL(盲 SSRF / 盲 RCE 常用)。
    pub fn http_url(&self) -> String {
        format!("http://{}/", self.host)
    }
}

/// 一条带外交互记录(目标服务器对我们的带外域名发起的 DNS / HTTP 等回连)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interaction {
    /// 协议:`dns` / `http` / `smtp` / `ldap` 等。
    pub protocol: String,
    /// 被请求的 33 字符唯一 id(= 带外域名首 label,关联回探测点的钥匙)。
    pub unique_id: String,
    /// 完整 id(可能含更多 label)。
    pub full_id: String,
    /// 发起回连的远端地址(= 存在漏洞的目标服务器出口 IP)。
    pub remote_address: String,
    /// 服务器记录的时间戳(原样字符串)。
    pub timestamp: String,
}

/// 一个带外检测会话(一对 RSA 密钥 + 关联 id + secret,可派生任意多个一次性带外域名)。
pub struct OobSession {
    server: String,
    correlation_id: String,
    secret: String,
    priv_key: RsaPrivateKey,
    pub_key_b64: String,
}

impl OobSession {
    /// 生成一个新会话:RSA-2048 密钥对 + 随机关联 id + 随机 secret。
    ///
    /// `server` 为带外服务器域名(如 `oast.fun`)。RSA 密钥生成是 CPU 大头(约数百毫秒),
    /// 一个会话只做一次。
    pub fn generate(server: &str) -> Result<Self, OobError> {
        let mut rng = rand::thread_rng();
        let priv_key =
            RsaPrivateKey::new(&mut rng, 2048).map_err(|e| OobError::KeyGen(e.to_string()))?;
        let pub_key = RsaPublicKey::from(&priv_key);
        let pem = pub_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| OobError::PubKey(e.to_string()))?;
        let pub_key_b64 = base64_encode(pem.as_bytes());
        Ok(Self {
            server: server.trim().trim_end_matches('.').to_string(),
            correlation_id: random_id(CORRELATION_LEN),
            secret: random_uuid(),
            priv_key,
            pub_key_b64,
        })
    }

    /// 带外服务器域名。
    pub fn server(&self) -> &str {
        &self.server
    }

    /// 关联 id(20 字符;每个带外域名的前缀)。
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    /// 注册请求 URL(`https://<server>/register`)。
    pub fn register_url(&self) -> String {
        format!("https://{}/register", self.server)
    }

    /// 轮询请求 URL(`https://<server>/poll?id=<cid>&secret=<secret>`)。
    pub fn poll_url(&self) -> String {
        format!(
            "https://{}/poll?id={}&secret={}",
            self.server, self.correlation_id, self.secret
        )
    }

    /// 注销请求 URL(`https://<server>/deregister`)。
    pub fn deregister_url(&self) -> String {
        format!("https://{}/deregister", self.server)
    }

    /// 注册请求体(JSON):上报公钥 + secret + 关联 id,服务器据此为本会话建桶。
    pub fn register_body(&self) -> String {
        serde_json::json!({
            "public-key": self.pub_key_b64,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id,
        })
        .to_string()
    }

    /// 注销请求体(JSON)。
    pub fn deregister_body(&self) -> String {
        serde_json::json!({
            "secret-key": self.secret,
            "correlation-id": self.correlation_id,
        })
        .to_string()
    }

    /// 生成一个一次性带外 payload(唯一域名 + 33 字符 id)。每次调用都不同,用于区分探测点。
    pub fn new_payload(&self) -> OobPayload {
        let suffix = random_id(UNIQUE_LEN - CORRELATION_LEN);
        let id = format!("{}{}", self.correlation_id, suffix);
        let host = format!("{}.{}", id, self.server);
        OobPayload { host, id }
    }

    /// 解析并**解密**轮询响应(JSON)为交互记录列表。无交互时返回空 `Vec`。
    pub fn parse_poll(&self, json_body: &str) -> Result<Vec<Interaction>, OobError> {
        let v: serde_json::Value =
            serde_json::from_str(json_body).map_err(|e| OobError::Json(e.to_string()))?;

        let data = match v.get("data") {
            Some(serde_json::Value::Array(a)) => a,
            // data 为 null / 缺省 = 暂无交互。
            _ => return Ok(Vec::new()),
        };
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let aes_key_b64 = v
            .get("aes_key")
            .and_then(|x| x.as_str())
            .ok_or(OobError::Base64)?;
        let enc_key = base64_decode(aes_key_b64).ok_or(OobError::Base64)?;
        let aes_key = self
            .priv_key
            .decrypt(Oaep::new::<Sha256>(), &enc_key)
            .map_err(|e| OobError::RsaDecrypt(e.to_string()))?;
        if aes_key.len() != 32 {
            return Err(OobError::AesKeyLen(aes_key.len()));
        }

        let mut out = Vec::new();
        for item in data {
            let Some(s) = item.as_str() else { continue };
            let raw = base64_decode(s).ok_or(OobError::Base64)?;
            let plaintext = aes_cfb_decrypt(&aes_key, &raw)?;
            if let Some(it) = parse_interaction(&plaintext) {
                out.push(it);
            }
        }
        Ok(out)
    }
}

/// 关联辅助:把一批交互记录按 `unique_id` 关联回探测点表(`id -> 任意载荷`),
/// 返回命中的 `(交互, &载荷)` 对。`map` 的 key 是 [`OobPayload::id`]。
pub fn correlate<'a, T>(
    interactions: &'a [Interaction],
    map: &'a HashMap<String, T>,
) -> Vec<(&'a Interaction, &'a T)> {
    let mut out = Vec::new();
    for it in interactions {
        // 优先精确匹配 unique_id;否则在 full_id / unique_id 里找已知 id 前缀(容忍多 label)。
        let hit = map.get(&it.unique_id).or_else(|| {
            map.iter()
                .find(|(id, _)| it.unique_id.contains(id.as_str()) || it.full_id.contains(id.as_str()))
                .map(|(_, v)| v)
        });
        if let Some(v) = hit {
            out.push((it, v));
        }
    }
    out
}

/// 从解密后的 JSON 字节解析出一条交互记录。
fn parse_interaction(bytes: &[u8]) -> Option<Interaction> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let get = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    Some(Interaction {
        protocol: get("protocol"),
        unique_id: get("unique-id"),
        full_id: get("full-id"),
        remote_address: get("remote-address"),
        timestamp: get("timestamp"),
    })
}

/// AES-256-CFB 解密:`raw` = IV(16 字节) || 密文。返回明文。
fn aes_cfb_decrypt(key: &[u8], raw: &[u8]) -> Result<Vec<u8>, OobError> {
    use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
    type Dec = cfb_mode::Decryptor<aes::Aes256>;
    if raw.len() < 16 {
        return Err(OobError::AesDecrypt);
    }
    let (iv, ct) = raw.split_at(16);
    let dec = Dec::new_from_slices(key, iv).map_err(|_| OobError::AesDecrypt)?;
    let mut buf = ct.to_vec();
    dec.decrypt(&mut buf);
    Ok(buf)
}

/// 生成 `len` 字符的随机 id(小写字母 + 数字)。
fn random_id(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| ID_CHARSET[rng.gen_range(0..ID_CHARSET.len())] as char)
        .collect()
}

/// 生成一个随机 UUID v4 风格字符串(作为会话 secret)。
fn random_uuid() -> String {
    let mut rng = rand::thread_rng();
    let mut b = [0u8; 16];
    rng.fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

const B64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// 标准 base64 编码(带 `=` 填充)。
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// 标准 base64 解码(容忍空白与换行;同时兼容 URL-safe 字母 `-_`)。返回 `None` 表示非法输入。
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut bits: u32 = 0;
    let mut nbits = 0;
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for ch in s.bytes() {
        let val = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b'\n' | b'\r' | b' ' | b'\t' => continue,
            _ => return None,
        };
        bits = (bits << 6) | val as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};

    #[test]
    fn base64_roundtrip() {
        for sample in [
            &b""[..],
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            b"hello scry oob",
            &[0u8, 255, 16, 128, 7][..],
        ] {
            let enc = base64_encode(sample);
            let dec = base64_decode(&enc).unwrap();
            assert_eq!(dec, sample, "roundtrip failed for {sample:?}");
        }
    }

    #[test]
    fn base64_decode_ignores_whitespace_and_urlsafe() {
        // 标准带换行 vs URL-safe(-_)应解出同样字节。
        let std = base64_encode(&[251, 255, 191, 0, 1, 2]);
        let with_nl = format!("{}\n{}", &std[..4], &std[4..]);
        assert_eq!(base64_decode(&with_nl).unwrap(), vec![251, 255, 191, 0, 1, 2]);
    }

    #[test]
    fn payload_ids_are_unique_and_prefixed() {
        let s = OobSession::generate("oast.fun").unwrap();
        let a = s.new_payload();
        let b = s.new_payload();
        assert_ne!(a.id, b.id);
        assert_eq!(a.id.len(), UNIQUE_LEN);
        assert!(a.id.starts_with(s.correlation_id()));
        assert!(a.host.ends_with(".oast.fun"));
        assert_eq!(a.http_url(), format!("http://{}/", a.host));
    }

    #[test]
    fn register_body_has_required_fields() {
        let s = OobSession::generate("oast.fun").unwrap();
        let v: serde_json::Value = serde_json::from_str(&s.register_body()).unwrap();
        assert!(v["public-key"].as_str().unwrap().len() > 100);
        assert_eq!(v["correlation-id"].as_str().unwrap(), s.correlation_id());
        assert!(v["secret-key"].as_str().unwrap().contains('-'));
        // 公钥是 base64(PKIX PEM 文本):解开应看到 PEM 头。
        let pem = base64_decode(v["public-key"].as_str().unwrap()).unwrap();
        let pem_txt = String::from_utf8(pem).unwrap();
        assert!(pem_txt.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn empty_poll_yields_no_interactions() {
        let s = OobSession::generate("oast.fun").unwrap();
        assert!(s.parse_poll(r#"{"data":null,"aes_key":null}"#).unwrap().is_empty());
        assert!(s.parse_poll(r#"{"data":[]}"#).unwrap().is_empty());
        assert!(s.parse_poll(r#"{}"#).unwrap().is_empty());
    }

    /// 端到端解密:用会话**公钥**加密一把 AES 密钥 + 用它 AES-CFB 加密一条交互 JSON,
    /// 模拟 interactsh 服务器的轮询响应,断言 [`OobSession::parse_poll`] 能解出原始交互。
    #[test]
    fn parse_poll_decrypts_interaction_end_to_end() {
        let s = OobSession::generate("oast.fun").unwrap();
        let payload = s.new_payload();

        // 服务器侧:随机 AES-256 密钥,用会话公钥 RSA-OAEP 加密。
        let pub_key = RsaPublicKey::from(&s.priv_key);
        let aes_key = [7u8; 32];
        let mut rng = rand::thread_rng();
        let enc_key = pub_key
            .encrypt(&mut rng, Oaep::new::<Sha256>(), &aes_key)
            .unwrap();

        // 一条 DNS 交互记录,unique-id = 我们生成的带外 id。
        let interaction = serde_json::json!({
            "protocol": "dns",
            "unique-id": payload.id,
            "full-id": payload.id,
            "remote-address": "203.0.113.7",
            "timestamp": "2026-06-25T10:00:00Z",
        })
        .to_string();

        // AES-256-CFB 加密:IV(16) || 密文。
        type Enc = cfb_mode::Encryptor<aes::Aes256>;
        let iv = [3u8; 16];
        let mut buf = interaction.clone().into_bytes();
        Enc::new_from_slices(&aes_key, &iv).unwrap().encrypt(&mut buf);
        let mut raw = iv.to_vec();
        raw.extend_from_slice(&buf);

        let resp = serde_json::json!({
            "data": [base64_encode(&raw)],
            "aes_key": base64_encode(&enc_key),
        })
        .to_string();

        let interactions = s.parse_poll(&resp).unwrap();
        assert_eq!(interactions.len(), 1);
        let it = &interactions[0];
        assert_eq!(it.protocol, "dns");
        assert_eq!(it.unique_id, payload.id);
        assert_eq!(it.remote_address, "203.0.113.7");

        // 关联:把交互对回探测点表。
        let mut map = HashMap::new();
        map.insert(payload.id.clone(), "blind-ssrf@/api?url=");
        let hits = correlate(&interactions, &map);
        assert_eq!(hits.len(), 1);
        assert_eq!(*hits[0].1, "blind-ssrf@/api?url=");
    }
}
