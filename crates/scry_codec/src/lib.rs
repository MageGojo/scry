//! Scry 解码器内核(对标 Burp Decoder / CyberChef):一组**文本 → 文本**的编解码 / 加解密 /
//! 哈希变换,外加「智能解码」自动识别一层编码。全部纯函数、零 IO,便于单测与复用。
//!
//! - 编解码(双向):URL 百分号、HTML 实体、Base64、Base32、Base58、Hex、Binary、Unicode `\u` 转义。
//! - 单向:ROT13、JWT 解析(只解码 header/payload,不验签)。
//! - 对称加解密(需密钥):XOR、RC4、AES-CBC / AES-ECB(PKCS7;密文 I/O 走 Base64)。
//! - 哈希 / MAC(单向):MD5 / SHA-1 / SHA-256 / SHA-512 / HMAC-SHA256(输出小写 hex)。
//! - 解码产生的字节按 UTF-8 宽松还原(非法序列 → `�`),保证返回合法 `String`。
//!
//! Base64 / Base32 / Base58 / Hex 等手写(项目惯例:能不引依赖就不引);仅 AES 引入
//! RustCrypto `aes`/`cbc`/`ecb`(纯 Rust、免 cmake),HMAC 用现有 `sha2` 手写构造。

use md5::Digest;
use md5::Md5 as Md5Hasher;
use sha1::Sha1 as Sha1Hasher;
use sha2::{Sha256 as Sha256Hasher, Sha512 as Sha512Hasher};

use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::{
    block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit,
};

/// 无 schema 的 Protobuf / gRPC 线格式解码器。
pub mod protobuf;

/// 变换分类(UI 按此把按钮分组着色)。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Category {
    /// 无密钥的编解码(可逆)。
    Codec,
    /// 需密钥的对称加解密。
    Cipher,
    /// 单向哈希 / MAC。
    Hash,
}

/// 一个可应用到文本上的变换(解码器的一个动作按钮)。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transform {
    UrlEncode,
    UrlDecode,
    HtmlEncode,
    HtmlDecode,
    Base64Encode,
    Base64Decode,
    Base32Encode,
    Base32Decode,
    Base58Encode,
    Base58Decode,
    HexEncode,
    HexDecode,
    BinaryEncode,
    BinaryDecode,
    UnicodeEscape,
    UnicodeUnescape,
    Rot13,
    JwtDecode,
    /// Protobuf / gRPC 解码(输入 hex / base64 / 原始字节 → 字段树)。
    ProtobufDecode,
    // 对称加解密(需密钥;密文 I/O = Base64)
    XorEncrypt,
    XorDecrypt,
    Rc4Encrypt,
    Rc4Decrypt,
    AesCbcEncrypt,
    AesCbcDecrypt,
    AesEcbEncrypt,
    AesEcbDecrypt,
    // 哈希 / MAC
    Md5,
    Sha1,
    Sha256,
    Sha512,
    HmacSha256,
}

impl Transform {
    /// 全部变换(UI 按钮顺序:编解码 → 对称加解密 → 哈希/MAC)。
    pub const ALL: [Transform; 32] = [
        Transform::UrlEncode,
        Transform::UrlDecode,
        Transform::HtmlEncode,
        Transform::HtmlDecode,
        Transform::Base64Encode,
        Transform::Base64Decode,
        Transform::Base32Encode,
        Transform::Base32Decode,
        Transform::Base58Encode,
        Transform::Base58Decode,
        Transform::HexEncode,
        Transform::HexDecode,
        Transform::BinaryEncode,
        Transform::BinaryDecode,
        Transform::UnicodeEscape,
        Transform::UnicodeUnescape,
        Transform::Rot13,
        Transform::JwtDecode,
        Transform::ProtobufDecode,
        Transform::XorEncrypt,
        Transform::XorDecrypt,
        Transform::Rc4Encrypt,
        Transform::Rc4Decrypt,
        Transform::AesCbcEncrypt,
        Transform::AesCbcDecrypt,
        Transform::AesEcbEncrypt,
        Transform::AesEcbDecrypt,
        Transform::Md5,
        Transform::Sha1,
        Transform::Sha256,
        Transform::Sha512,
        Transform::HmacSha256,
    ];

    /// 英文标签(UI 经 i18n 表转中文)。
    pub fn label(self) -> &'static str {
        match self {
            Transform::UrlEncode => "URL encode",
            Transform::UrlDecode => "URL decode",
            Transform::HtmlEncode => "HTML encode",
            Transform::HtmlDecode => "HTML decode",
            Transform::Base64Encode => "Base64 encode",
            Transform::Base64Decode => "Base64 decode",
            Transform::Base32Encode => "Base32 encode",
            Transform::Base32Decode => "Base32 decode",
            Transform::Base58Encode => "Base58 encode",
            Transform::Base58Decode => "Base58 decode",
            Transform::HexEncode => "Hex encode",
            Transform::HexDecode => "Hex decode",
            Transform::BinaryEncode => "Binary encode",
            Transform::BinaryDecode => "Binary decode",
            Transform::UnicodeEscape => "Unicode escape",
            Transform::UnicodeUnescape => "Unicode unescape",
            Transform::Rot13 => "ROT13",
            Transform::JwtDecode => "JWT decode",
            Transform::ProtobufDecode => "Protobuf / gRPC decode",
            Transform::XorEncrypt => "XOR encrypt",
            Transform::XorDecrypt => "XOR decrypt",
            Transform::Rc4Encrypt => "RC4 encrypt",
            Transform::Rc4Decrypt => "RC4 decrypt",
            Transform::AesCbcEncrypt => "AES-CBC encrypt",
            Transform::AesCbcDecrypt => "AES-CBC decrypt",
            Transform::AesEcbEncrypt => "AES-ECB encrypt",
            Transform::AesEcbDecrypt => "AES-ECB decrypt",
            Transform::Md5 => "MD5",
            Transform::Sha1 => "SHA-1",
            Transform::Sha256 => "SHA-256",
            Transform::Sha512 => "SHA-512",
            Transform::HmacSha256 => "HMAC-SHA256",
        }
    }

    /// 分类(UI 分组)。
    pub fn category(self) -> Category {
        if self.is_hash() {
            Category::Hash
        } else if self.needs_key() {
            Category::Cipher
        } else {
            Category::Codec
        }
    }

    /// 是否单向哈希 / MAC(UI 上与编解码按钮分组着色)。
    pub fn is_hash(self) -> bool {
        matches!(
            self,
            Transform::Md5
                | Transform::Sha1
                | Transform::Sha256
                | Transform::Sha512
                | Transform::HmacSha256
        )
    }

    /// 是否需要密钥(XOR / RC4 / AES / HMAC)。
    pub fn needs_key(self) -> bool {
        matches!(
            self,
            Transform::XorEncrypt
                | Transform::XorDecrypt
                | Transform::Rc4Encrypt
                | Transform::Rc4Decrypt
                | Transform::AesCbcEncrypt
                | Transform::AesCbcDecrypt
                | Transform::AesEcbEncrypt
                | Transform::AesEcbDecrypt
                | Transform::HmacSha256
        )
    }

    /// 是否需要 IV(仅 AES-CBC)。
    pub fn needs_iv(self) -> bool {
        matches!(self, Transform::AesCbcEncrypt | Transform::AesCbcDecrypt)
    }

    /// 是否解码方向(失败可能性大,UI 提示用)。
    pub fn is_decode(self) -> bool {
        matches!(
            self,
            Transform::UrlDecode
                | Transform::HtmlDecode
                | Transform::Base64Decode
                | Transform::Base32Decode
                | Transform::Base58Decode
                | Transform::HexDecode
                | Transform::BinaryDecode
                | Transform::UnicodeUnescape
                | Transform::JwtDecode
                | Transform::ProtobufDecode
                | Transform::XorDecrypt
                | Transform::Rc4Decrypt
                | Transform::AesCbcDecrypt
                | Transform::AesEcbDecrypt
        )
    }

    /// 应用变换(无密钥版;keyed 变换会因缺密钥报错)。
    pub fn apply(self, input: &str) -> Result<String, String> {
        self.apply_with(input, "", "")
    }

    /// 应用变换。`key` / `iv` 仅 keyed 变换使用(按 UTF-8 字节解释),其余忽略。
    /// 编码 / 哈希恒成功;解码 / 解密非法输入返回 `Err(中文原因)`。
    pub fn apply_with(self, input: &str, key: &str, iv: &str) -> Result<String, String> {
        match self {
            Transform::UrlEncode => Ok(url_encode(input)),
            Transform::UrlDecode => Ok(url_decode(input)),
            Transform::HtmlEncode => Ok(html_encode(input)),
            Transform::HtmlDecode => Ok(html_decode(input)),
            Transform::Base64Encode => Ok(base64_encode(input)),
            Transform::Base64Decode => base64_decode(input),
            Transform::Base32Encode => Ok(base32_encode(input.as_bytes())),
            Transform::Base32Decode => {
                base32_decode(input).map(|b| String::from_utf8_lossy(&b).into_owned())
            }
            Transform::ProtobufDecode => protobuf::decode_text_input(input),
            Transform::Base58Encode => Ok(base58_encode(input.as_bytes())),
            Transform::Base58Decode => {
                base58_decode(input).map(|b| String::from_utf8_lossy(&b).into_owned())
            }
            Transform::HexEncode => Ok(hex_encode(input)),
            Transform::HexDecode => hex_decode(input),
            Transform::BinaryEncode => Ok(binary_encode(input.as_bytes())),
            Transform::BinaryDecode => {
                binary_decode(input).map(|b| String::from_utf8_lossy(&b).into_owned())
            }
            Transform::UnicodeEscape => Ok(unicode_escape(input)),
            Transform::UnicodeUnescape => Ok(unicode_unescape(input)),
            Transform::Rot13 => Ok(rot13(input)),
            Transform::JwtDecode => jwt_decode(input),
            Transform::XorEncrypt => xor_encrypt(input, key),
            Transform::XorDecrypt => xor_decrypt(input, key),
            Transform::Rc4Encrypt => rc4_encrypt(input, key),
            Transform::Rc4Decrypt => rc4_decrypt(input, key),
            Transform::AesCbcEncrypt => aes_encrypt(AesMode::Cbc, input, key, iv),
            Transform::AesCbcDecrypt => aes_decrypt(AesMode::Cbc, input, key, iv),
            Transform::AesEcbEncrypt => aes_encrypt(AesMode::Ecb, input, key, iv),
            Transform::AesEcbDecrypt => aes_decrypt(AesMode::Ecb, input, key, iv),
            Transform::Md5 => Ok(hash_hex::<Md5Hasher>(input)),
            Transform::Sha1 => Ok(hash_hex::<Sha1Hasher>(input)),
            Transform::Sha256 => Ok(hash_hex::<Sha256Hasher>(input)),
            Transform::Sha512 => Ok(hash_hex::<Sha512Hasher>(input)),
            Transform::HmacSha256 => hmac_sha256(input, key),
        }
    }
}

// ── 半字节 / 十六进制工具 ────────────────────────────────────────────

fn hex_lower(n: u8) -> char {
    (if n < 10 { b'0' + n } else { b'a' + n - 10 }) as char
}

fn hex_upper(n: u8) -> char {
    (if n < 10 { b'0' + n } else { b'A' + n - 10 }) as char
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ── URL 百分号编码 ──────────────────────────────────────────────────

/// 百分号编码:仅保留 RFC 3986 unreserved(`A-Za-z0-9-_.~`),其余字节 → `%XX`(大写)。
pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(hex_upper(b >> 4));
            out.push(hex_upper(b & 0x0f));
        }
    }
    out
}

/// 百分号解码:`%XX` → 字节;非法 / 不完整的 `%` 序列原样保留(容错,贴近 Burp)。
pub fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ── HTML 实体 ───────────────────────────────────────────────────────

/// HTML 实体编码:转义 `& < > " '`(够防 XSS 上下文注入)。
pub fn html_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// HTML 实体解码:命名实体(常见集)+ `&#NN;` 十进制 + `&#xHH;` 十六进制;未识别的原样保留。
pub fn html_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp..];
        if let Some(semi) = after.find(';') {
            let entity = &after[1..semi];
            if entity.len() <= 15
                && !entity.contains('&')
                && !entity.chars().any(char::is_whitespace)
            {
                if let Some(ch) = decode_entity(entity) {
                    out.push(ch);
                    rest = &after[semi + 1..];
                    continue;
                }
            }
        }
        out.push('&');
        rest = &after[1..];
    }
    out.push_str(rest);
    out
}

/// 解析单个实体名(不含首 `&` 与尾 `;`)。
fn decode_entity(e: &str) -> Option<char> {
    if let Some(num) = e.strip_prefix('#') {
        let code = if let Some(hex) = num.strip_prefix(['x', 'X']) {
            u32::from_str_radix(hex, 16).ok()?
        } else {
            num.parse::<u32>().ok()?
        };
        return char::from_u32(code);
    }
    Some(match e {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => '\u{00A0}',
        "copy" => '\u{00A9}',
        "reg" => '\u{00AE}',
        "trade" => '\u{2122}',
        "hellip" => '\u{2026}',
        "mdash" => '\u{2014}',
        "ndash" => '\u{2013}',
        "lsquo" => '\u{2018}',
        "rsquo" => '\u{2019}',
        "ldquo" => '\u{201C}',
        "rdquo" => '\u{201D}',
        "euro" => '\u{20AC}',
        "pound" => '\u{00A3}',
        "cent" => '\u{00A2}',
        "yen" => '\u{00A5}',
        "sect" => '\u{00A7}',
        "middot" => '\u{00B7}',
        "times" => '\u{00D7}',
        "divide" => '\u{00F7}',
        _ => return None,
    })
}

// ── Base64 ──────────────────────────────────────────────────────────

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 编码(标准字母表,带 `=` 填充)。
pub fn base64_encode(s: &str) -> String {
    bytes_to_base64(s.as_bytes())
}

/// Base64 字符 → 6 bit 值;接受标准与 URL-safe(`-_`)字母表。
fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

fn base64_decode_bytes(s: &str) -> Result<Vec<u8>, String> {
    let mut vals: Vec<u8> = Vec::with_capacity(s.len());
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        match b64_val(c) {
            Some(v) => vals.push(v),
            None => return Err(format!("非法 Base64 字符:{:?}", c as char)),
        }
    }
    let mut out = Vec::with_capacity(vals.len() / 4 * 3);
    for chunk in vals.chunks(4) {
        match chunk.len() {
            1 => return Err("Base64 长度非法(末尾多 1 个字符)".into()),
            2 => {
                let n = ((chunk[0] as u32) << 18) | ((chunk[1] as u32) << 12);
                out.push((n >> 16) as u8);
            }
            3 => {
                let n = ((chunk[0] as u32) << 18)
                    | ((chunk[1] as u32) << 12)
                    | ((chunk[2] as u32) << 6);
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
            }
            _ => {
                let n = ((chunk[0] as u32) << 18)
                    | ((chunk[1] as u32) << 12)
                    | ((chunk[2] as u32) << 6)
                    | (chunk[3] as u32);
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
        }
    }
    Ok(out)
}

/// Base64 解码(容错:忽略空白、可选填充、接受 URL-safe);结果按 UTF-8 宽松还原。
pub fn base64_decode(s: &str) -> Result<String, String> {
    let bytes = base64_decode_bytes(s)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

// ── Hex ─────────────────────────────────────────────────────────────

/// 十六进制编码(每字节两位小写)。
pub fn hex_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for &b in s.as_bytes() {
        out.push(hex_lower(b >> 4));
        out.push(hex_lower(b & 0x0f));
    }
    out
}

fn hex_decode_bytes(s: &str) -> Result<Vec<u8>, String> {
    let mut nibbles: Vec<u8> = Vec::with_capacity(s.len());
    for &c in s.as_bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        match hex_val(c) {
            Some(v) => nibbles.push(v),
            None => return Err(format!("非法十六进制字符:{:?}", c as char)),
        }
    }
    if !nibbles.len().is_multiple_of(2) {
        return Err("十六进制位数必须为偶数".into());
    }
    Ok(nibbles.chunks(2).map(|p| (p[0] << 4) | p[1]).collect())
}

/// 十六进制解码(忽略空白);结果按 UTF-8 宽松还原。
pub fn hex_decode(s: &str) -> Result<String, String> {
    let bytes = hex_decode_bytes(s)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

// ── 哈希 ────────────────────────────────────────────────────────────

fn hash_hex<D: Digest>(input: &str) -> String {
    let mut hasher = D::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    to_hex(&digest)
}

/// 字节序列 → 小写十六进制串。
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(hex_lower(b >> 4));
        s.push(hex_lower(b & 0x0f));
    }
    s
}

// ── Base32(RFC 4648,带 = 填充)──────────────────────────────────────

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base32 编码:每 5 字节 → 8 个字符,不足补 `=`。
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    for chunk in data.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = ((buf[0] as u64) << 32)
            | ((buf[1] as u64) << 24)
            | ((buf[2] as u64) << 16)
            | ((buf[3] as u64) << 8)
            | (buf[4] as u64);
        // 每个 chunk 输出的有效字符数(按输入字节数):1→2,2→4,3→5,4→7,5→8。
        let chars = match chunk.len() {
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            _ => 8,
        };
        for i in 0..8 {
            if i < chars {
                out.push(B32[((n >> (35 - i * 5)) & 31) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn b32_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a'),
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    }
}

/// Base32 解码(容错:忽略空白与 `=`,接受大小写)。
pub fn base32_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut vals: Vec<u8> = Vec::with_capacity(s.len());
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        match b32_val(c) {
            Some(v) => vals.push(v),
            None => return Err(format!("非法 Base32 字符:{:?}", c as char)),
        }
    }
    let mut out = Vec::with_capacity(vals.len() * 5 / 8);
    for chunk in vals.chunks(8) {
        let mut n: u64 = 0;
        for (i, &v) in chunk.iter().enumerate() {
            n |= (v as u64) << (35 - i * 5);
        }
        // 有效字符数 → 还原字节数:2→1,4→2,5→3,7→4,8→5。
        let bytes = match chunk.len() {
            2 => 1,
            4 => 2,
            5 => 3,
            7 => 4,
            8 => 5,
            other => return Err(format!("Base32 长度非法(组内 {other} 个字符)")),
        };
        for i in 0..bytes {
            out.push((n >> (32 - i * 8)) as u8);
        }
    }
    Ok(out)
}

// ── Base58(比特币字母表)─────────────────────────────────────────────

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58 编码(大整数进制转换,保留前导零 → `1`)。
pub fn base58_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    // 以 base-256 大数反复除以 58 取余(在 u8 数组上做长除法)。
    let mut digits: Vec<u8> = Vec::new();
    for &byte in &data[zeros..] {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(B58[d as usize] as char);
    }
    out
}

fn b58_val(c: u8) -> Option<u8> {
    B58.iter().position(|&x| x == c).map(|p| p as u8)
}

/// Base58 解码(忽略空白)。
pub fn base58_decode(s: &str) -> Result<Vec<u8>, String> {
    let trimmed: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let zeros = trimmed.iter().take_while(|&&c| c == b'1').count();
    let mut bytes: Vec<u8> = Vec::new();
    for &c in &trimmed[zeros..] {
        let mut carry = b58_val(c).ok_or_else(|| format!("非法 Base58 字符:{:?}", c as char))? as u32;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = Vec::with_capacity(zeros + bytes.len());
    out.extend(std::iter::repeat_n(0u8, zeros));
    out.extend(bytes.iter().rev());
    Ok(out)
}

// ── Binary(8 位二进制)───────────────────────────────────────────────

/// 二进制编码:每字节 8 位,字节间空格分隔。
pub fn binary_encode(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:08b}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// 二进制解码:取所有 0/1 位(忽略其它字符),每 8 位 → 一字节。
pub fn binary_decode(s: &str) -> Result<Vec<u8>, String> {
    let bits: Vec<u8> = s.bytes().filter(|&b| b == b'0' || b == b'1').collect();
    if bits.is_empty() {
        return Err("未找到二进制位(0/1)".into());
    }
    if !bits.len().is_multiple_of(8) {
        return Err(format!("二进制位数必须为 8 的倍数(当前 {})", bits.len()));
    }
    Ok(bits
        .chunks(8)
        .map(|byte| byte.iter().fold(0u8, |acc, &b| (acc << 1) | (b - b'0')))
        .collect())
}

// ── Unicode \u 转义 ───────────────────────────────────────────────────

/// Unicode 转义:非 ASCII 字符 → `\uXXXX`(astral 字符走代理对)。
pub fn unicode_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else {
            let mut buf = [0u16; 2];
            for u in ch.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{u:04x}"));
            }
        }
    }
    out
}

/// Unicode 反转义:把 `\uXXXX`(含代理对)还原;其余字符原样保留。
pub fn unicode_unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut units: Vec<u16> = Vec::new();
    let mut out = String::with_capacity(s.len());
    let flush = |units: &mut Vec<u16>, out: &mut String| {
        if !units.is_empty() {
            out.push_str(&String::from_utf16_lossy(units));
            units.clear();
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 5 < bytes.len() && (bytes[i + 1] == b'u' || bytes[i + 1] == b'U')
        {
            let hex = &s[i + 2..i + 6];
            if let Ok(u) = u16::from_str_radix(hex, 16) {
                units.push(u);
                i += 6;
                continue;
            }
        }
        flush(&mut units, &mut out);
        // 推进一个完整 UTF-8 字符。
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    flush(&mut units, &mut out);
    out
}

// ── ROT13 ─────────────────────────────────────────────────────────────

/// ROT13:字母循环位移 13;非字母原样。
pub fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            _ => c,
        })
        .collect()
}

// ── JWT 解码(只解码,不验签)──────────────────────────────────────────

/// 解码 JWT:`header.payload.signature` → 展示 Header / Payload(base64url 解码)+ 原始签名。
pub fn jwt_decode(s: &str) -> Result<String, String> {
    let t = s.trim();
    let parts: Vec<&str> = t.split('.').collect();
    if parts.len() < 2 {
        return Err("不是 JWT(应为 header.payload.signature)".into());
    }
    let header = base64_decode(parts[0]).map_err(|e| format!("Header 解码失败:{e}"))?;
    let payload = base64_decode(parts[1]).map_err(|e| format!("Payload 解码失败:{e}"))?;
    let sig = parts.get(2).copied().unwrap_or("");
    Ok(format!(
        "[Header]\n{header}\n\n[Payload]\n{payload}\n\n[Signature(原始,未验证)]\n{sig}"
    ))
}

// ── XOR(重复密钥;密文 I/O = Base64)────────────────────────────────

fn xor_bytes(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

fn xor_encrypt(input: &str, key: &str) -> Result<String, String> {
    if key.is_empty() {
        return Err("XOR 需要密钥".into());
    }
    Ok(bytes_to_base64(&xor_bytes(input.as_bytes(), key.as_bytes())))
}

fn xor_decrypt(input: &str, key: &str) -> Result<String, String> {
    if key.is_empty() {
        return Err("XOR 需要密钥".into());
    }
    let ct = base64_decode_bytes(input).map_err(|_| "密文需为 Base64".to_string())?;
    Ok(String::from_utf8_lossy(&xor_bytes(&ct, key.as_bytes())).into_owned())
}

// ── RC4(密文 I/O = Base64)──────────────────────────────────────────

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    data.iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
            b ^ k
        })
        .collect()
}

fn rc4_encrypt(input: &str, key: &str) -> Result<String, String> {
    if key.is_empty() {
        return Err("RC4 需要密钥".into());
    }
    Ok(bytes_to_base64(&rc4(key.as_bytes(), input.as_bytes())))
}

fn rc4_decrypt(input: &str, key: &str) -> Result<String, String> {
    if key.is_empty() {
        return Err("RC4 需要密钥".into());
    }
    let ct = base64_decode_bytes(input).map_err(|_| "密文需为 Base64".to_string())?;
    Ok(String::from_utf8_lossy(&rc4(key.as_bytes(), &ct)).into_owned())
}

// ── AES-CBC / AES-ECB(PKCS7;密钥 16/24/32 字节;密文 I/O = Base64)──

#[derive(Clone, Copy)]
enum AesMode {
    Cbc,
    Ecb,
}

fn aes_key_err(n: usize) -> String {
    format!("AES 密钥需 16/24/32 字节(当前 {n} 字节)")
}

fn cbc_enc<C: KeyIvInit + BlockEncryptMut>(key: &[u8], iv: &[u8], pt: &[u8]) -> Result<Vec<u8>, String> {
    let c = C::new_from_slices(key, iv).map_err(|_| "AES 密钥/IV 长度非法(IV 需 16 字节)".to_string())?;
    Ok(c.encrypt_padded_vec_mut::<Pkcs7>(pt))
}

fn cbc_dec<C: KeyIvInit + BlockDecryptMut>(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
    let c = C::new_from_slices(key, iv).map_err(|_| "AES 密钥/IV 长度非法(IV 需 16 字节)".to_string())?;
    c.decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map_err(|_| "AES 解密失败(密钥/IV 错误或密文非法)".to_string())
}

fn ecb_enc<C: KeyInit + BlockEncryptMut>(key: &[u8], pt: &[u8]) -> Result<Vec<u8>, String> {
    let c = C::new_from_slice(key).map_err(|_| aes_key_err(key.len()))?;
    Ok(c.encrypt_padded_vec_mut::<Pkcs7>(pt))
}

fn ecb_dec<C: KeyInit + BlockDecryptMut>(key: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
    let c = C::new_from_slice(key).map_err(|_| aes_key_err(key.len()))?;
    c.decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map_err(|_| "AES 解密失败(密钥错误或密文非法)".to_string())
}

fn aes_encrypt(mode: AesMode, input: &str, key: &str, iv: &str) -> Result<String, String> {
    let k = key.as_bytes();
    let iv = iv.as_bytes();
    let pt = input.as_bytes();
    let ct = match mode {
        AesMode::Cbc => match k.len() {
            16 => cbc_enc::<cbc::Encryptor<Aes128>>(k, iv, pt)?,
            24 => cbc_enc::<cbc::Encryptor<Aes192>>(k, iv, pt)?,
            32 => cbc_enc::<cbc::Encryptor<Aes256>>(k, iv, pt)?,
            n => return Err(aes_key_err(n)),
        },
        AesMode::Ecb => match k.len() {
            16 => ecb_enc::<ecb::Encryptor<Aes128>>(k, pt)?,
            24 => ecb_enc::<ecb::Encryptor<Aes192>>(k, pt)?,
            32 => ecb_enc::<ecb::Encryptor<Aes256>>(k, pt)?,
            n => return Err(aes_key_err(n)),
        },
    };
    Ok(bytes_to_base64(&ct))
}

fn aes_decrypt(mode: AesMode, input: &str, key: &str, iv: &str) -> Result<String, String> {
    let k = key.as_bytes();
    let iv = iv.as_bytes();
    let ct = base64_decode_bytes(input).map_err(|_| "密文需为 Base64".to_string())?;
    let pt = match mode {
        AesMode::Cbc => match k.len() {
            16 => cbc_dec::<cbc::Decryptor<Aes128>>(k, iv, &ct)?,
            24 => cbc_dec::<cbc::Decryptor<Aes192>>(k, iv, &ct)?,
            32 => cbc_dec::<cbc::Decryptor<Aes256>>(k, iv, &ct)?,
            n => return Err(aes_key_err(n)),
        },
        AesMode::Ecb => match k.len() {
            16 => ecb_dec::<ecb::Decryptor<Aes128>>(k, &ct)?,
            24 => ecb_dec::<ecb::Decryptor<Aes192>>(k, &ct)?,
            32 => ecb_dec::<ecb::Decryptor<Aes256>>(k, &ct)?,
            n => return Err(aes_key_err(n)),
        },
    };
    Ok(String::from_utf8_lossy(&pt).into_owned())
}

// ── HMAC-SHA256(手写构造,复用 sha2)────────────────────────────────

fn hmac_sha256(input: &str, key: &str) -> Result<String, String> {
    if key.is_empty() {
        return Err("HMAC 需要密钥".into());
    }
    const BLOCK: usize = 64;
    let mut k = key.as_bytes().to_vec();
    if k.len() > BLOCK {
        let mut h = Sha256Hasher::new();
        h.update(&k);
        k = h.finalize().to_vec();
    }
    k.resize(BLOCK, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut hi = Sha256Hasher::new();
    hi.update(&ipad);
    hi.update(input.as_bytes());
    let inner = hi.finalize();
    let mut ho = Sha256Hasher::new();
    ho.update(&opad);
    ho.update(inner);
    Ok(to_hex(&ho.finalize()))
}

// ── 密文 Base64(无空白,标准字母表)──────────────────────────────────

/// 字节 → 标准 Base64(带填充);加解密结果统一用它,便于复制粘贴。
fn bytes_to_base64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

// ── 智能解码 ────────────────────────────────────────────────────────

/// 自动识别并解开**一层**编码:依次尝试 URL → HTML → Hex → Base64,
/// 命中(且结果与原文不同 / 多数可打印)即返回 `(命中的变换, 结果)`;都不像则 `None`。
pub fn smart_decode(input: &str) -> Option<(Transform, String)> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    if looks_url_encoded(trimmed) {
        let s = url_decode(trimmed);
        if s != trimmed {
            return Some((Transform::UrlDecode, s));
        }
    }
    if looks_html(trimmed) {
        let s = html_decode(trimmed);
        if s != trimmed {
            return Some((Transform::HtmlDecode, s));
        }
    }
    if looks_hex(trimmed) {
        if let Ok(bytes) = hex_decode_bytes(trimmed) {
            if mostly_printable(&bytes) {
                return Some((
                    Transform::HexDecode,
                    String::from_utf8_lossy(&bytes).into_owned(),
                ));
            }
        }
    }
    if looks_base64(trimmed) {
        if let Ok(bytes) = base64_decode_bytes(trimmed) {
            if !bytes.is_empty() && mostly_printable(&bytes) {
                return Some((
                    Transform::Base64Decode,
                    String::from_utf8_lossy(&bytes).into_owned(),
                ));
            }
        }
    }
    None
}

fn looks_url_encoded(s: &str) -> bool {
    s.as_bytes()
        .windows(3)
        .any(|w| w[0] == b'%' && hex_val(w[1]).is_some() && hex_val(w[2]).is_some())
}

fn looks_html(s: &str) -> bool {
    s.contains('&') && s.contains(';') && html_decode(s) != s
}

fn looks_hex(s: &str) -> bool {
    let mut n = 0usize;
    for c in s.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if hex_val(c).is_none() {
            return false;
        }
        n += 1;
    }
    n >= 4 && n.is_multiple_of(2)
}

fn looks_base64(s: &str) -> bool {
    // 含空格 = 多半是句子而非 base64 令牌,直接否决(降低误判)。
    if s.contains(' ') {
        return false;
    }
    let mut n = 0usize;
    for c in s.bytes() {
        if c.is_ascii_whitespace() || c == b'=' {
            continue;
        }
        if b64_val(c).is_none() {
            return false;
        }
        n += 1;
    }
    // 4 个有效字符即可解出 ≥3 字节;`n % 4 == 1` 是不可能的 base64 长度。
    n >= 4 && n % 4 != 1
}

/// 解出的字节是否「多数可打印」(用于智能解码判定:避免把随机串误判成有意义明文)。
fn mostly_printable(b: &[u8]) -> bool {
    if b.is_empty() {
        return false;
    }
    let text = String::from_utf8_lossy(b);
    let total = text.chars().count().max(1);
    let bad = text
        .chars()
        .filter(|&c| c == '\u{FFFD}' || (c.is_control() && !matches!(c, '\n' | '\r' | '\t')))
        .count();
    (bad as f64 / total as f64) < 0.15
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_basic() {
        assert_eq!(url_encode("a b"), "a%20b");
        assert_eq!(url_encode("你"), "%E4%BD%A0");
        assert_eq!(url_encode("safe-_.~AZ09"), "safe-_.~AZ09");
    }

    #[test]
    fn url_decode_basic_and_tolerant() {
        assert_eq!(url_decode("%E4%BD%A0%E5%A5%BD"), "你好");
        assert_eq!(url_decode("a%20b"), "a b");
        // 非法 / 不完整的 % 原样保留。
        assert_eq!(url_decode("100%"), "100%");
        assert_eq!(url_decode("%zz"), "%zz");
    }

    #[test]
    fn url_roundtrip() {
        let s = "key=值&x=1 2/3?#";
        assert_eq!(url_decode(&url_encode(s)), s);
    }

    #[test]
    fn html_encode_decode() {
        assert_eq!(html_encode("<a href=\"x\">&'"), "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
        assert_eq!(html_decode("&lt;b&gt;&amp;&#39;"), "<b>&'");
        assert_eq!(html_decode("&#65;&#x42;"), "AB");
        assert_eq!(html_decode("a&copy;b"), "a\u{00A9}b");
        // 未识别实体原样保留。
        assert_eq!(html_decode("100% &notreal; ok"), "100% &notreal; ok");
        assert_eq!(html_decode("AT&T"), "AT&T");
    }

    #[test]
    fn base64_encode_vectors() {
        assert_eq!(base64_encode(""), "");
        assert_eq!(base64_encode("M"), "TQ==");
        assert_eq!(base64_encode("Ma"), "TWE=");
        assert_eq!(base64_encode("Man"), "TWFu");
        assert_eq!(base64_encode("Hello"), "SGVsbG8=");
    }

    #[test]
    fn base64_decode_tolerant() {
        assert_eq!(base64_decode("TWFu").unwrap(), "Man");
        assert_eq!(base64_decode("SGVsbG8=").unwrap(), "Hello");
        // 忽略空白 / 换行。
        assert_eq!(base64_decode("SGVs\nbG8=").unwrap(), "Hello");
        // 缺填充也能解。
        assert_eq!(base64_decode("TQ").unwrap(), "M");
        // URL-safe 字母表。
        assert_eq!(base64_decode("-_-_").unwrap(), base64_decode("+/+/").unwrap());
        assert!(base64_decode("@@@").is_err());
    }

    #[test]
    fn base64_roundtrip() {
        let s = "任意 UTF-8 文本 123 !@#";
        assert_eq!(base64_decode(&base64_encode(s)).unwrap(), s);
    }

    #[test]
    fn hex_encode_decode() {
        assert_eq!(hex_encode("AB"), "4142");
        assert_eq!(hex_decode("4142").unwrap(), "AB");
        // 忽略空白。
        assert_eq!(hex_decode("48 65 6c 6c 6f").unwrap(), "Hello");
        assert!(hex_decode("abc").is_err()); // 奇数位
        assert!(hex_decode("zz").is_err()); // 非法字符
    }

    #[test]
    fn hash_vectors() {
        assert_eq!(
            Transform::Md5.apply("").unwrap(),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        assert_eq!(
            Transform::Md5.apply("abc").unwrap(),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            Transform::Sha1.apply("abc").unwrap(),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            Transform::Sha256.apply("abc").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            Transform::Sha512.apply("abc").unwrap(),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn smart_decode_detects_layer() {
        assert_eq!(
            smart_decode("%E4%BD%A0%E5%A5%BD"),
            Some((Transform::UrlDecode, "你好".to_string()))
        );
        assert_eq!(
            smart_decode("SGVsbG8="),
            Some((Transform::Base64Decode, "Hello".to_string()))
        );
        assert_eq!(
            smart_decode("48656c6c6f"),
            Some((Transform::HexDecode, "Hello".to_string()))
        );
        assert_eq!(
            smart_decode("&lt;b&gt;"),
            Some((Transform::HtmlDecode, "<b>".to_string()))
        );
        assert_eq!(smart_decode("just plain words"), None);
        assert_eq!(smart_decode(""), None);
    }

    #[test]
    fn transform_metadata() {
        assert_eq!(Transform::ALL.len(), 32);
        assert!(Transform::Md5.is_hash());
        assert!(Transform::HmacSha256.is_hash());
        assert!(!Transform::UrlEncode.is_hash());
        assert!(Transform::HexDecode.is_decode());
        assert!(!Transform::HexEncode.is_decode());
        // 分类与密钥需求。
        assert_eq!(Transform::UrlEncode.category(), Category::Codec);
        assert_eq!(Transform::AesCbcEncrypt.category(), Category::Cipher);
        assert_eq!(Transform::HmacSha256.category(), Category::Hash);
        assert!(Transform::Rc4Encrypt.needs_key());
        assert!(!Transform::Base32Encode.needs_key());
        assert!(Transform::AesCbcEncrypt.needs_iv());
        assert!(!Transform::AesEcbEncrypt.needs_iv());
    }

    #[test]
    fn base32_roundtrip_and_vectors() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI======");
        assert_eq!(base32_encode(b"f"), "MY======");
        assert_eq!(base32_decode("MZXW6YTBOI======").unwrap(), b"foobar");
        // 容错:忽略空白与填充、接受小写。
        assert_eq!(base32_decode("mzxw6 ytboi").unwrap(), b"foobar");
        assert!(base32_decode("8888").is_err());
    }

    #[test]
    fn base58_roundtrip_and_leading_zeros() {
        assert_eq!(base58_encode(b"Hello World!"), "2NEpo7TZRRrLZSi2U");
        assert_eq!(base58_decode("2NEpo7TZRRrLZSi2U").unwrap(), b"Hello World!");
        // 前导零字节 → 前导 '1'。
        assert_eq!(base58_encode(&[0, 0, 1]), "112");
        assert_eq!(base58_decode("112").unwrap(), vec![0, 0, 1]);
        assert!(base58_decode("0OIl").is_err()); // 字母表外字符
    }

    #[test]
    fn binary_roundtrip() {
        assert_eq!(binary_encode(b"AB"), "01000001 01000010");
        assert_eq!(binary_decode("01000001 01000010").unwrap(), b"AB");
        assert_eq!(binary_decode("0100000101000010").unwrap(), b"AB");
        assert!(binary_decode("0101").is_err()); // 非 8 倍数
        assert!(binary_decode("xyz").is_err()); // 无 0/1
    }

    #[test]
    fn unicode_escape_roundtrip() {
        assert_eq!(unicode_escape("A你"), "A\\u4f60");
        assert_eq!(unicode_unescape("A\\u4f60"), "A你");
        // astral(emoji)走代理对。
        let s = "x😀y";
        assert_eq!(unicode_unescape(&unicode_escape(s)), s);
        // 非转义内容原样。
        assert_eq!(unicode_unescape("plain ascii"), "plain ascii");
    }

    #[test]
    fn rot13_is_involution() {
        assert_eq!(rot13("Hello, World!"), "Uryyb, Jbeyq!");
        assert_eq!(rot13(&rot13("Hello, World!")), "Hello, World!");
    }

    #[test]
    fn jwt_decode_header_payload() {
        // {"alg":"HS256","typ":"JWT"} . {"sub":"1","name":"a"} . sig
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6ImEifQ.SIG";
        let out = Transform::JwtDecode.apply(jwt).unwrap();
        assert!(out.contains("\"alg\":\"HS256\""));
        assert!(out.contains("\"name\":\"a\""));
        assert!(out.contains("SIG"));
        assert!(Transform::JwtDecode.apply("notajwt").is_err());
    }

    #[test]
    fn xor_roundtrip_and_needs_key() {
        let ct = Transform::XorEncrypt.apply_with("secret", "k", "").unwrap();
        assert_eq!(
            Transform::XorDecrypt.apply_with(&ct, "k", "").unwrap(),
            "secret"
        );
        assert!(Transform::XorEncrypt.apply_with("x", "", "").is_err());
    }

    #[test]
    fn rc4_known_vector_and_roundtrip() {
        // RC4(key="Key", "Plaintext") = BBF316E8D940AF0AD3(hex)。
        let ct = Transform::Rc4Encrypt.apply_with("Plaintext", "Key", "").unwrap();
        let raw = base64_decode_bytes(&ct).unwrap();
        assert_eq!(to_hex(&raw), "bbf316e8d940af0ad3");
        assert_eq!(
            Transform::Rc4Decrypt.apply_with(&ct, "Key", "").unwrap(),
            "Plaintext"
        );
    }

    #[test]
    fn aes_cbc_roundtrip() {
        let key = "0123456789abcdef"; // 16 字节 → AES-128
        let iv = "abcdef9876543210";
        let ct = Transform::AesCbcEncrypt
            .apply_with("hello aes cbc", key, iv)
            .unwrap();
        assert_eq!(
            Transform::AesCbcDecrypt.apply_with(&ct, key, iv).unwrap(),
            "hello aes cbc"
        );
        // 密钥长度非法报错。
        assert!(Transform::AesCbcEncrypt.apply_with("x", "short", iv).is_err());
    }

    #[test]
    fn aes_ecb_roundtrip_256() {
        let key = "0123456789abcdef0123456789abcdef"; // 32 字节 → AES-256
        let ct = Transform::AesEcbEncrypt.apply_with("ecb mode", key, "").unwrap();
        assert_eq!(
            Transform::AesEcbDecrypt.apply_with(&ct, key, "").unwrap(),
            "ecb mode"
        );
    }

    #[test]
    fn hmac_sha256_vector() {
        // 标准向量:HMAC-SHA256(key="key", "The quick brown fox jumps over the lazy dog")
        let mac = Transform::HmacSha256
            .apply_with("The quick brown fox jumps over the lazy dog", "key", "")
            .unwrap();
        assert_eq!(
            mac,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
        assert!(Transform::HmacSha256.apply_with("x", "", "").is_err());
    }
}
