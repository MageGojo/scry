//! 密码学瑞士军刀 CLI —— 复用 scry 内核已用的 `md-5` / `sha2` 依赖,提供打靶常用的
//! base64url / md5 / sha256 / HMAC-SHA256 / JWT 伪造与解码原语(JWT alg:none、弱密钥 HS256 伪造、
//! 可预测重置令牌、kid 注入等题用)。
//!
//! 用法:
//! ```text
//! cargo run -p scry_proxy --example crypto -- <op> [args...]
//! ```
//! op:
//! - `b64url-enc <s>` / `b64url-dec <s>`
//! - `md5 <s>` / `sha256 <s>` / `hmac256 <key> <msg>`
//! - `jwt-none <payload-json>`            → 伪造 alg:none 令牌(空签名)
//! - `jwt-hs256 <secret> <payload-json>`  → 用弱密钥签 HS256 令牌
//! - `jwt-decode <token>`                 → 解码 header / payload

use md5::Md5;
use sha2::{Digest, Sha256};

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[(n & 63) as usize] as char);
        }
    }
    out
}

fn b64url_decode(s: &str) -> Vec<u8> {
    let mut rev = [255u8; 256];
    for (i, &c) in B64.iter().enumerate() {
        rev[c as usize] = i as u8;
    }
    let bytes: Vec<u8> = s.bytes().filter(|&c| rev[c as usize] != 255).collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn md5_hex(data: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(data);
    hex(&h.finalize())
}

fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

/// 标准 HMAC-SHA256(块长 64)。
fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut k = if key.len() > 64 {
        sha256_bytes(key)
    } else {
        key.to_vec()
    };
    k.resize(64, 0);
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

/// RFC3986 百分号编码(unreserved 之外全编码),用于把注入/模板 payload 塞进 URL query。
fn url_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for &b in data {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "用法: crypto <b64url-enc|b64url-dec|md5|sha256|hmac256|jwt-none|jwt-hs256|jwt-decode> [args...]";
    let Some(op) = args.first() else {
        eprintln!("{usage}");
        std::process::exit(2);
    };
    match op.as_str() {
        "b64url-enc" => println!("{}", b64url_encode(args[1].as_bytes())),
        "b64url-dec" => println!("{}", String::from_utf8_lossy(&b64url_decode(&args[1]))),
        "url-enc" => println!("{}", url_encode(args[1].as_bytes())),
        "md5" => println!("{}", md5_hex(args[1].as_bytes())),
        "sha256" => println!("{}", hex(&sha256_bytes(args[1].as_bytes()))),
        "hmac256" => println!("{}", hex(&hmac_sha256(args[1].as_bytes(), args[2].as_bytes()))),
        "jwt-none" => {
            let header = b64url_encode(br#"{"alg":"none","typ":"JWT"}"#);
            let payload = b64url_encode(args[1].as_bytes());
            println!("{header}.{payload}.");
        }
        "jwt-hs256" => {
            let secret = &args[1];
            let header = b64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
            let payload = b64url_encode(args[2].as_bytes());
            let signing_input = format!("{header}.{payload}");
            let sig = b64url_encode(&hmac_sha256(secret.as_bytes(), signing_input.as_bytes()));
            println!("{signing_input}.{sig}");
        }
        "jwt-sign" => {
            // jwt-sign <secret> <header-json> <payload-json>:自定义 header(如恶意 kid)再 HS256 签名。
            let secret = &args[1];
            let header = b64url_encode(args[2].as_bytes());
            let payload = b64url_encode(args[3].as_bytes());
            let signing_input = format!("{header}.{payload}");
            let sig = b64url_encode(&hmac_sha256(secret.as_bytes(), signing_input.as_bytes()));
            println!("{signing_input}.{sig}");
        }
        "jwt-decode" => {
            for (i, part) in args[1].split('.').take(2).enumerate() {
                let label = if i == 0 { "header" } else { "payload" };
                println!("[{label}] {}", String::from_utf8_lossy(&b64url_decode(part)));
            }
        }
        other => {
            eprintln!("未知 op: {other}\n{usage}");
            std::process::exit(2);
        }
    }
}
