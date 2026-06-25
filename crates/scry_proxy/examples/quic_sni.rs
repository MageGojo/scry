//! QUIC(HTTP/3)Initial 包被动解析示例 —— 从一个 QUIC Initial 数据报(UDP/443 负载)解出 SNI / ALPN。
//!
//! scry 无法主动 MITM QUIC(UDP 不走 HTTP CONNECT 代理),但 QUIC Initial 用公开盐派生密钥,
//! 可**无密钥被动解密**取出 ClientHello(对标 Wireshark)。本例演示该能力:
//!
//! ```bash
//! # 传入一个 QUIC Initial 数据报的十六进制(可含空格)
//! cargo run -p scry_proxy --example quic_sni -- "<hex of a QUIC v1 Initial datagram>"
//! ```
//!
//! 真实抓取这段字节需要从网卡 UDP/443 捕获(scry_sniff 的被动嗅探后续会接入)。

use scry_proxy::quic;

fn main() {
    let arg = std::env::args().nth(1);
    let Some(hex) = arg else {
        eprintln!("用法: cargo run -p scry_proxy --example quic_sni -- <QUIC Initial 的 hex>");
        std::process::exit(2);
    };
    let bytes = hex_to_bytes(&hex);

    if !quic::is_long_header(&bytes) {
        println!("不是 QUIC 长包(首字节 header form 位未置位)");
        return;
    }
    match quic::parse_long_header(&bytes) {
        Some(h) => println!(
            "QUIC 长包: version=0x{:08x} dcid={} scid={}",
            h.version,
            to_hex(&h.dcid),
            to_hex(&h.scid)
        ),
        None => {
            println!("长包头解析失败");
            return;
        }
    }
    if !quic::is_initial(&bytes) {
        println!("不是 Initial 包(无法取 ClientHello / SNI)");
        return;
    }
    match quic::extract_handshake_info(&bytes) {
        Some(hello) => {
            println!("HTTP/3 (QUIC) Initial 解密成功:");
            println!("  SNI : {}", hello.sni.as_deref().unwrap_or("(无)"));
            println!(
                "  ALPN: {}",
                if hello.alpn.is_empty() {
                    "(无)".to_string()
                } else {
                    hello.alpn.join(", ")
                }
            );
        }
        None => println!("Initial 解密失败(可能非 QUIC v1 / 截断 / 已加密的非首包)"),
    }
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .filter_map(|i| s.get(i..i + 2).and_then(|p| u8::from_str_radix(p, 16).ok()))
        .collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
