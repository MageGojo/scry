//! 打印各 TLS 指纹 profile 的**真实** JA4 / JA3(由 rustls 实际生成的 ClientHello 解析得出)。
//!
//! 运行:`cargo run -p scry_proxy --example ja3`
//! - JA4 稳定,可拿去和指纹回显站(如 https://tls.peet.ws/api/all)对照。
//! - JA3 为单次采样:rustls 每次握手随机化扩展顺序,故每跑一次都会变(这是预期行为)。

use scry_proxy::tls_profile::TlsProfile;

fn main() {
    println!("{:<10} {:<26} JA3 (sampled, randomized)", "Profile", "JA4 (stable)");
    println!("{}", "-".repeat(96));
    for p in TlsProfile::ALL {
        match scry_proxy::fingerprint::fingerprint_for(p) {
            Ok(f) => println!("{:<10} {:<26} {}", p.label(), f.ja4, f.ja3_hash),
            Err(e) => println!("{:<10} <error: {e}>", p.label()),
        }
    }
    println!();
    println!("注:各档 JA4 仅 ALPN 段有别——本套指纹伪装只改 rustls 可控的密码/曲线顺序+ALPN,");
    println!("    JA4 故意忽略顺序;要让 JA3/JA4 真正等于 Chrome 需 BoringSSL(boring/rquest)。");
}
