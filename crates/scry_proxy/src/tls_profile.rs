//! TLS 指纹 profile —— 让 MITM / 重放 对**上游**的 ClientHello 贴近主流浏览器(在 rustls 可控范围内)。
//!
//! 现实约束(必须如实记录):字节级 JA3/JA4 由「密码套件 + 扩展**顺序** + 椭圆曲线 + GREASE + 精确布局」
//! 共同决定;**rustls 不暴露扩展顺序 / GREASE / 精确布局**,因此无法做到逐字节复刻浏览器指纹。本模块只
//! 调整 rustls **能控**的部分:**ALPN 提议**、**密码套件**与**椭圆曲线**的集合与顺序(经自定义 `CryptoProvider`)。
//! 这能显著改变握手「提供内容」(JA3 的 cipher / curve 段 + ALPN 扩展),足以避开「一眼 rustls 默认」的识别;
//! 要逐字节伪装需换 BoringSSL(`boring` / `rquest`),工程更重,列为后续。
//!
//! 想知道当前档**真实**呈现什么指纹?见 [`crate::fingerprint`]:让 rustls 真吐 ClientHello 再解析(JA3+JA4),不靠猜。
//!
//! 接入方式:进程级全局 [`set_active`] / [`active`](`AtomicU8`),`build_client_config` 读取它,
//! 免去把 profile 一路透传过 proxy / mitm / replay 的签名改动。

use std::sync::atomic::{AtomicU8, Ordering};

use tokio_rustls::rustls::crypto::{ring, CryptoProvider};
use tokio_rustls::rustls::{CipherSuite, NamedGroup};

/// 浏览器 / 客户端指纹档位。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsProfile {
    /// rustls 默认(不伪装)。
    Default,
    Chrome,
    Firefox,
    Safari,
    /// curl(默认不提议 ALPN,贴近命令行客户端)。
    Curl,
}

impl TlsProfile {
    pub const ALL: [TlsProfile; 5] = [
        TlsProfile::Default,
        TlsProfile::Chrome,
        TlsProfile::Firefox,
        TlsProfile::Safari,
        TlsProfile::Curl,
    ];

    /// 英文标签(UI i18n key)。
    pub fn label(self) -> &'static str {
        match self {
            TlsProfile::Default => "Default",
            TlsProfile::Chrome => "Chrome",
            TlsProfile::Firefox => "Firefox",
            TlsProfile::Safari => "Safari",
            TlsProfile::Curl => "curl",
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            TlsProfile::Default => 0,
            TlsProfile::Chrome => 1,
            TlsProfile::Firefox => 2,
            TlsProfile::Safari => 3,
            TlsProfile::Curl => 4,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => TlsProfile::Chrome,
            2 => TlsProfile::Firefox,
            3 => TlsProfile::Safari,
            4 => TlsProfile::Curl,
            _ => TlsProfile::Default,
        }
    }

    /// ALPN 提议(空 = 不发 ALPN 扩展)。
    pub fn alpn(self) -> Vec<Vec<u8>> {
        match self {
            // 浏览器都提议 h2 + http/1.1。
            TlsProfile::Chrome | TlsProfile::Firefox | TlsProfile::Safari => {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            }
            // curl 默认只 http/1.1(不开 --http2 时);Default 跟随之(单 http/1.1,最稳)。
            TlsProfile::Curl | TlsProfile::Default => vec![b"http/1.1".to_vec()],
        }
    }

    /// 密码套件优先序(前置这些;其余保持 ring 默认相对序)。空 = 不调整。
    pub fn cipher_pref(self) -> &'static [CipherSuite] {
        match self {
            TlsProfile::Chrome => &CHROME,
            TlsProfile::Firefox => &FIREFOX,
            TlsProfile::Safari => &SAFARI,
            TlsProfile::Default | TlsProfile::Curl => &[],
        }
    }

    /// 椭圆曲线(supported_groups)优先序。曲线是 JA3 的大头,各浏览器排布不同。空 = 不调整。
    pub fn curve_pref(self) -> &'static [NamedGroup] {
        match self {
            TlsProfile::Chrome => &CHROME_CURVES,
            TlsProfile::Firefox => &FIREFOX_CURVES,
            TlsProfile::Safari => &SAFARI_CURVES,
            TlsProfile::Default | TlsProfile::Curl => &[],
        }
    }
}

// 各档位的 TLS1.3 + TLS1.2(ECDHE)套件优先序(贴近各浏览器的常见排布)。
const CHROME: [CipherSuite; 5] = [
    CipherSuite::TLS13_AES_128_GCM_SHA256,
    CipherSuite::TLS13_AES_256_GCM_SHA384,
    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];
const FIREFOX: [CipherSuite; 5] = [
    CipherSuite::TLS13_AES_128_GCM_SHA256,
    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS13_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];
const SAFARI: [CipherSuite; 3] = [
    CipherSuite::TLS13_AES_256_GCM_SHA384,
    CipherSuite::TLS13_AES_128_GCM_SHA256,
    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
];

// 各档位的曲线优先序(贴近各浏览器 supported_groups;仅含 ring provider 支持的 ECDHE 曲线)。
const CHROME_CURVES: [NamedGroup; 3] = [
    NamedGroup::X25519,
    NamedGroup::secp256r1,
    NamedGroup::secp384r1,
];
const FIREFOX_CURVES: [NamedGroup; 4] = [
    NamedGroup::X25519,
    NamedGroup::secp256r1,
    NamedGroup::secp384r1,
    NamedGroup::secp521r1,
];
const SAFARI_CURVES: [NamedGroup; 4] = [
    NamedGroup::X25519,
    NamedGroup::secp256r1,
    NamedGroup::secp384r1,
    NamedGroup::secp521r1,
];

/// 进程级当前 profile(默认 0 = Default)。
static ACTIVE: AtomicU8 = AtomicU8::new(0);

/// 设置当前 TLS 指纹 profile(UI 设置变更时调用)。
pub fn set_active(p: TlsProfile) {
    ACTIVE.store(p.as_u8(), Ordering::Relaxed);
}

/// 读取当前 TLS 指纹 profile(`build_client_config` 用)。
pub fn active() -> TlsProfile {
    TlsProfile::from_u8(ACTIVE.load(Ordering::Relaxed))
}

/// 按 profile 构造 rustls `CryptoProvider`(在 ring 默认上**重排密码套件 + 椭圆曲线顺序**)。
pub fn provider_for(profile: TlsProfile) -> CryptoProvider {
    let base = ring::default_provider();
    let pref = profile.cipher_pref();
    let curves = profile.curve_pref();
    if pref.is_empty() && curves.is_empty() {
        return base;
    }
    // 密码套件:列在 pref 里的按其下标前置;未列出的保持原相对序(sort_by_key 稳定)。
    let mut suites = base.cipher_suites.clone();
    if !pref.is_empty() {
        suites.sort_by_key(|s| {
            pref.iter()
                .position(|p| *p == s.suite())
                .unwrap_or(usize::MAX)
        });
    }
    // 曲线同理:按 curve_pref 重排 kx_groups(不丢曲线,只改顺序)。
    let mut kx = base.kx_groups.clone();
    if !curves.is_empty() {
        kx.sort_by_key(|g| {
            curves
                .iter()
                .position(|c| *c == g.name())
                .unwrap_or(usize::MAX)
        });
    }
    CryptoProvider {
        cipher_suites: suites,
        kx_groups: kx,
        ..base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u8_roundtrip() {
        for p in TlsProfile::ALL {
            assert_eq!(TlsProfile::from_u8(p.as_u8()), p);
        }
        // 越界回 Default。
        assert_eq!(TlsProfile::from_u8(99), TlsProfile::Default);
    }

    #[test]
    fn alpn_per_profile() {
        assert_eq!(TlsProfile::Chrome.alpn(), vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert_eq!(TlsProfile::Curl.alpn(), vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn provider_reorders_first_cipher() {
        // Chrome 首选 TLS13_AES_128_GCM_SHA256;Safari 首选 TLS13_AES_256_GCM_SHA384。
        let chrome = provider_for(TlsProfile::Chrome);
        assert_eq!(
            chrome.cipher_suites.first().unwrap().suite(),
            CipherSuite::TLS13_AES_128_GCM_SHA256
        );
        let safari = provider_for(TlsProfile::Safari);
        assert_eq!(
            safari.cipher_suites.first().unwrap().suite(),
            CipherSuite::TLS13_AES_256_GCM_SHA384
        );
        // 重排不丢套件(数量与默认一致)。
        assert_eq!(
            chrome.cipher_suites.len(),
            ring::default_provider().cipher_suites.len()
        );
    }

    #[test]
    fn default_provider_unchanged() {
        let def = provider_for(TlsProfile::Default);
        let base = ring::default_provider();
        assert_eq!(def.cipher_suites.len(), base.cipher_suites.len());
        // Default 不重排:首套件与 ring 默认一致。
        assert_eq!(
            def.cipher_suites.first().unwrap().suite(),
            base.cipher_suites.first().unwrap().suite()
        );
    }

    #[test]
    fn provider_reorders_curves() {
        // 各浏览器档曲线首选 X25519;重排不丢曲线(数量与默认一致)。
        let base = ring::default_provider();
        for p in [TlsProfile::Chrome, TlsProfile::Firefox, TlsProfile::Safari] {
            let prov = provider_for(p);
            assert_eq!(prov.kx_groups.first().unwrap().name(), NamedGroup::X25519);
            assert_eq!(prov.kx_groups.len(), base.kx_groups.len());
        }
    }
}
