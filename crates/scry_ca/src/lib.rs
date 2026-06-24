//! Scry 证书层 —— 根 CA 生成 / 持久化 + 按域名**动态签发叶子证书**(供 TLS MITM 解密)。
//!
//! 用法:
//! - 首次:[`Ca::load_or_create`] 在 `~/.scry/` 生成 `ca.pem` / `ca.key`,用户把 `ca.pem` 导入系统信任。
//! - MITM:对每个目标域名调 [`Ca::sign_leaf`] 拿到叶子证书 + 私钥(PEM),喂给 TLS 服务端握手。

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use time::{Duration, OffsetDateTime};

/// 一对 PEM(证书 + 私钥)。
#[derive(Debug, Clone)]
pub struct CertPem {
    pub cert_pem: String,
    pub key_pem: String,
}

/// 根 CA(证书 + 私钥),用于签发叶子证书。
///
/// 内置**按域名的叶子证书缓存**:签发是 CPU 大头(生成私钥 + 签名),同一域名的多条连接
/// (keep-alive / 并发)直接命中缓存,避免重复签发。缓存用 `Mutex` 做内部可变,`sign_leaf`
/// 仍是 `&self`,因此 `Arc<Ca>` 共享照旧。
pub struct Ca {
    cert: Certificate,
    key: KeyPair,
    /// host → 已签发叶子证书(含私钥)。
    leaf_cache: Mutex<HashMap<String, CertPem>>,
}

impl Ca {
    /// 从 `dir` 加载 `ca.pem` / `ca.key`;不存在则**新建并落盘**。
    pub fn load_or_create(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca.key");
        if cert_path.exists() && key_path.exists() {
            let cert_pem = std::fs::read_to_string(&cert_path).context("读取 ca.pem 失败")?;
            let key_pem = std::fs::read_to_string(&key_path).context("读取 ca.key 失败")?;
            Self::from_pem(&cert_pem, &key_pem)
        } else {
            std::fs::create_dir_all(dir).ok();
            let ca = Self::generate()?;
            std::fs::write(&cert_path, ca.cert.pem()).context("写 ca.pem 失败")?;
            std::fs::write(&key_path, ca.key.serialize_pem()).context("写 ca.key 失败")?;
            Ok(ca)
        }
    }

    /// 默认目录 `~/.scry/`。
    pub fn load_or_create_default() -> Result<Self> {
        Self::load_or_create(default_ca_dir())
    }

    /// 全新生成一个根 CA。
    pub fn generate() -> Result<Self> {
        let mut params =
            CertificateParams::new(Vec::<String>::new()).context("构造 CA 参数失败")?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Scry Root CA");
        dn.push(DnType::OrganizationName, "Scry");
        params.distinguished_name = dn;

        let key = KeyPair::generate().context("生成 CA 私钥失败")?;
        let cert = params.self_signed(&key).context("自签 CA 失败")?;
        Ok(Self {
            cert,
            key,
            leaf_cache: Mutex::new(HashMap::new()),
        })
    }

    /// 由已有 PEM 重建(注意:rcgen 需用参数 + 私钥「重签」以拿回 `Certificate` 句柄)。
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key = KeyPair::from_pem(key_pem).context("解析 CA 私钥失败")?;
        let params = CertificateParams::from_ca_cert_pem(cert_pem).context("解析 CA 证书失败")?;
        let cert = params.self_signed(&key).context("重建 CA 句柄失败")?;
        Ok(Self {
            cert,
            key,
            leaf_cache: Mutex::new(HashMap::new()),
        })
    }

    /// 根证书 PEM(给用户导入系统信任 / MITM 握手链附带)。
    pub fn cert_pem(&self) -> String {
        self.cert.pem()
    }

    /// 根证书 **DER** 二进制(Windows `.crt` 双击安装 / `.mobileconfig` 内嵌用)。
    pub fn cert_der(&self) -> Vec<u8> {
        self.cert.der().as_ref().to_vec()
    }

    /// 根证书 DER 的标准 Base64(`.mobileconfig` 描述文件内嵌证书数据用)。
    pub fn cert_der_base64(&self) -> String {
        base64_std(self.cert.der().as_ref())
    }

    /// 根证书 DER 的 SHA-256(小写十六进制)—— 用于派生稳定的描述文件 UUID。
    pub fn cert_sha256_hex(&self) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(self.cert.der().as_ref());
        let mut s = String::with_capacity(64);
        for b in digest.iter() {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// 根 CA 公钥 **SPKI 的 SHA-256(Base64,RFC 7469)**。
    ///
    /// 用途:内置浏览器(T1)启动参数 `--ignore-certificate-errors-spki-list=<本值>` —— Chrome 会把
    /// **服务器呈现链里任意一张证书**的 SPKI 与白名单比对,命中即跳过证书校验。配合 MITM 握手链里
    /// **带上 CA 证书**(见 `scry_proxy::mitm`),浏览器即可**免装系统 CA、且连 pinning 站都过**。
    /// CA 密钥稳定 → 该指纹稳定(不像逐域名随机的叶子证书)。
    pub fn spki_sha256_base64(&self) -> Result<String> {
        use sha2::{Digest, Sha256};
        use x509_parser::prelude::*;

        let der = self.cert.der();
        let (_, parsed) =
            X509Certificate::from_der(der.as_ref()).context("解析根证书 DER 失败")?;
        let spki_der = parsed.public_key().raw; // SubjectPublicKeyInfo 的完整 DER
        let digest = Sha256::digest(spki_der);
        Ok(base64_std(&digest))
    }

    /// 根 CA **私钥** PEM(PKCS#8)。⚠️ 敏感:仅用于本机备份 / 多机迁移,切勿公开。
    pub fn key_pem(&self) -> String {
        self.key.serialize_pem()
    }

    /// 导出**完整 CA 身份**(私钥 + 证书,合并成单个 PEM)——用于多台设备共用同一根 CA。
    ///
    /// ⚠️ 含私钥,拿到者可伪造任意 HTTPS 证书,务必仅在自己掌控的设备间传输。
    pub fn identity_pem(&self) -> String {
        format!(
            "{}\n{}\n",
            self.key.serialize_pem().trim_end(),
            self.cert.pem().trim_end()
        )
    }

    /// 把合并身份 PEM 拆成 `(证书 PEM, 私钥 PEM)` 两段(保留原始字节,用于落盘还原)。
    pub fn split_identity_pem(combined: &str) -> Result<(String, String)> {
        let cert_pem =
            extract_pem_block(combined, "CERTIFICATE").context("身份文件缺少 CERTIFICATE 段")?;
        let key_pem =
            extract_pem_block(combined, "PRIVATE KEY").context("身份文件缺少 PRIVATE KEY 段")?;
        Ok((cert_pem, key_pem))
    }

    /// 从 [`Self::identity_pem`] 的合并 PEM 重建 CA(拆出证书段 + 私钥段并校验可用)。
    pub fn from_identity_pem(combined: &str) -> Result<Self> {
        let (cert_pem, key_pem) = Self::split_identity_pem(combined)?;
        Self::from_pem(&cert_pem, &key_pem)
    }

    /// 为某域名签发叶子证书(返回叶子证书 + 其私钥 PEM)。**命中缓存则直接复用**。
    pub fn sign_leaf(&self, host: &str) -> Result<CertPem> {
        if let Some(hit) = self.cache().get(host).cloned() {
            return Ok(hit);
        }
        let leaf = self.sign_leaf_uncached(host)?;
        self.cache().insert(host.to_string(), leaf.clone());
        Ok(leaf)
    }

    /// 不走缓存,实打实签一张叶子证书。
    pub fn sign_leaf_uncached(&self, host: &str) -> Result<CertPem> {
        let mut params =
            CertificateParams::new(vec![host.to_string()]).context("构造叶子参数失败")?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;

        // 关键:叶子证书必须用「合理有效期 + serverAuth EKU」,否则 Chrome / Apple 的服务器证书
        // 寿命与用途校验会直接拒收(rcgen 默认 1975–4096 的超长有效期就是被拒主因;curl/LibreSSL
        // 不校验寿命所以放行,造成「curl 能解、浏览器解不开」)。有效期压在 398 天内。
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(397);
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let leaf_key = KeyPair::generate().context("生成叶子私钥失败")?;
        let leaf_cert = params
            .signed_by(&leaf_key, &self.cert, &self.key)
            .context("用 CA 签发叶子失败")?;
        Ok(CertPem {
            cert_pem: leaf_cert.pem(),
            key_pem: leaf_key.serialize_pem(),
        })
    }

    /// 当前已缓存的叶子证书数量(观测 / 测试用)。
    pub fn leaf_cache_len(&self) -> usize {
        self.cache().len()
    }

    /// 清空叶子证书缓存。
    pub fn clear_leaf_cache(&self) {
        self.cache().clear();
    }

    /// 取缓存锁(锁中毒时也恢复内部数据,避免 panic 传播)。
    fn cache(&self) -> std::sync::MutexGuard<'_, HashMap<String, CertPem>> {
        self.leaf_cache.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// `~/.scry/`(取不到 HOME 时退回当前目录)。
pub fn default_ca_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".scry")
}

/// 从合并 PEM 文本里抽出指定标签的一整段(含 `-----BEGIN/END <label>-----` 行)。
fn extract_pem_block(s: &str, label: &str) -> Option<String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = s.find(&begin)?;
    let stop = s[start..].find(&end)? + start + end.len();
    Some(s[start..stop].to_string())
}

/// 标准 Base64 编码(RFC 4648,带 `=` 填充)—— SPKI 指纹用,免引入额外依赖。
fn base64_std(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
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

    #[test]
    fn generate_and_sign_leaf() {
        let ca = Ca::generate().unwrap();
        assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));
        let leaf = ca.sign_leaf("example.com").unwrap();
        assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(leaf.key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn roundtrip_from_pem() {
        let ca = Ca::generate().unwrap();
        let cert_pem = ca.cert_pem();
        let key_pem = ca.key.serialize_pem();
        let ca2 = Ca::from_pem(&cert_pem, &key_pem).unwrap();
        // 重建后仍能签发。
        assert!(ca2.sign_leaf("test.local").is_ok());
    }

    #[test]
    fn leaf_cache_reuses_same_cert() {
        let ca = Ca::generate().unwrap();
        let a = ca.sign_leaf("example.com").unwrap();
        let b = ca.sign_leaf("example.com").unwrap(); // 同域名 → 命中缓存
        let c = ca.sign_leaf("other.com").unwrap(); // 新域名 → 新签

        // 命中缓存:证书与私钥都和首次完全一致。
        assert_eq!(a.cert_pem, b.cert_pem);
        assert_eq!(a.key_pem, b.key_pem);
        // 不同域名:确实是另一张证书。
        assert_ne!(a.cert_pem, c.cert_pem);
        assert_eq!(ca.leaf_cache_len(), 2);

        ca.clear_leaf_cache();
        assert_eq!(ca.leaf_cache_len(), 0);
    }

    #[test]
    fn uncached_signs_fresh_each_time() {
        let ca = Ca::generate().unwrap();
        let a = ca.sign_leaf_uncached("example.com").unwrap();
        let b = ca.sign_leaf_uncached("example.com").unwrap();
        // 每次新生成私钥 → 证书不同;且不污染缓存。
        assert_ne!(a.key_pem, b.key_pem);
        assert_eq!(ca.leaf_cache_len(), 0);
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_std(b""), "");
        assert_eq!(base64_std(b"f"), "Zg==");
        assert_eq!(base64_std(b"fo"), "Zm8=");
        assert_eq!(base64_std(b"foo"), "Zm9v");
        assert_eq!(base64_std(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn spki_fingerprint_is_stable_base64_sha256() {
        let ca = Ca::generate().unwrap();
        let a = ca.spki_sha256_base64().unwrap();
        // SHA-256 = 32 字节 → 标准 base64 44 字符、末位 `=`。
        assert_eq!(a.len(), 44);
        assert!(a.ends_with('='));
        // 同一 CA 多次计算稳定;重建后(同密钥)也一致。
        assert_eq!(a, ca.spki_sha256_base64().unwrap());
        let ca2 = Ca::from_pem(&ca.cert_pem(), &ca.key.serialize_pem()).unwrap();
        assert_eq!(a, ca2.spki_sha256_base64().unwrap());
    }

    /// 回归:叶子证书必须有「合理有效期(≤398 天)+ serverAuth EKU」,否则 Chrome / Apple 拒收
    /// (这正是早期 1975–4096 超长有效期导致「curl 能解、浏览器解不开」的根因)。
    #[test]
    fn leaf_cert_has_sane_validity_and_server_auth() {
        use x509_parser::prelude::*;
        let ca = Ca::generate().unwrap();
        let leaf = ca.sign_leaf("example.com").unwrap();
        let (_, pem) = parse_x509_pem(leaf.cert_pem.as_bytes()).unwrap();
        let cert = pem.parse_x509().unwrap();

        let span = cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp();
        assert!(span > 0, "not_after 必须晚于 not_before");
        assert!(
            span <= 398 * 24 * 3600,
            "叶子有效期过长({span}s),会被浏览器拒收"
        );

        let eku = cert
            .extended_key_usage()
            .expect("解析 EKU 失败")
            .expect("缺少 EKU 扩展");
        assert!(eku.value.server_auth, "叶子证书必须含 serverAuth EKU");
    }

    #[test]
    fn der_base64_and_sha256_hex_consistent() {
        let ca = Ca::generate().unwrap();
        assert!(!ca.cert_der().is_empty());
        // cert_der_base64 == 对 DER 做标准 base64。
        assert_eq!(ca.cert_der_base64(), base64_std(&ca.cert_der()));
        // SHA-256 十六进制:64 字符、全为十六进制。
        let hex = ca.cert_sha256_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn identity_pem_roundtrip_preserves_same_ca() {
        let ca = Ca::generate().unwrap();
        let id = ca.identity_pem();
        assert!(id.contains("BEGIN CERTIFICATE"));
        assert!(id.contains("PRIVATE KEY"));

        let ca2 = Ca::from_identity_pem(&id).unwrap();
        // 同一把私钥 → 公钥/SPKI 一致(抓包按公钥验证叶子;证书可能因重签而字节不同)。
        assert_eq!(
            ca.spki_sha256_base64().unwrap(),
            ca2.spki_sha256_base64().unwrap()
        );
        assert!(ca2.sign_leaf("example.com").is_ok());

        // 拆分应还原出两段原始 PEM。
        let (cert_pem, key_pem) = Ca::split_identity_pem(&id).unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn from_identity_pem_rejects_incomplete_input() {
        let ca = Ca::generate().unwrap();
        // 只有证书、没有私钥 → 应报错。
        assert!(Ca::from_identity_pem(&ca.cert_pem()).is_err());
    }
}
