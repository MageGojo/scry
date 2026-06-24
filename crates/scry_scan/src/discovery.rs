//! 主动「敏感文件 / 路径」探测 —— **Nikto 式**内置 Web 漏洞扫描的纯函数内核。
//!
//! 思路:对每个目标 origin(`scheme://host:port`)请求一组**已知高危路径**(VCS 仓库 / 配置 /
//! 备份 / 数据库导出 / 信息泄露端点 / 管理后台 / API 文档 / Spring Actuator 等),按
//! 「状态码 + 响应体特征」判定是否真实命中。
//!
//! 为压制「站点对任何路径都回 200」(SPA / 自定义 404)造成的误报,先对每个 origin 取一个
//! **soft-404 基线**(请求一个必然不存在的随机路径),`Sig::Exists` 类判定会与基线对比剔除。
//!
//! 全部纯函数、可单测;真正发包由 UI runner 复用 [`scry_proxy::replay`](与主动扫描同一路径)。

use scry_core::{Header, HttpFlow};

use crate::types::{Finding, Severity};

/// 探测请求用的 User-Agent(中性标识,便于目标侧识别是扫描器)。
const USER_AGENT: &str = "Mozilla/5.0 (compatible; ScryScanner/1.0)";

/// 命中判定方式。
#[derive(Clone, Copy, Debug)]
pub enum Sig {
    /// 资源「存在即问题」:`2xx` 且响应不同于 soft-404 基线即命中(配合基线压误报)。
    Exists,
    /// `2xx` 且**解码后**响应体(小写)含**任一**特征串才命中(签名强,天然抗 soft-404)。
    BodyAny(&'static [&'static str]),
    /// `2xx` 且**原始**响应体以给定魔数字节开头(二进制文件,如 zip / sqlite / heapdump)。
    /// 注意:魔数不要用 `1f 8b`(gzip),否则会与「响应被 gzip 压缩」混淆。
    Magic(&'static [u8]),
}

/// 一条已知高危路径规则。
#[derive(Clone, Copy, Debug)]
pub struct SensitivePath {
    /// 探测路径(origin-form,以 `/` 开头)。
    pub path: &'static str,
    /// 稳定规则 id(去重用)。
    pub rule_id: &'static str,
    /// 发现标题(英文 i18n key,界面 `lang.t()` 翻译)。
    pub title: &'static str,
    pub severity: Severity,
    pub sig: Sig,
}

/// 内置高危路径库(Nikto 精髓的高信号子集;签名尽量强以压低误报)。
pub const PATHS: &[SensitivePath] = &[
    // ── 版本控制目录泄露(可还原源码 / 历史)──
    sp("/.git/HEAD", "disc-git-head", "Exposed Git repository", Severity::Critical, Sig::BodyAny(&["ref:"])),
    sp("/.git/config", "disc-git-config", "Exposed Git repository", Severity::Critical, Sig::BodyAny(&["[core]"])),
    sp("/.git/", "disc-git-dir", "Exposed Git repository", Severity::High, Sig::BodyAny(&["index of", "parent directory"])),
    sp("/.svn/entries", "disc-svn-entries", "Exposed SVN repository", Severity::High, Sig::Exists),
    sp("/.svn/wc.db", "disc-svn-wcdb", "Exposed SVN repository", Severity::High, Sig::Magic(b"SQLite format 3\x00")),
    sp("/.hg/requires", "disc-hg", "Exposed Mercurial repository", Severity::High, Sig::Exists),
    // ── 环境 / 凭据文件 ──
    sp("/.env", "disc-env", "Exposed environment file", Severity::High, Sig::BodyAny(&["app_", "db_", "secret", "api_key", "password", "aws_"])),
    sp("/.env.local", "disc-env-local", "Exposed environment file", Severity::High, Sig::BodyAny(&["app_", "db_", "secret", "api_key", "password", "aws_"])),
    sp("/.aws/credentials", "disc-aws", "Exposed cloud credentials", Severity::Critical, Sig::BodyAny(&["aws_access_key_id", "[default]"])),
    sp("/.npmrc", "disc-npmrc", "Exposed npm credentials", Severity::Medium, Sig::BodyAny(&["_authtoken", "//registry"])),
    sp("/.htpasswd", "disc-htpasswd", "Exposed password file", Severity::High, Sig::Exists),
    sp("/config.php.bak", "disc-config-bak", "Exposed source backup", Severity::High, Sig::BodyAny(&["<?php"])),
    // ── 备份 / 数据库导出 ──
    sp("/backup.zip", "disc-backup-zip", "Exposed backup archive", Severity::High, Sig::Magic(b"PK\x03\x04")),
    sp("/backup.sql", "disc-backup-sql", "Exposed database dump", Severity::Critical, Sig::BodyAny(&["create table", "insert into", "drop table", "-- dump"])),
    sp("/database.sql", "disc-database-sql", "Exposed database dump", Severity::Critical, Sig::BodyAny(&["create table", "insert into", "drop table", "-- dump"])),
    sp("/dump.sql", "disc-dump-sql", "Exposed database dump", Severity::Critical, Sig::BodyAny(&["create table", "insert into", "drop table", "-- dump"])),
    sp("/.DS_Store", "disc-dsstore", "Exposed .DS_Store metadata", Severity::Low, Sig::Magic(&[0, 0, 0, 1, b'B', b'u', b'd', b'1'])),
    // ── 配置文件 ──
    sp("/web.config", "disc-webconfig", "Exposed configuration file", Severity::Medium, Sig::BodyAny(&["<configuration"])),
    sp("/WEB-INF/web.xml", "disc-webxml", "Exposed configuration file", Severity::High, Sig::BodyAny(&["<web-app"])),
    sp("/.htaccess", "disc-htaccess", "Exposed configuration file", Severity::Medium, Sig::BodyAny(&["rewriteengine", "<files", "deny from", "order allow"])),
    // ── 信息泄露端点 ──
    sp("/phpinfo.php", "disc-phpinfo", "PHP configuration disclosure", Severity::Medium, Sig::BodyAny(&["phpinfo()", "php version"])),
    sp("/info.php", "disc-infophp", "PHP configuration disclosure", Severity::Medium, Sig::BodyAny(&["phpinfo()", "php version"])),
    sp("/server-status", "disc-apache-status", "Server status page exposed", Severity::Medium, Sig::BodyAny(&["apache server status", "apache status"])),
    sp("/server-info", "disc-apache-info", "Server status page exposed", Severity::Medium, Sig::BodyAny(&["apache server information"])),
    // ── API 文档 ──
    sp("/swagger.json", "disc-swagger-json", "Exposed API documentation", Severity::Low, Sig::BodyAny(&["\"swagger\"", "\"openapi\""])),
    sp("/openapi.json", "disc-openapi-json", "Exposed API documentation", Severity::Low, Sig::BodyAny(&["\"openapi\"", "\"swagger\""])),
    sp("/v2/api-docs", "disc-springdoc", "Exposed API documentation", Severity::Low, Sig::BodyAny(&["\"swagger\"", "\"paths\""])),
    sp("/swagger-ui.html", "disc-swagger-ui", "Exposed API documentation", Severity::Low, Sig::BodyAny(&["swagger-ui", "swagger ui"])),
    // ── Spring Boot Actuator(高价值)──
    sp("/actuator", "disc-actuator", "Spring Boot Actuator exposed", Severity::Medium, Sig::BodyAny(&["\"_links\"", "\"self\""])),
    sp("/actuator/env", "disc-actuator-env", "Spring Boot Actuator env exposed", Severity::High, Sig::BodyAny(&["\"propertysources\"", "systemproperties"])),
    sp("/actuator/heapdump", "disc-actuator-heapdump", "Spring Boot heap dump exposed", Severity::Critical, Sig::Magic(b"JAVA")),
    sp("/actuator/mappings", "disc-actuator-mappings", "Spring Boot Actuator exposed", Severity::Medium, Sig::BodyAny(&["\"mappings\"", "dispatcherservlet"])),
    // ── 管理后台 / 源码元数据 ──
    sp("/phpmyadmin/", "disc-phpmyadmin", "phpMyAdmin reachable", Severity::Medium, Sig::BodyAny(&["phpmyadmin"])),
    sp("/package.json", "disc-packagejson", "Exposed source metadata", Severity::Low, Sig::BodyAny(&["\"dependencies\"", "\"devdependencies\""])),
    sp("/composer.json", "disc-composerjson", "Exposed source metadata", Severity::Low, Sig::BodyAny(&["\"require\"", "\"autoload\""])),
    sp("/docker-compose.yml", "disc-dockercompose", "Exposed Docker compose file", Severity::Medium, Sig::BodyAny(&["services:", "image:"])),
    sp("/.gitlab-ci.yml", "disc-gitlabci", "Exposed CI configuration", Severity::Low, Sig::BodyAny(&["stages:", "script:"])),
    sp("/.idea/workspace.xml", "disc-idea", "Exposed IDE project files", Severity::Low, Sig::BodyAny(&["<project"])),
];

/// `const fn` 简写,使 [`PATHS`] 表保持紧凑可读。
const fn sp(
    path: &'static str,
    rule_id: &'static str,
    title: &'static str,
    severity: Severity,
    sig: Sig,
) -> SensitivePath {
    SensitivePath {
        path,
        rule_id,
        title,
        severity,
        sig,
    }
}

/// 一个目标源(协议 + 主机 + 端口);探测以它为基准拼路径。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl Origin {
    /// 基准 URL(省略默认端口),仅用于展示 / 日志。
    pub fn base_url(&self) -> String {
        let default = matches!(
            (self.scheme.as_str(), self.port),
            ("http", 80) | ("https", 443)
        );
        if default {
            format!("{}://{}", self.scheme, self.host)
        } else {
            format!("{}://{}:{}", self.scheme, self.host, self.port)
        }
    }

    /// `Host` 头取值(非默认端口带端口)。
    fn host_header(&self) -> String {
        let default = matches!(
            (self.scheme.as_str(), self.port),
            ("http", 80) | ("https", 443)
        );
        if default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// 从已抓到的流里提炼出去重的目标 origin 列表(保序;跳过空 host)。
pub fn origins(flows: &[HttpFlow]) -> Vec<Origin> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for f in flows {
        if f.host.is_empty() {
            continue;
        }
        let o = Origin {
            scheme: if f.scheme.is_empty() {
                "https".to_string()
            } else {
                f.scheme.clone()
            },
            host: f.host.clone(),
            port: f.port,
        };
        if seen.insert((o.scheme.clone(), o.host.clone(), o.port)) {
            out.push(o);
        }
    }
    out
}

/// 构造一个探测请求流(`GET path`,带 `Host` / `User-Agent` / `Accept` 头,可直接喂 `replay`)。
pub fn probe_flow(o: &Origin, path: &str) -> HttpFlow {
    let headers: Vec<Header> = vec![
        ("Host".to_string(), o.host_header()),
        ("User-Agent".to_string(), USER_AGENT.to_string()),
        ("Accept".to_string(), "*/*".to_string()),
    ];
    HttpFlow::request("GET", o.scheme.clone(), o.host.clone(), o.port, path, headers, vec![])
}

/// 用于测 soft-404 的「必不存在」随机路径(足够独特,正常站点必然没有此文件)。
pub fn baseline_path() -> &'static str {
    "/scry_probe_404_b7f3e9a1c2.html"
}

/// soft-404 基线:对不存在路径的响应特征(状态码 + 响应体长度)。
#[derive(Clone, Copy, Debug)]
pub struct Baseline {
    pub status: u16,
    pub body_len: usize,
}

/// 由基线响应构造 [`Baseline`]。
pub fn build_baseline(resp: &HttpFlow) -> Baseline {
    Baseline {
        status: resp.status,
        body_len: resp.resp_body.len(),
    }
}

/// 判定某响应是否「与基线无异」(= 站点对不存在路径的统一软 404 回复)。
fn looks_like_baseline(resp: &HttpFlow, base: &Baseline) -> bool {
    if resp.status != base.status {
        return false;
    }
    // 同状态码下,响应体长度接近(绝对差 ≤ 64B 或 ≤ 基线 5%)即视作同一软 404 页。
    let a = resp.resp_body.len() as i64;
    let b = base.body_len as i64;
    let diff = (a - b).abs();
    diff <= 64 || (b > 0 && diff * 20 <= b)
}

/// 对一次探测响应做命中判定 → 命中则给一条 [`Finding`]。
///
/// - `base`:该 origin 的 soft-404 基线(无则不做基线压制)。
pub fn evaluate_path(entry: &SensitivePath, resp: &HttpFlow, base: Option<&Baseline>) -> Option<Finding> {
    if resp.status == 0 {
        // 网络失败 / 无响应。
        return None;
    }
    let is_2xx = (200..300).contains(&resp.status);
    let hit = match entry.sig {
        Sig::Exists => {
            if !is_2xx {
                return None;
            }
            if let Some(b) = base {
                if looks_like_baseline(resp, b) {
                    return None;
                }
            }
            true
        }
        Sig::BodyAny(needles) => {
            if !is_2xx {
                return None;
            }
            let text = if resp.resp_body.is_empty() {
                String::new()
            } else {
                scry_decode::display_text(&resp.resp_headers, &resp.resp_body)
            };
            let low = text.to_ascii_lowercase();
            needles.iter().any(|n| low.contains(n))
        }
        Sig::Magic(prefix) => is_2xx && resp.resp_body.starts_with(prefix),
    };
    if !hit {
        return None;
    }
    Some(Finding::new(
        entry.rule_id,
        entry.title,
        entry.severity,
        resp.url(),
        format!(
            "GET {} → {} ({} bytes)",
            entry.path,
            resp.status,
            resp.resp_body.len()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(host: &str, scheme: &str, port: u16, path: &str) -> HttpFlow {
        HttpFlow::request("GET", scheme, host, port, path, vec![], vec![])
    }

    #[test]
    fn origins_dedupe_by_scheme_host_port() {
        let flows = vec![
            flow("a.com", "https", 443, "/x"),
            flow("a.com", "https", 443, "/y"), // 同 origin 不同 path → 合一
            flow("a.com", "http", 80, "/x"),   // 不同 scheme/port → 另算
            flow("b.com", "https", 443, "/"),
        ];
        let os = origins(&flows);
        assert_eq!(os.len(), 3);
        assert_eq!(os[0].base_url(), "https://a.com");
        assert_eq!(os[1].base_url(), "http://a.com");
    }

    #[test]
    fn probe_flow_sets_host_and_method() {
        let o = Origin {
            scheme: "https".into(),
            host: "ex.com".into(),
            port: 8443,
        };
        let f = probe_flow(&o, "/.git/HEAD");
        assert_eq!(f.method, "GET");
        assert_eq!(f.path, "/.git/HEAD");
        assert_eq!(f.req_header("host"), Some("ex.com:8443"));
        assert_eq!(f.url(), "https://ex.com:8443/.git/HEAD");
    }

    fn entry(rule_id: &'static str) -> &'static SensitivePath {
        PATHS.iter().find(|e| e.rule_id == rule_id).unwrap()
    }

    fn resp(status: u16, ct: &str, body: &[u8]) -> HttpFlow {
        HttpFlow::request("GET", "https", "ex.com", 443, "/p", vec![], vec![]).with_response(
            status,
            vec![("Content-Type".to_string(), ct.to_string())],
            body.to_vec(),
            5,
        )
    }

    #[test]
    fn body_any_hits_git_config() {
        let e = entry("disc-git-config");
        let r = resp(200, "text/plain", b"[core]\n\trepositoryformatversion = 0\n");
        let f = evaluate_path(e, &r, None).unwrap();
        assert_eq!(f.rule_id, "disc-git-config");
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn body_any_miss_on_clean_or_non_2xx() {
        let e = entry("disc-git-config");
        // 200 但无签名 → 不命中。
        assert!(evaluate_path(e, &resp(200, "text/html", b"<html>not here</html>"), None).is_none());
        // 含签名但 404 → 不命中。
        assert!(evaluate_path(e, &resp(404, "text/plain", b"[core]"), None).is_none());
    }

    #[test]
    fn exists_suppressed_by_soft_404_baseline() {
        let e = entry("disc-htpasswd"); // Sig::Exists
        // 站点对一切路径都回 200 + 同样长度的软 404 页。
        let base = Baseline {
            status: 200,
            body_len: 1000,
        };
        let soft = resp(200, "text/html", &[b'x'; 1000]);
        assert!(evaluate_path(e, &soft, Some(&base)).is_none());
        // 与基线显著不同(长度差很大)→ 视作真实存在 → 命中。
        let real = resp(200, "text/plain", &[b'y'; 50]);
        assert_eq!(evaluate_path(e, &real, Some(&base)).unwrap().rule_id, "disc-htpasswd");
    }

    #[test]
    fn magic_hits_zip_and_misses_text() {
        let e = entry("disc-backup-zip");
        let zip = resp(200, "application/zip", b"PK\x03\x04\x14\x00rest-of-archive");
        assert_eq!(evaluate_path(e, &zip, None).unwrap().rule_id, "disc-backup-zip");
        // 普通 HTML 不以 PK 开头 → 不命中。
        assert!(evaluate_path(e, &resp(200, "text/html", b"<html></html>"), None).is_none());
    }

    #[test]
    fn ignores_no_response() {
        let e = entry("disc-git-head");
        let mut r = resp(200, "text/plain", b"ref: refs/heads/main");
        r.status = 0; // 无响应
        assert!(evaluate_path(e, &r, None).is_none());
    }

    #[test]
    fn every_entry_has_unique_rule_id() {
        let mut ids: Vec<&str> = PATHS.iter().map(|e| e.rule_id).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n, "rule_id 必须唯一");
    }
}
