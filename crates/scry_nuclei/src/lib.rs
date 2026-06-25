//! Scry nuclei 引擎 —— [`projectdiscovery/nuclei`](https://github.com/projectdiscovery/nuclei)
//! **HTTP 模板子集**的纯函数内核。
//!
//! 价值:一次实现引擎,即可白嫖社区
//! [`nuclei-templates`](https://github.com/projectdiscovery/nuclei-templates) 的几千个检测模板
//! (CVE / 暴露 / 错误配置 / 默认口令 / 指纹…),无需逐个手写规则。
//!
//! 设计与 `scry_sqli` / `scry_xss` / `scry_scan` 一致:**只读、可单测的纯函数**;真正发包由
//! `scry_app` 的 runner 复用 [`scry_proxy::replay`] 完成(后台 runtime 串行 + mpsc 流式回填)。
//!
//! 流水线:
//! 1. [`parse_template`] —— YAML → [`Template`](HTTP 子集;宽容解析,见 [`template`])。
//! 2. [`build_block_requests`] —— 一个请求块 + [`Target`] → 一批具体 [`BuiltRequest`]
//!    (`path` / `raw` 两形态 + `{{BaseURL}}` 等变量插值)。
//! 3. runner 用 `replay::send` 发请求,拿响应组 [`RespData`]。
//! 4. [`evaluate_request`] —— 跑 matchers(word/regex/status/size/binary/dsl)判命中、
//!    跑 extractors(regex/kval/dsl)抽证据。
//!
//! 子集边界见 `docs/设计-nuclei模板引擎.md`(不做多请求跨响应关联 / 非 http 协议 /
//! fuzzing / interactsh,后者由 `scry_oob` 覆盖)。

pub mod builtins;
pub mod dsl;
pub mod extractor;
pub mod matcher;
pub mod template;

pub use builtins::{load_builtins, BUILTIN_TEMPLATES};
pub use extractor::{extract, extractor_label};
pub use matcher::{matcher_label, matcher_matches};
pub use template::{
    parse_template, Condition, Extractor, ExtractorKind, Info, Matcher, MatcherKind, ParseError,
    Part, Request, Severity, Template,
};

/// 一次响应的只读视图(matcher / extractor 求值的输入)。
#[derive(Debug, Clone, Copy)]
pub struct RespData<'a> {
    pub status: u16,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    pub duration_ms: u64,
}

impl<'a> RespData<'a> {
    pub fn new(
        status: u16,
        headers: &'a [(String, String)],
        body: &'a [u8],
        duration_ms: u64,
    ) -> Self {
        Self {
            status,
            headers,
            body,
            duration_ms,
        }
    }
}

/// 扫描目标:单个 `scheme://host[:port][/base]`。
#[derive(Debug, Clone)]
pub struct Target {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// 基路径(常为空;末尾 `/` 已去除)。
    pub base_path: String,
}

impl Target {
    /// 解析 `scheme://host[:port][/path]`;无 scheme 默认 https,无端口按 scheme 取 80/443。
    pub fn parse(url: &str) -> Option<Target> {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            return None;
        }
        let (scheme, rest) = match trimmed.split_once("://") {
            Some((s, r)) => (s.to_ascii_lowercase(), r),
            None => ("https".to_string(), trimmed),
        };
        if rest.is_empty() {
            return None;
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, String::new()),
        };
        let default_port = if scheme == "https" { 443 } else { 80 };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
            None => (authority.to_string(), default_port),
        };
        if host.is_empty() {
            return None;
        }
        Some(Target {
            scheme,
            host,
            port,
            base_path: path.trim_end_matches('/').to_string(),
        })
    }

    fn is_default_port(&self) -> bool {
        matches!(
            (self.scheme.as_str(), self.port),
            ("http", 80) | ("https", 443)
        )
    }

    /// 根 URL `scheme://host[:port]`(省略默认端口)。
    pub fn root_url(&self) -> String {
        if self.is_default_port() {
            format!("{}://{}", self.scheme, self.host)
        } else {
            format!("{}://{}:{}", self.scheme, self.host, self.port)
        }
    }

    /// `{{BaseURL}}` = 根 URL + 基路径。
    pub fn base_url(&self) -> String {
        format!("{}{}", self.root_url(), self.base_path)
    }

    /// `{{Hostname}}` = host[:port](省略默认端口)。
    pub fn hostname(&self) -> String {
        if self.is_default_port() {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// 把 `{{…}}` 变量替换为目标的具体值(未知变量原样保留,best-effort)。
pub fn substitute(s: &str, target: &Target) -> String {
    s.replace("{{BaseURL}}", &target.base_url())
        .replace("{{RootURL}}", &target.root_url())
        .replace("{{Hostname}}", &target.hostname())
        .replace("{{Host}}", &target.host)
        .replace("{{Port}}", &target.port.to_string())
        .replace("{{Scheme}}", &target.scheme)
        .replace("{{Path}}", &target.base_path)
}

/// 由模板请求块展开出的一条具体 HTTP 请求(交给 runner 用 replay 发送)。
#[derive(Debug, Clone)]
pub struct BuiltRequest {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// origin-form 路径 + 查询串。
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl BuiltRequest {
    /// 完整 URL(命中报告里展示)。
    pub fn url(&self) -> String {
        let default = matches!(
            (self.scheme.as_str(), self.port),
            ("http", 80) | ("https", 443)
        );
        if default {
            format!("{}://{}{}", self.scheme, self.host, self.path)
        } else {
            format!("{}://{}:{}{}", self.scheme, self.host, self.port, self.path)
        }
    }
}

/// 把一个请求块 + 目标展开成一批具体请求(`path` 与 `raw` 都处理)。
pub fn build_block_requests(req: &Request, target: &Target) -> Vec<BuiltRequest> {
    let mut out = Vec::new();
    let body = substitute(&req.body, target);
    let subst_headers: Vec<(String, String)> = req
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), substitute(v, target)))
        .collect();

    // path 形态:每个 path 插值后通常是完整 URL(`{{BaseURL}}/x`)。
    for p in &req.paths {
        let sp = substitute(p, target);
        let built = if sp.contains("://") {
            let Some((scheme, host, port, path)) = split_url(&sp) else {
                continue;
            };
            let mut headers = subst_headers.clone();
            ensure_header(&mut headers, "Host", &host_header(&host, port, &scheme));
            ensure_header(&mut headers, "User-Agent", DEFAULT_UA);
            ensure_header(&mut headers, "Accept", "*/*");
            BuiltRequest {
                method: req.method.clone(),
                scheme,
                host,
                port,
                path,
                headers,
                body: body.clone().into_bytes(),
            }
        } else {
            // 罕见:非完整 URL 的 path,挂在目标根上。
            let path = if sp.starts_with('/') {
                sp
            } else {
                format!("/{sp}")
            };
            let mut headers = subst_headers.clone();
            ensure_header(&mut headers, "Host", &target.hostname());
            ensure_header(&mut headers, "User-Agent", DEFAULT_UA);
            ensure_header(&mut headers, "Accept", "*/*");
            BuiltRequest {
                method: req.method.clone(),
                scheme: target.scheme.clone(),
                host: target.host.clone(),
                port: target.port,
                path,
                headers,
                body: body.clone().into_bytes(),
            }
        };
        out.push(built);
    }

    // raw 形态:整段原始请求,插值后解析。
    for raw in &req.raw {
        let sr = substitute(raw, target);
        if let Some(b) = build_from_raw(&sr, target, &req.method) {
            out.push(b);
        }
    }

    out
}

/// matcher / extractor 求值结果。
#[derive(Debug, Clone, Default)]
pub struct EvalResult {
    /// 模板是否对该响应命中。
    pub matched: bool,
    /// 命中的 matcher 名 / 类型(展示用)。
    pub matched_names: Vec<String>,
    /// 抽取到的证据:`(extractor 名/类型, 值)`。
    pub extracted: Vec<(String, String)>,
}

/// 对一个响应跑请求块的 matchers + extractors。
pub fn evaluate_request(req: &Request, resp: &RespData) -> EvalResult {
    if req.matchers.is_empty() {
        return EvalResult::default();
    }
    let mut names = Vec::new();
    let mut all = true;
    let mut any = false;
    for m in &req.matchers {
        let hit = matcher_matches(m, resp);
        if hit {
            names.push(matcher_label(m));
            any = true;
        } else {
            all = false;
        }
    }
    let matched = match req.matchers_condition {
        Condition::And => all,
        Condition::Or => any,
    };
    let extracted = if matched {
        let mut ex = Vec::new();
        for e in &req.extractors {
            for v in extract(e, resp) {
                ex.push((extractor_label(e), v));
            }
        }
        ex
    } else {
        Vec::new()
    };
    EvalResult {
        matched,
        matched_names: names,
        extracted,
    }
}

// ───────────────────────── 内部工具 ─────────────────────────

const DEFAULT_UA: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) scry-nuclei";

/// 拆完整 URL → (scheme, host, port, path)。
fn split_url(url: &str) -> Option<(String, String, u16, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if rest.is_empty() {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let default_port = if scheme == "https" { 443 } else { 80 };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (authority.to_string(), default_port),
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme, host, port, path))
}

/// Host 头值(省略默认端口)。
fn host_header(host: &str, port: u16, scheme: &str) -> String {
    let default = matches!((scheme, port), ("http", 80) | ("https", 443));
    if default {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// 若某头缺失(大小写不敏感)则追加。
fn ensure_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name)) {
        headers.push((name.to_string(), value.to_string()));
    }
}

/// 解析一段原始 HTTP 请求文本(raw 形态)→ [`BuiltRequest`]。
fn build_from_raw(raw: &str, target: &Target, method_default: &str) -> Option<BuiltRequest> {
    let norm = raw.replace("\r\n", "\n");
    let (head, body) = match norm.split_once("\n\n") {
        Some((h, b)) => (h, b),
        None => (norm.as_str(), ""),
    };
    let mut lines = head.lines();
    let request_line = lines.next()?.trim();
    if request_line.is_empty() {
        return None;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or(method_default).to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut headers = Vec::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    ensure_header(&mut headers, "Host", &target.hostname());
    ensure_header(&mut headers, "User-Agent", DEFAULT_UA);

    Some(BuiltRequest {
        method,
        scheme: target.scheme.clone(),
        host: target.host.clone(),
        port: target.port,
        path,
        headers,
        body: body.as_bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parsing_and_vars() {
        let t = Target::parse("https://example.com").unwrap();
        assert_eq!(t.scheme, "https");
        assert_eq!(t.port, 443);
        assert_eq!(t.base_url(), "https://example.com");
        assert_eq!(t.hostname(), "example.com");

        let t2 = Target::parse("http://h:8080/app/").unwrap();
        assert_eq!(t2.port, 8080);
        assert_eq!(t2.base_path, "/app");
        assert_eq!(t2.root_url(), "http://h:8080");
        assert_eq!(t2.base_url(), "http://h:8080/app");
        assert_eq!(t2.hostname(), "h:8080");

        // 无 scheme 默认 https。
        assert_eq!(Target::parse("example.org").unwrap().scheme, "https");
        assert!(Target::parse("").is_none());
    }

    #[test]
    fn substitute_known_vars() {
        let t = Target::parse("https://h:8443/x").unwrap();
        assert_eq!(
            substitute("{{BaseURL}}/.git/config", &t),
            "https://h:8443/x/.git/config"
        );
        assert_eq!(substitute("{{Hostname}}", &t), "h:8443");
        assert_eq!(substitute("{{Host}}:{{Port}}", &t), "h:8443");
        // 未知变量保留。
        assert_eq!(substitute("{{rand}}", &t), "{{rand}}");
    }

    #[test]
    fn build_path_requests_add_host() {
        let t = parse_template(
            "id: x\ninfo:\n  name: x\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/.git/config\"\n    matchers:\n      - type: status\n        status: [200]\n",
        )
        .unwrap();
        let target = Target::parse("https://example.com").unwrap();
        let reqs = build_block_requests(&t.requests[0], &target);
        assert_eq!(reqs.len(), 1);
        let r = &reqs[0];
        assert_eq!(r.method, "GET");
        assert_eq!(r.host, "example.com");
        assert_eq!(r.port, 443);
        assert_eq!(r.path, "/.git/config");
        assert!(r.headers.iter().any(|(k, _)| k == "Host"));
        assert_eq!(r.url(), "https://example.com/.git/config");
    }

    #[test]
    fn build_raw_requests() {
        let t = parse_template(
            "id: x\ninfo:\n  name: x\nhttp:\n  - raw:\n      - |\n        POST /login HTTP/1.1\n        Host: {{Hostname}}\n        Content-Type: application/json\n\n        {\"a\":1}\n    matchers:\n      - type: status\n        status: [200]\n",
        )
        .unwrap();
        let target = Target::parse("http://h:8080").unwrap();
        let reqs = build_block_requests(&t.requests[0], &target);
        assert_eq!(reqs.len(), 1);
        let r = &reqs[0];
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/login");
        assert_eq!(r.host, "h");
        assert_eq!(r.port, 8080);
        assert!(r.headers.iter().any(|(k, v)| k == "Host" && v == "h:8080"));
        // YAML `|` 块标量保留末尾换行,raw body 即 `{"a":1}\n`(与 nuclei 一致)。
        assert_eq!(r.body, b"{\"a\":1}\n");
    }

    #[test]
    fn evaluate_and_or_and_extract() {
        let t = parse_template(
            "id: x\ninfo:\n  name: x\nhttp:\n  - path: [\"{{BaseURL}}/x\"]\n    matchers-condition: and\n    matchers:\n      - type: word\n        words: [\"alpha\"]\n      - type: status\n        status: [200]\n    extractors:\n      - type: regex\n        group: 1\n        regex: ['v=([0-9]+)']\n",
        )
        .unwrap();
        let body = b"alpha v=42";
        let resp = RespData::new(200, &[], body, 10);
        let res = evaluate_request(&t.requests[0], &resp);
        assert!(res.matched);
        assert_eq!(res.extracted, vec![("regex".to_string(), "42".to_string())]);

        // and 条件:状态码不符 → 不命中,不抽取。
        let resp404 = RespData::new(404, &[], body, 10);
        let res2 = evaluate_request(&t.requests[0], &resp404);
        assert!(!res2.matched);
        assert!(res2.extracted.is_empty());
    }
}
