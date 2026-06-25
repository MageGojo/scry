//! nuclei 模板 schema 子集 + YAML 解析。
//!
//! 解析策略:先把 YAML 解析成通用 [`serde_yaml::Value`],再**手动游走**取字段。相比强类型
//! `derive(Deserialize)`,这样对社区模板五花八门的写法(单值 vs 列表、字符串 vs 数字、缺字段)
//! **极度宽容**——任何结构意外都退化为默认值,而不是让整个模板解析失败被丢弃。目标是「能加载的
//! 尽量加载」,真正不支持的(dns/tcp/code/headless 协议、无 matcher)才显式跳过并计数。

use serde_yaml::Value;

/// 漏洞 / 检测严重度(对齐 nuclei `info.severity`)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Unknown,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Severity {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => Severity::Unknown,
        }
    }
    /// 英文标签(界面 i18n key)。
    pub fn label(self) -> &'static str {
        match self {
            Severity::Unknown => "Unknown",
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }
}

/// 多项之间的逻辑(matcher 之间 / 一个 matcher 内多 word 之间)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    And,
    Or,
}

impl Condition {
    fn parse(s: &str) -> Condition {
        if s.trim().eq_ignore_ascii_case("and") {
            Condition::And
        } else {
            Condition::Or
        }
    }
}

/// 匹配 / 提取作用的响应部位。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    Body,
    Header,
    All,
}

impl Part {
    fn parse(s: &str) -> Part {
        match s.trim().to_ascii_lowercase().as_str() {
            "header" | "all_headers" => Part::Header,
            "all" | "response" | "raw" => Part::All,
            _ => Part::Body, // body / interactsh_* / 未知 → body
        }
    }
}

/// matcher 的具体类型 + 其数据。
#[derive(Debug, Clone)]
pub enum MatcherKind {
    Word(Vec<String>),
    Regex(Vec<String>),
    Status(Vec<u16>),
    Size(Vec<usize>),
    Dsl(Vec<String>),
    /// 十六进制串解码出的字节序列(在原始字节里做子串扫描)。
    Binary(Vec<Vec<u8>>),
}

/// 一个 matcher(对应 YAML `matchers:` 列表的一项)。
#[derive(Debug, Clone)]
pub struct Matcher {
    pub kind: MatcherKind,
    pub part: Part,
    /// 本 matcher 内多项之间的逻辑(words/regex/dsl/binary)。
    pub condition: Condition,
    pub negative: bool,
    pub case_insensitive: bool,
    pub name: Option<String>,
}

/// extractor 的具体类型 + 其数据。
#[derive(Debug, Clone)]
pub enum ExtractorKind {
    Regex { patterns: Vec<String>, group: usize },
    Kval(Vec<String>),
    Dsl(Vec<String>),
}

/// 一个 extractor(对应 YAML `extractors:` 列表的一项)。
#[derive(Debug, Clone)]
pub struct Extractor {
    pub kind: ExtractorKind,
    pub part: Part,
    pub name: Option<String>,
}

/// 一个 HTTP 请求块(对应 `http:` / `requests:` 列表的一项)。
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// 整段原始请求模板(与 `paths` 互斥;变量插值后解析)。
    pub raw: Vec<String>,
    /// 模板化 path(如 `{{BaseURL}}/.git/config`)。
    pub paths: Vec<String>,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// matcher 之间的逻辑。
    pub matchers_condition: Condition,
    pub stop_at_first_match: bool,
    pub matchers: Vec<Matcher>,
    pub extractors: Vec<Extractor>,
}

/// 模板元信息。
#[derive(Debug, Clone)]
pub struct Info {
    pub name: String,
    pub author: String,
    pub severity: Severity,
    pub description: String,
    pub tags: Vec<String>,
    pub reference: Vec<String>,
}

/// 一个解析后的 nuclei 模板(HTTP 子集)。
#[derive(Debug, Clone)]
pub struct Template {
    pub id: String,
    pub info: Info,
    pub requests: Vec<Request>,
}

impl Template {
    pub fn severity(&self) -> Severity {
        self.info.severity
    }
    /// 模板内 matcher 总数(用于过滤无效模板 / 统计)。
    pub fn matcher_count(&self) -> usize {
        self.requests.iter().map(|r| r.matchers.len()).sum()
    }
    /// 是否带某标签(大小写不敏感)。
    pub fn has_tag(&self, tag: &str) -> bool {
        self.info.tags.iter().any(|x| x.eq_ignore_ascii_case(tag))
    }
}

/// 解析失败原因(用于加载统计:语法错 / 不支持 / 无效)。
#[derive(Debug, Clone)]
pub enum ParseError {
    /// YAML 语法错误。
    Yaml(String),
    /// 不支持的协议 / 形态(dns/tcp/code/headless、无 http 块、无可用 matcher)。
    Unsupported(String),
    /// 必要字段缺失(如 id)。
    Invalid(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Yaml(e) => write!(f, "YAML 解析失败: {e}"),
            ParseError::Unsupported(e) => write!(f, "不支持: {e}"),
            ParseError::Invalid(e) => write!(f, "无效模板: {e}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// 解析一个 nuclei 模板(YAML 文本)→ HTTP 子集 [`Template`]。
pub fn parse_template(yaml: &str) -> Result<Template, ParseError> {
    let doc: Value = serde_yaml::from_str(yaml).map_err(|e| ParseError::Yaml(e.to_string()))?;
    if !doc.is_mapping() {
        return Err(ParseError::Invalid("顶层不是 mapping".into()));
    }

    let id = scalar_string(mget(&doc, "id"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ParseError::Invalid("缺少 id".into()))?;

    // HTTP 块:v3 用 `http`,v2 用 `requests`。都没有则按其它协议判不支持。
    let http = mget(&doc, "http").or_else(|| mget(&doc, "requests"));
    let Some(http) = http else {
        for proto in [
            "dns", "tcp", "ssl", "file", "headless", "code", "flow", "network", "javascript",
            "whois", "websocket",
        ] {
            if mget(&doc, proto).is_some() {
                return Err(ParseError::Unsupported(format!("{proto} 协议")));
            }
        }
        return Err(ParseError::Unsupported("无 http 请求块".into()));
    };

    let info = parse_info(mget(&doc, "info"), &id);

    let mut requests = Vec::new();
    if let Some(seq) = http.as_sequence() {
        for item in seq {
            if let Some(req) = parse_request(item) {
                requests.push(req);
            }
        }
    }

    if requests.is_empty() {
        return Err(ParseError::Unsupported("无可解析的请求块".into()));
    }
    if requests.iter().all(|r| r.matchers.is_empty()) {
        return Err(ParseError::Unsupported("无可用 matcher".into()));
    }

    Ok(Template {
        id,
        info,
        requests,
    })
}

// ───────────────────────── 子解析 ─────────────────────────

fn parse_info(info: Option<&Value>, fallback_id: &str) -> Info {
    let name = info
        .and_then(|v| scalar_string(mget(v, "name")))
        .unwrap_or_else(|| fallback_id.to_string());
    let author = info
        .and_then(|v| scalar_string(mget(v, "author")))
        .unwrap_or_default();
    let severity = info
        .and_then(|v| scalar_string(mget(v, "severity")))
        .map(|s| Severity::parse(&s))
        .unwrap_or(Severity::Unknown);
    let description = info
        .and_then(|v| scalar_string(mget(v, "description")))
        .unwrap_or_default();
    // tags:逗号串或列表。
    let tags = info
        .and_then(|v| mget(v, "tags"))
        .map(parse_tags)
        .unwrap_or_default();
    let reference = info
        .map(|v| string_list(mget(v, "reference")))
        .unwrap_or_default();
    Info {
        name,
        author,
        severity,
        description,
        tags,
        reference,
    }
}

fn parse_tags(v: &Value) -> Vec<String> {
    if let Some(s) = v.as_str() {
        return s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect();
    }
    string_list(Some(v))
}

fn parse_request(v: &Value) -> Option<Request> {
    if !v.is_mapping() {
        return None;
    }
    let method = scalar_string(mget(v, "method"))
        .unwrap_or_else(|| "GET".into())
        .trim()
        .to_uppercase();
    let raw = string_list(mget(v, "raw"));
    let paths = string_list(mget(v, "path"));
    let headers = map_pairs(mget(v, "headers"));
    let body = scalar_string(mget(v, "body")).unwrap_or_default();
    let matchers_condition = scalar_string(mget(v, "matchers-condition"))
        .map(|s| Condition::parse(&s))
        .unwrap_or(Condition::Or);
    let stop_at_first_match = bool_field(mget(v, "stop-at-first-match"));

    let mut matchers = Vec::new();
    if let Some(seq) = mget(v, "matchers").and_then(|m| m.as_sequence()) {
        for m in seq {
            if let Some(parsed) = parse_matcher(m) {
                matchers.push(parsed);
            }
        }
    }
    let mut extractors = Vec::new();
    if let Some(seq) = mget(v, "extractors").and_then(|m| m.as_sequence()) {
        for e in seq {
            if let Some(parsed) = parse_extractor(e) {
                extractors.push(parsed);
            }
        }
    }

    // 既无 path 也无 raw → 无法发请求,丢弃该块。
    if paths.is_empty() && raw.is_empty() {
        return None;
    }

    Some(Request {
        method,
        raw,
        paths,
        headers,
        body,
        matchers_condition,
        stop_at_first_match,
        matchers,
        extractors,
    })
}

fn parse_matcher(v: &Value) -> Option<Matcher> {
    if !v.is_mapping() {
        return None;
    }
    let ty = scalar_string(mget(v, "type"))
        .unwrap_or_else(|| "word".into())
        .trim()
        .to_ascii_lowercase();
    let part = scalar_string(mget(v, "part"))
        .map(|s| Part::parse(&s))
        .unwrap_or(Part::Body);
    let condition = scalar_string(mget(v, "condition"))
        .map(|s| Condition::parse(&s))
        .unwrap_or(Condition::Or);
    let negative = bool_field(mget(v, "negative"));
    let case_insensitive = bool_field(mget(v, "case-insensitive"));
    let name = scalar_string(mget(v, "name"));

    let kind = match ty.as_str() {
        "word" => {
            let words = string_list(mget(v, "words"));
            if words.is_empty() {
                return None;
            }
            MatcherKind::Word(words)
        }
        "regex" => {
            let rx = string_list(mget(v, "regex"));
            if rx.is_empty() {
                return None;
            }
            MatcherKind::Regex(rx)
        }
        "status" => {
            let codes: Vec<u16> = int_list(mget(v, "status"))
                .into_iter()
                .filter(|n| (0..=65535).contains(n))
                .map(|n| n as u16)
                .collect();
            if codes.is_empty() {
                return None;
            }
            MatcherKind::Status(codes)
        }
        "size" => {
            let sizes: Vec<usize> = int_list(mget(v, "size"))
                .into_iter()
                .filter(|n| *n >= 0)
                .map(|n| n as usize)
                .collect();
            if sizes.is_empty() {
                return None;
            }
            MatcherKind::Size(sizes)
        }
        "dsl" => {
            let exprs = string_list(mget(v, "dsl"));
            if exprs.is_empty() {
                return None;
            }
            MatcherKind::Dsl(exprs)
        }
        "binary" => {
            let bins: Vec<Vec<u8>> = string_list(mget(v, "binary"))
                .iter()
                .filter_map(|h| hex_decode(h))
                .filter(|b| !b.is_empty())
                .collect();
            if bins.is_empty() {
                return None;
            }
            MatcherKind::Binary(bins)
        }
        _ => return None, // 不支持的 matcher 类型(如 xpath / dsl-extension)→ 跳过
    };

    Some(Matcher {
        kind,
        part,
        condition,
        negative,
        case_insensitive,
        name,
    })
}

fn parse_extractor(v: &Value) -> Option<Extractor> {
    if !v.is_mapping() {
        return None;
    }
    let ty = scalar_string(mget(v, "type"))
        .unwrap_or_else(|| "regex".into())
        .trim()
        .to_ascii_lowercase();
    let part = scalar_string(mget(v, "part"))
        .map(|s| Part::parse(&s))
        .unwrap_or(Part::Body);
    let name = scalar_string(mget(v, "name"));

    let kind = match ty.as_str() {
        "regex" => {
            let patterns = string_list(mget(v, "regex"));
            if patterns.is_empty() {
                return None;
            }
            let group = int_list(mget(v, "group"))
                .first()
                .copied()
                .filter(|n| *n >= 0)
                .unwrap_or(0) as usize;
            ExtractorKind::Regex { patterns, group }
        }
        "kval" => {
            let keys = string_list(mget(v, "kval"));
            if keys.is_empty() {
                return None;
            }
            ExtractorKind::Kval(keys)
        }
        "dsl" => {
            let exprs = string_list(mget(v, "dsl"));
            if exprs.is_empty() {
                return None;
            }
            ExtractorKind::Dsl(exprs)
        }
        _ => return None, // json / xpath 暂不支持
    };

    Some(Extractor { kind, part, name })
}

// ───────────────────────── Value 取值小工具 ─────────────────────────

/// 在一个 mapping 里按字符串 key 取值(不依赖 serde_yaml 的 Index impl,直接遍历更稳)。
fn mget<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    let m = v.as_mapping()?;
    for (k, val) in m {
        if k.as_str() == Some(key) {
            return Some(val);
        }
    }
    None
}

/// 把一个标量(字符串 / 数字 / 布尔)取成字符串。
fn scalar_string(v: Option<&Value>) -> Option<String> {
    let v = v?;
    if let Some(s) = v.as_str() {
        return Some(s.to_string());
    }
    if let Some(i) = v.as_i64() {
        return Some(i.to_string());
    }
    if let Some(u) = v.as_u64() {
        return Some(u.to_string());
    }
    if let Some(f) = v.as_f64() {
        return Some(f.to_string());
    }
    if let Some(b) = v.as_bool() {
        return Some(b.to_string());
    }
    None
}

/// 取「字符串列表」:接受单个标量(裹成 1 元列表)或序列(逐项标量化)。
fn string_list(v: Option<&Value>) -> Vec<String> {
    let Some(v) = v else {
        return Vec::new();
    };
    if let Some(seq) = v.as_sequence() {
        return seq
            .iter()
            .filter_map(|x| scalar_string(Some(x)))
            .collect();
    }
    scalar_string(Some(v)).into_iter().collect()
}

/// 取「整数列表」:接受单个整数 / 数字串,或序列。
fn int_list(v: Option<&Value>) -> Vec<i64> {
    let Some(v) = v else {
        return Vec::new();
    };
    let one = |x: &Value| -> Option<i64> {
        if let Some(i) = x.as_i64() {
            return Some(i);
        }
        if let Some(u) = x.as_u64() {
            return Some(u as i64);
        }
        x.as_str().and_then(|s| s.trim().parse::<i64>().ok())
    };
    if let Some(seq) = v.as_sequence() {
        return seq.iter().filter_map(one).collect();
    }
    one(v).into_iter().collect()
}

/// 取 mapping → (key, value) 对(值标量化)。
fn map_pairs(v: Option<&Value>) -> Vec<(String, String)> {
    let Some(v) = v.and_then(|x| x.as_mapping()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (k, val) in v {
        if let (Some(k), Some(val)) = (k.as_str(), scalar_string(Some(val))) {
            out.push((k.to_string(), val));
        }
    }
    out
}

/// 布尔字段:接受真正的 bool 或字符串 "true"/"false"。
fn bool_field(v: Option<&Value>) -> bool {
    match v {
        Some(v) => v
            .as_bool()
            .or_else(|| v.as_str().map(|s| s.eq_ignore_ascii_case("true")))
            .unwrap_or(false),
        None => false,
    }
}

/// 解码十六进制串(允许空格 / 大小写;奇数长度或非法字符 → None)。
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
        return None;
    }
    let bytes = cleaned.as_bytes();
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIT: &str = r#"
id: git-config
info:
  name: Git Config Exposure
  author: pdteam
  severity: medium
  tags: config,git,exposure
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "[core]"
          - "repositoryformatversion ="
        condition: and
      - type: status
        status:
          - 200
"#;

    #[test]
    fn parses_basic_template() {
        let t = parse_template(GIT).unwrap();
        assert_eq!(t.id, "git-config");
        assert_eq!(t.info.name, "Git Config Exposure");
        assert_eq!(t.info.severity, Severity::Medium);
        assert!(t.has_tag("git"));
        assert_eq!(t.requests.len(), 1);
        let r = &t.requests[0];
        assert_eq!(r.method, "GET");
        assert_eq!(r.paths, vec!["{{BaseURL}}/.git/config"]);
        assert_eq!(r.matchers_condition, Condition::And);
        assert_eq!(r.matchers.len(), 2);
        match &r.matchers[0].kind {
            MatcherKind::Word(w) => assert_eq!(w.len(), 2),
            _ => panic!("expected word matcher"),
        }
        assert_eq!(r.matchers[0].condition, Condition::And);
        match &r.matchers[1].kind {
            MatcherKind::Status(s) => assert_eq!(s, &vec![200]),
            _ => panic!("expected status matcher"),
        }
    }

    #[test]
    fn raw_and_extractors() {
        let y = r#"
id: ver
info:
  name: Version
  severity: info
http:
  - raw:
      - |
        GET /version HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: regex
        regex:
          - "v[0-9.]+"
    extractors:
      - type: regex
        part: body
        group: 0
        regex:
          - "v[0-9.]+"
      - type: kval
        kval:
          - server
"#;
        let t = parse_template(y).unwrap();
        let r = &t.requests[0];
        assert_eq!(r.raw.len(), 1);
        assert!(r.raw[0].contains("GET /version"));
        assert_eq!(r.extractors.len(), 2);
        match &r.extractors[0].kind {
            ExtractorKind::Regex { patterns, group } => {
                assert_eq!(patterns.len(), 1);
                assert_eq!(*group, 0);
            }
            _ => panic!("expected regex extractor"),
        }
        match &r.extractors[1].kind {
            ExtractorKind::Kval(k) => assert_eq!(k, &vec!["server".to_string()]),
            _ => panic!("expected kval extractor"),
        }
    }

    #[test]
    fn unsupported_protocols_are_rejected() {
        let dns = "id: x\ninfo:\n  name: x\n  severity: info\ndns:\n  - name: example.com\n";
        assert!(matches!(
            parse_template(dns),
            Err(ParseError::Unsupported(_))
        ));
        let nomatch = "id: x\ninfo:\n  name: x\nhttp:\n  - path:\n      - \"{{BaseURL}}/\"\n";
        assert!(matches!(
            parse_template(nomatch),
            Err(ParseError::Unsupported(_))
        ));
    }

    #[test]
    fn missing_id_is_invalid() {
        let y = "info:\n  name: x\nhttp:\n  - path: [\"{{BaseURL}}/\"]\n    matchers:\n      - type: status\n        status: [200]\n";
        assert!(matches!(parse_template(y), Err(ParseError::Invalid(_))));
    }

    #[test]
    fn tags_as_list_and_single_status() {
        let y = r#"
id: t
info:
  name: t
  severity: high
  tags:
    - aaa
    - bbb
http:
  - path: ["{{BaseURL}}/x"]
    matchers:
      - type: status
        status: 200
"#;
        let t = parse_template(y).unwrap();
        assert!(t.has_tag("aaa") && t.has_tag("bbb"));
        // status 单值(非列表)也应被接受。
        match &t.requests[0].matchers[0].kind {
            MatcherKind::Status(s) => assert_eq!(s, &vec![200]),
            _ => panic!(),
        }
    }

    #[test]
    fn hex_decode_works() {
        assert_eq!(hex_decode("4142"), Some(vec![0x41, 0x42]));
        assert_eq!(hex_decode("ff 00"), Some(vec![0xff, 0x00]));
        assert_eq!(hex_decode("xyz"), None);
        assert_eq!(hex_decode("abc"), None); // 奇数长度
    }
}
