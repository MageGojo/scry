//! 代理拦截规则:**自定义拦截范围(Scope)** + **Match & Replace 自动改包**。纯逻辑 + 单测。
//!
//! - UI 侧持有可编辑的纯结构(`ScopeRule` / `ReplaceRule`),增删 / 启停或抓包启动时
//!   `compile()` 成预编译快照(`CompiledScope` / `CompiledReplace`,含编译好的正则)推给 `ExtRegistry`;
//! - 引擎逐请求只读快照:`should_intercept` 决定是否暂停、`CompiledReplace::apply` 自动改包。
//!
//! 详见 `docs/设计-拦截规则.md`。

use regex::Regex;
use serde::{Deserialize, Serialize};
use scry_core::{Header, HttpFlow};

use crate::ext::InterceptDir;

// ───────────────────────── 条件:字段 + 算子 ─────────────────────────

/// 条件匹配的报文字段。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Field {
    Url,
    Host,
    Path,
    Method,
    Status,
    ReqHeaders,
    ReqBody,
    RespHeaders,
    RespBody,
    Any,
}

impl Field {
    pub const ALL: [Field; 10] = [
        Field::Url,
        Field::Host,
        Field::Path,
        Field::Method,
        Field::Status,
        Field::ReqHeaders,
        Field::ReqBody,
        Field::RespHeaders,
        Field::RespBody,
        Field::Any,
    ];

    /// i18n 键(英文原文即键)。
    pub fn label(self) -> &'static str {
        match self {
            Field::Url => "URL",
            Field::Host => "Host",
            Field::Path => "Path",
            Field::Method => "Method",
            Field::Status => "Status",
            Field::ReqHeaders => "Request headers",
            Field::ReqBody => "Request body",
            Field::RespHeaders => "Response headers",
            Field::RespBody => "Response body",
            Field::Any => "Anywhere",
        }
    }
}

/// 匹配算子。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Op {
    Contains,
    Equals,
    Wildcard,
    Regex,
}

impl Op {
    pub const ALL: [Op; 4] = [Op::Contains, Op::Equals, Op::Wildcard, Op::Regex];

    pub fn label(self) -> &'static str {
        match self {
            Op::Contains => "contains",
            Op::Equals => "equals",
            Op::Wildcard => "wildcard",
            Op::Regex => "regex",
        }
    }
}

/// 一个条件(UI 可编辑的纯结构)。
#[derive(Clone)]
pub struct Condition {
    pub field: Field,
    pub op: Op,
    pub value: String,
    /// 取反:命中时视为不命中(对标 Burp 的 "does not")。
    pub negate: bool,
}

/// 取出某字段的待匹配文本(头逐行 `Name: Value`;`Any` 汇总 URL + 头 + 体)。
fn field_values(flow: &HttpFlow, field: Field) -> Vec<String> {
    let header_lines = |hs: &[Header]| -> Vec<String> {
        hs.iter().map(|(k, v)| format!("{k}: {v}")).collect()
    };
    match field {
        Field::Url => vec![flow.url()],
        Field::Host => vec![flow.host.clone()],
        Field::Path => vec![flow.path.clone()],
        Field::Method => vec![flow.method.clone()],
        Field::Status => vec![flow.status.to_string()],
        Field::ReqHeaders => header_lines(&flow.req_headers),
        Field::RespHeaders => header_lines(&flow.resp_headers),
        Field::ReqBody => vec![String::from_utf8_lossy(&flow.req_body).into_owned()],
        Field::RespBody => vec![String::from_utf8_lossy(&flow.resp_body).into_owned()],
        Field::Any => {
            let mut v = vec![flow.url()];
            v.extend(header_lines(&flow.req_headers));
            v.extend(header_lines(&flow.resp_headers));
            v.push(String::from_utf8_lossy(&flow.req_body).into_owned());
            v.push(String::from_utf8_lossy(&flow.resp_body).into_owned());
            v
        }
    }
}

/// 把通配模式(`*` 任意串 / `?` 单字符)编译成锚定正则。
fn wildcard_regex(pat: &str) -> Option<Regex> {
    let mut re = String::from("^");
    for ch in pat.chars() {
        match ch {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
    }
    re.push('$');
    Regex::new(&re).ok()
}

/// 编译后的匹配器(预编译正则,逐请求只读)。
enum Matcher {
    Contains(String),
    Equals(String),
    Re(Regex),
    /// 正则 / 通配编译失败 → 永不命中(不 panic)。
    Never,
}

/// 编译后的条件。
pub struct CompiledCond {
    field: Field,
    matcher: Matcher,
    negate: bool,
}

impl Condition {
    pub fn compile(&self) -> CompiledCond {
        let matcher = match self.op {
            Op::Contains => Matcher::Contains(self.value.clone()),
            Op::Equals => Matcher::Equals(self.value.clone()),
            Op::Wildcard => wildcard_regex(&self.value).map(Matcher::Re).unwrap_or(Matcher::Never),
            Op::Regex => Regex::new(&self.value).map(Matcher::Re).unwrap_or(Matcher::Never),
        };
        CompiledCond {
            field: self.field,
            matcher,
            negate: self.negate,
        }
    }
}

impl CompiledCond {
    pub fn matches(&self, flow: &HttpFlow) -> bool {
        let base = field_values(flow, self.field).iter().any(|h| match &self.matcher {
            Matcher::Contains(s) => h.contains(s.as_str()),
            Matcher::Equals(s) => h == s,
            Matcher::Re(re) => re.is_match(h),
            Matcher::Never => false,
        });
        base ^ self.negate
    }
}

// ───────────────────────── 拦截范围(Scope) ─────────────────────────

/// 一条拦截范围规则:某方向 + 条件 + 动作(拦截 / 跳过)。
#[derive(Clone)]
pub struct ScopeRule {
    pub enabled: bool,
    pub dir: InterceptDir,
    pub cond: Condition,
    /// `true` = 命中则拦截;`false` = 命中则跳过(排除)。
    pub intercept: bool,
}

/// 编译后的拦截范围规则。
pub struct CompiledScope {
    pub enabled: bool,
    pub dir: InterceptDir,
    pub intercept: bool,
    cond: CompiledCond,
}

impl ScopeRule {
    pub fn compile(&self) -> CompiledScope {
        CompiledScope {
            enabled: self.enabled,
            dir: self.dir,
            intercept: self.intercept,
            cond: self.cond.compile(),
        }
    }
}

/// 在某方向决定是否暂停该流(仅当该方向开关已开、`default_on=true` 时调用):
/// - 该方向无规则 → 返回 `default_on`(= 拦全部,保持旧行为);
/// - 命中任一「跳过」规则 → 不拦(排除优先);
/// - 存在「拦截」规则 → 命中其一才拦;
/// - 只有「跳过」规则且都没命中 → 拦。
pub fn should_intercept(
    flow: &HttpFlow,
    dir: InterceptDir,
    rules: &[CompiledScope],
    default_on: bool,
) -> bool {
    let mut any = false;
    let mut has_include = false;
    let mut matched_include = false;
    let mut matched_exclude = false;
    for r in rules.iter().filter(|r| r.enabled && r.dir == dir) {
        any = true;
        if r.intercept {
            has_include = true;
            if r.cond.matches(flow) {
                matched_include = true;
            }
        } else if r.cond.matches(flow) {
            matched_exclude = true;
        }
    }
    if !any {
        return default_on;
    }
    if matched_exclude {
        return false;
    }
    if has_include {
        return matched_include;
    }
    true
}

// ───────────────────────── Match & Replace ─────────────────────────

/// 替换规则的作用目标。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Target {
    ReqPath,
    ReqHeaders,
    ReqBody,
    RespHeaders,
    RespBody,
}

impl Target {
    pub const ALL: [Target; 5] = [
        Target::ReqPath,
        Target::ReqHeaders,
        Target::ReqBody,
        Target::RespHeaders,
        Target::RespBody,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Target::ReqPath => "Request path",
            Target::ReqHeaders => "Request header",
            Target::ReqBody => "Request body",
            Target::RespHeaders => "Response header",
            Target::RespBody => "Response body",
        }
    }

    /// 该目标属于请求向(在 `on_request` 应用),否则响应向(`on_response`)。
    pub fn is_request(self) -> bool {
        matches!(self, Target::ReqPath | Target::ReqHeaders | Target::ReqBody)
    }
}

/// 一条 Match & Replace 规则(UI 可编辑纯结构)。
#[derive(Clone)]
pub struct ReplaceRule {
    pub enabled: bool,
    pub target: Target,
    pub is_regex: bool,
    /// 待匹配串;**为空 = 追加**(头:把 `replace` 当作 `Name: Value` 新增头;体 / 路径:空匹配不动)。
    pub find: String,
    pub replace: String,
}

enum RKind {
    Literal(String),
    Re(Regex),
    /// `find` 为空:头追加新行,其它目标视为 no-op。
    Append,
    /// 正则编译失败 → no-op。
    Never,
}

/// 编译后的替换规则。
pub struct CompiledReplace {
    pub enabled: bool,
    pub target: Target,
    kind: RKind,
    replace: String,
}

impl ReplaceRule {
    pub fn compile(&self) -> CompiledReplace {
        let kind = if self.find.is_empty() {
            RKind::Append
        } else if self.is_regex {
            Regex::new(&self.find).map(RKind::Re).unwrap_or(RKind::Never)
        } else {
            RKind::Literal(self.find.clone())
        };
        CompiledReplace {
            enabled: self.enabled,
            target: self.target,
            kind,
            replace: self.replace.clone(),
        }
    }
}

impl CompiledReplace {
    fn replace_in(&self, s: &str) -> String {
        match &self.kind {
            RKind::Literal(f) => s.replace(f.as_str(), &self.replace),
            RKind::Re(re) => re.replace_all(s, self.replace.as_str()).into_owned(),
            RKind::Append | RKind::Never => s.to_string(),
        }
    }

    fn apply_str(&self, s: &mut String) {
        if matches!(self.kind, RKind::Append | RKind::Never) {
            return;
        }
        *s = self.replace_in(s);
    }

    fn apply_body(&self, body: &mut Vec<u8>) {
        if matches!(self.kind, RKind::Append | RKind::Never) {
            return;
        }
        let s = String::from_utf8_lossy(body).into_owned();
        *body = self.replace_in(&s).into_bytes();
    }

    fn apply_headers(&self, headers: &mut Vec<Header>) {
        match &self.kind {
            // 空匹配 → 追加新头(`replace` 形如 `Name: Value`)。
            RKind::Append => {
                if let Some((k, v)) = self.replace.split_once(':') {
                    headers.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
            RKind::Never => {}
            _ => {
                for (k, v) in headers.iter_mut() {
                    let line = format!("{k}: {v}");
                    let newline = self.replace_in(&line);
                    if newline != line {
                        if let Some((nk, nv)) = newline.split_once(':') {
                            *k = nk.trim().to_string();
                            *v = nv.trim().to_string();
                        }
                    }
                }
            }
        }
    }

    /// 按目标对流做替换(`apply` 前请确保 `enabled`)。
    pub fn apply(&self, flow: &mut HttpFlow) {
        match self.target {
            Target::ReqPath => self.apply_str(&mut flow.path),
            Target::ReqBody => self.apply_body(&mut flow.req_body),
            Target::RespBody => self.apply_body(&mut flow.resp_body),
            Target::ReqHeaders => self.apply_headers(&mut flow.req_headers),
            Target::RespHeaders => self.apply_headers(&mut flow.resp_headers),
        }
    }
}

// ───────────────────────── Map Local / Map Remote / Mock ─────────────────────────
//
// 对标 Reqable:
// - **Map Remote**:命中 → 把连接目标重定向到另一 host[:port](在连上游前生效,见 mitm/proxy_plain)。
// - **Map Local**:命中 → 用本地文件内容作为响应**短路返回**(走 `HookAction::Respond`)。
// - **Mock**:命中 → 用内联 status/headers/body **短路返回**。
// 三者共用条件系统([`Condition`]);Local/Mock 在 `on_request` 钩子短路,Remote 经 `remap_target`。

/// Map 规则的动作。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MapAction {
    /// 重定向连接目标:`to_host` 为空 = 不改 host;`to_port == 0` = 不改 port。
    Remote { to_host: String, to_port: u16 },
    /// 用本地文件内容作为响应(200,content-type 按扩展名猜)。
    Local { file: String },
    /// 内联响应。
    Mock {
        status: u16,
        content_type: String,
        body: String,
    },
}

/// 一条 Map 规则(UI 可编辑纯结构)。
#[derive(Clone)]
pub struct MapRule {
    pub enabled: bool,
    pub cond: Condition,
    pub action: MapAction,
}

/// 编译后的 Map 规则。
pub struct CompiledMap {
    pub enabled: bool,
    cond: CompiledCond,
    action: MapAction,
}

impl MapRule {
    pub fn compile(&self) -> CompiledMap {
        CompiledMap {
            enabled: self.enabled,
            cond: self.cond.compile(),
            action: self.action.clone(),
        }
    }
}

/// Map 规则对某条流的求值结果(短路类)。
#[derive(Debug, PartialEq, Eq)]
pub enum MapResult {
    /// 未命中 / 非短路动作。
    NoMatch,
    /// Mock:短路返回内联响应。
    Mock {
        status: u16,
        headers: Vec<Header>,
        body: Vec<u8>,
    },
    /// Map Local:短路返回本地文件(文件读取交调用方,以保持本模块无 IO)。
    LocalFile {
        path: String,
        content_type: String,
    },
}

impl CompiledMap {
    /// 命中且为 Remote → 返回重定向目标 `(host, port)`(空 host / 0 port 用原值兜底)。
    pub fn remote_target(&self, flow: &HttpFlow) -> Option<(String, u16)> {
        if !self.enabled {
            return None;
        }
        if let MapAction::Remote { to_host, to_port } = &self.action {
            if self.cond.matches(flow) {
                let h = if to_host.is_empty() {
                    flow.host.clone()
                } else {
                    to_host.clone()
                };
                let p = if *to_port == 0 { flow.port } else { *to_port };
                return Some((h, p));
            }
        }
        None
    }

    /// 命中且为 Local/Mock → 返回短路响应描述;否则 `NoMatch`。
    pub fn eval_respond(&self, flow: &HttpFlow) -> MapResult {
        if !self.enabled || !self.cond.matches(flow) {
            return MapResult::NoMatch;
        }
        match &self.action {
            MapAction::Mock {
                status,
                content_type,
                body,
            } => MapResult::Mock {
                status: *status,
                headers: vec![("Content-Type".to_string(), content_type.clone())],
                body: body.clone().into_bytes(),
            },
            MapAction::Local { file } => MapResult::LocalFile {
                path: file.clone(),
                content_type: guess_content_type(file).to_string(),
            },
            MapAction::Remote { .. } => MapResult::NoMatch,
        }
    }
}

/// 按文件扩展名猜 content-type(纯函数;未知回退 `application/octet-stream`)。
pub fn guess_content_type(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

// ───────────────────────── 持久化(规则存盘 → 重启后自动加载生效) ─────────────────────────
//
// 用户诉求:「保存拦截规则,开启后下次遇到这个链接自动执行」。把 UI 规则序列化到
// `~/.scry/intercept_rules.json`;启动 `load_rules` 回填 state,抓包时 `sync_rules_to_engine`
// 推给引擎 → 匹配的链接自动拦截(scope)/ 自动改包(Match & Replace)。
// 为不给 `ext::InterceptDir` 增派生,这里用 `resp: bool` 镜像方向。

/// 拦截规则存盘位置:`~/.scry/intercept_rules.json`(取不到 HOME 时退回当前目录)。
fn rules_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home)
        .join(".scry")
        .join("intercept_rules.json")
}

/// 可序列化的范围规则(`dir` 拍平为 `resp` 布尔)。
#[derive(Serialize, Deserialize)]
struct StoredScope {
    enabled: bool,
    /// 方向:`false` = 请求,`true` = 响应。
    resp: bool,
    field: Field,
    op: Op,
    value: String,
    negate: bool,
    intercept: bool,
}

/// 可序列化的 Match & Replace 规则。
#[derive(Serialize, Deserialize)]
struct StoredReplace {
    enabled: bool,
    target: Target,
    is_regex: bool,
    find: String,
    replace: String,
}

/// 可序列化的 Map 规则。
#[derive(Serialize, Deserialize)]
struct StoredMap {
    enabled: bool,
    field: Field,
    op: Op,
    value: String,
    negate: bool,
    action: MapAction,
}

#[derive(Serialize, Deserialize, Default)]
struct StoredRules {
    #[serde(default)]
    scope: Vec<StoredScope>,
    #[serde(default)]
    replace: Vec<StoredReplace>,
    #[serde(default)]
    maps: Vec<StoredMap>,
}

/// 把内存规则编码为 JSON 文本(纯函数,可单测)。
pub fn serialize_rules(scope: &[ScopeRule], replace: &[ReplaceRule], maps: &[MapRule]) -> String {
    let stored = StoredRules {
        scope: scope
            .iter()
            .map(|r| StoredScope {
                enabled: r.enabled,
                resp: matches!(r.dir, InterceptDir::Response),
                field: r.cond.field,
                op: r.cond.op,
                value: r.cond.value.clone(),
                negate: r.cond.negate,
                intercept: r.intercept,
            })
            .collect(),
        replace: replace
            .iter()
            .map(|r| StoredReplace {
                enabled: r.enabled,
                target: r.target,
                is_regex: r.is_regex,
                find: r.find.clone(),
                replace: r.replace.clone(),
            })
            .collect(),
        maps: maps
            .iter()
            .map(|r| StoredMap {
                enabled: r.enabled,
                field: r.cond.field,
                op: r.cond.op,
                value: r.cond.value.clone(),
                negate: r.cond.negate,
                action: r.action.clone(),
            })
            .collect(),
    };
    serde_json::to_string_pretty(&stored).unwrap_or_else(|_| "{}".to_string())
}

/// 从 JSON 文本解码为内存规则(纯函数,可单测;解析失败 → 空)。
pub fn deserialize_rules(json: &str) -> (Vec<ScopeRule>, Vec<ReplaceRule>, Vec<MapRule>) {
    let stored: StoredRules = serde_json::from_str(json).unwrap_or_default();
    let scope = stored
        .scope
        .into_iter()
        .map(|s| ScopeRule {
            enabled: s.enabled,
            dir: if s.resp {
                InterceptDir::Response
            } else {
                InterceptDir::Request
            },
            cond: Condition {
                field: s.field,
                op: s.op,
                value: s.value,
                negate: s.negate,
            },
            intercept: s.intercept,
        })
        .collect();
    let replace = stored
        .replace
        .into_iter()
        .map(|s| ReplaceRule {
            enabled: s.enabled,
            target: s.target,
            is_regex: s.is_regex,
            find: s.find,
            replace: s.replace,
        })
        .collect();
    let maps = stored
        .maps
        .into_iter()
        .map(|s| MapRule {
            enabled: s.enabled,
            cond: Condition {
                field: s.field,
                op: s.op,
                value: s.value,
                negate: s.negate,
            },
            action: s.action,
        })
        .collect();
    (scope, replace, maps)
}

/// 保存规则到 `~/.scry/intercept_rules.json`;best-effort,失败静默(不打断 UI)。
pub fn save_rules(scope: &[ScopeRule], replace: &[ReplaceRule], maps: &[MapRule]) {
    let path = rules_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, serialize_rules(scope, replace, maps));
}

/// 从磁盘加载规则(文件不存在 / 解析失败 → 空)。
pub fn load_rules() -> (Vec<ScopeRule>, Vec<ReplaceRule>, Vec<MapRule>) {
    match std::fs::read_to_string(rules_path()) {
        Ok(s) => deserialize_rules(&s),
        Err(_) => (Vec::new(), Vec::new(), Vec::new()),
    }
}

// ───────────────────────── 活动 WebSocket 改帧规则(持久化)─────────────────────────
//
// WS 改帧规则用内核类型 `scry_proxy::websocket::WsRewriteRule`(直接喂给 `ProxyConfig.ws_rewrite`);
// 这里只负责存盘到 `~/.scry/ws_rules.json`(内核类型不带 serde,用本地 mirror 转换)。

/// WS 规则存盘镜像(`to_server` 拍平方向枚举)。
#[derive(Serialize, Deserialize)]
struct StoredWsRule {
    to_server: bool,
    find: String,
    replace: String,
}

/// WS 改帧规则存盘位置:`~/.scry/ws_rules.json`。
fn ws_rules_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home).join(".scry").join("ws_rules.json")
}

/// 序列化 WS 规则(纯函数,可单测)。
pub fn serialize_ws_rules(rules: &[scry_proxy::websocket::WsRewriteRule]) -> String {
    let stored: Vec<StoredWsRule> = rules
        .iter()
        .map(|r| StoredWsRule {
            to_server: r.dir == scry_proxy::websocket::WsRuleDir::ToServer,
            find: r.find.clone(),
            replace: r.replace.clone(),
        })
        .collect();
    serde_json::to_string_pretty(&stored).unwrap_or_else(|_| "[]".to_string())
}

/// 反序列化 WS 规则(坏 JSON → 空)。
pub fn deserialize_ws_rules(s: &str) -> Vec<scry_proxy::websocket::WsRewriteRule> {
    serde_json::from_str::<Vec<StoredWsRule>>(s)
        .map(|v| {
            v.into_iter()
                .map(|r| scry_proxy::websocket::WsRewriteRule {
                    dir: if r.to_server {
                        scry_proxy::websocket::WsRuleDir::ToServer
                    } else {
                        scry_proxy::websocket::WsRuleDir::ToClient
                    },
                    find: r.find,
                    replace: r.replace,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// 保存 WS 改帧规则;best-effort,失败静默。
pub fn save_ws_rules(rules: &[scry_proxy::websocket::WsRewriteRule]) {
    let path = ws_rules_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, serialize_ws_rules(rules));
}

/// 加载 WS 改帧规则(文件不存在 / 坏 JSON → 空)。
pub fn load_ws_rules() -> Vec<scry_proxy::websocket::WsRewriteRule> {
    match std::fs::read_to_string(ws_rules_path()) {
        Ok(s) => deserialize_ws_rules(&s),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow() -> HttpFlow {
        HttpFlow::request(
            "POST",
            "https",
            "api.example.com",
            443,
            "/v1/login",
            vec![
                ("Host".to_string(), "api.example.com".to_string()),
                ("User-Agent".to_string(), "scry/1.0".to_string()),
            ],
            b"user=admin&pw=123".to_vec(),
        )
        .with_response(
            200,
            vec![("Content-Type".to_string(), "application/json".to_string())],
            b"{\"ok\":true}".to_vec(),
            0,
        )
    }

    fn cond(field: Field, op: Op, value: &str, negate: bool) -> CompiledCond {
        Condition {
            field,
            op,
            value: value.to_string(),
            negate,
        }
        .compile()
    }

    #[test]
    fn condition_contains_equals_wildcard_regex() {
        let f = flow();
        assert!(cond(Field::Host, Op::Equals, "api.example.com", false).matches(&f));
        assert!(!cond(Field::Host, Op::Equals, "other.com", false).matches(&f));
        assert!(cond(Field::Url, Op::Contains, "/v1/login", false).matches(&f));
        assert!(cond(Field::Host, Op::Wildcard, "*.example.com", false).matches(&f));
        assert!(cond(Field::Method, Op::Regex, "^(POST|PUT)$", false).matches(&f));
        assert!(cond(Field::ReqBody, Op::Contains, "admin", false).matches(&f));
        assert!(cond(Field::RespHeaders, Op::Contains, "application/json", false).matches(&f));
    }

    #[test]
    fn condition_negate_and_bad_regex() {
        let f = flow();
        assert!(cond(Field::Host, Op::Equals, "other.com", true).matches(&f)); // 取反命中
        assert!(!cond(Field::Method, Op::Regex, "(", false).matches(&f)); // 非法正则 → 不命中
    }

    #[test]
    fn scope_empty_falls_back_to_default() {
        let f = flow();
        assert!(should_intercept(&f, InterceptDir::Request, &[], true));
        assert!(!should_intercept(&f, InterceptDir::Request, &[], false));
    }

    fn scope(dir: InterceptDir, field: Field, op: Op, value: &str, intercept: bool) -> CompiledScope {
        ScopeRule {
            enabled: true,
            dir,
            cond: Condition {
                field,
                op,
                value: value.to_string(),
                negate: false,
            },
            intercept,
        }
        .compile()
    }

    #[test]
    fn scope_include_only_matches_intercept() {
        let f = flow();
        let rules = vec![scope(InterceptDir::Request, Field::Host, Op::Equals, "api.example.com", true)];
        assert!(should_intercept(&f, InterceptDir::Request, &rules, true));
        let rules2 = vec![scope(InterceptDir::Request, Field::Host, Op::Equals, "nope.com", true)];
        assert!(!should_intercept(&f, InterceptDir::Request, &rules2, true));
        // 方向不符的规则被忽略 → 回退默认。
        assert!(should_intercept(&f, InterceptDir::Response, &rules, true));
    }

    #[test]
    fn scope_exclude_wins() {
        let f = flow();
        let rules = vec![
            scope(InterceptDir::Request, Field::Host, Op::Equals, "api.example.com", true),
            scope(InterceptDir::Request, Field::Path, Op::Contains, "/login", false),
        ];
        assert!(!should_intercept(&f, InterceptDir::Request, &rules, true)); // 跳过优先
        // 只有跳过规则、未命中 → 拦。
        let only_skip = vec![scope(InterceptDir::Request, Field::Path, Op::Contains, "/static", false)];
        assert!(should_intercept(&f, InterceptDir::Request, &only_skip, true));
    }

    #[test]
    fn replace_header_modify_and_append() {
        let mut f = flow();
        ReplaceRule {
            enabled: true,
            target: Target::ReqHeaders,
            is_regex: false,
            find: "scry/1.0".to_string(),
            replace: "Mozilla/5.0".to_string(),
        }
        .compile()
        .apply(&mut f);
        assert!(f.req_headers.iter().any(|(k, v)| k == "User-Agent" && v == "Mozilla/5.0"));

        ReplaceRule {
            enabled: true,
            target: Target::ReqHeaders,
            is_regex: false,
            find: String::new(),
            replace: "X-Test: 1".to_string(),
        }
        .compile()
        .apply(&mut f);
        assert!(f.req_headers.iter().any(|(k, v)| k == "X-Test" && v == "1"));
    }

    #[test]
    fn replace_body_literal_regex_and_path() {
        let mut f = flow();
        ReplaceRule {
            enabled: true,
            target: Target::ReqBody,
            is_regex: false,
            find: "admin".to_string(),
            replace: "guest".to_string(),
        }
        .compile()
        .apply(&mut f);
        assert_eq!(f.req_body, b"user=guest&pw=123");

        ReplaceRule {
            enabled: true,
            target: Target::RespBody,
            is_regex: true,
            find: "\"ok\":\\s*true".to_string(),
            replace: "\"ok\":false".to_string(),
        }
        .compile()
        .apply(&mut f);
        assert_eq!(f.resp_body, b"{\"ok\":false}");

        ReplaceRule {
            enabled: true,
            target: Target::ReqPath,
            is_regex: false,
            find: "/v1/".to_string(),
            replace: "/v2/".to_string(),
        }
        .compile()
        .apply(&mut f);
        assert_eq!(f.path, "/v2/login");
    }

    #[test]
    fn rules_serialize_roundtrip() {
        let scope = vec![ScopeRule {
            enabled: true,
            dir: InterceptDir::Response,
            cond: Condition {
                field: Field::Url,
                op: Op::Contains,
                value: "/api".to_string(),
                negate: true,
            },
            intercept: true,
        }];
        let replace = vec![ReplaceRule {
            enabled: false,
            target: Target::RespBody,
            is_regex: true,
            find: "a".to_string(),
            replace: "b".to_string(),
        }];
        let maps = vec![MapRule {
            enabled: true,
            cond: Condition {
                field: Field::Host,
                op: Op::Equals,
                value: "api.example.com".to_string(),
                negate: false,
            },
            action: MapAction::Remote {
                to_host: "127.0.0.1".to_string(),
                to_port: 8080,
            },
        }];
        let json = serialize_rules(&scope, &replace, &maps);
        let (s2, r2, m2) = deserialize_rules(&json);
        assert_eq!(s2.len(), 1);
        assert!(matches!(s2[0].dir, InterceptDir::Response));
        assert_eq!(s2[0].cond.field, Field::Url);
        assert_eq!(s2[0].cond.op, Op::Contains);
        assert!(s2[0].cond.negate && s2[0].intercept);
        assert_eq!(s2[0].cond.value, "/api");
        assert_eq!(r2.len(), 1);
        assert!(r2[0].is_regex && !r2[0].enabled);
        assert_eq!(r2[0].target, Target::RespBody);
        assert_eq!(r2[0].replace, "b");
        assert_eq!(m2.len(), 1);
        assert!(matches!(
            &m2[0].action,
            MapAction::Remote { to_host, to_port } if to_host == "127.0.0.1" && *to_port == 8080
        ));
    }

    #[test]
    fn deserialize_garbage_is_empty() {
        let (s, r, m) = deserialize_rules("not valid json");
        assert!(s.is_empty() && r.is_empty() && m.is_empty());
    }

    fn map(action: MapAction, field: Field, op: Op, value: &str) -> CompiledMap {
        MapRule {
            enabled: true,
            cond: Condition {
                field,
                op,
                value: value.to_string(),
                negate: false,
            },
            action,
        }
        .compile()
    }

    #[test]
    fn map_remote_redirects_matching_host() {
        let f = flow();
        let m = map(
            MapAction::Remote {
                to_host: "10.0.0.1".to_string(),
                to_port: 9000,
            },
            Field::Host,
            Op::Equals,
            "api.example.com",
        );
        assert_eq!(m.remote_target(&f), Some(("10.0.0.1".to_string(), 9000)));
        // 不命中 host → 不重定向。
        let m2 = map(
            MapAction::Remote {
                to_host: "10.0.0.1".to_string(),
                to_port: 9000,
            },
            Field::Host,
            Op::Equals,
            "other.com",
        );
        assert_eq!(m2.remote_target(&f), None);
        // 空 host / 0 port → 用原值兜底。
        let m3 = map(
            MapAction::Remote {
                to_host: String::new(),
                to_port: 0,
            },
            Field::Host,
            Op::Equals,
            "api.example.com",
        );
        assert_eq!(m3.remote_target(&f), Some(("api.example.com".to_string(), 443)));
    }

    #[test]
    fn map_mock_short_circuits() {
        let f = flow();
        let m = map(
            MapAction::Mock {
                status: 503,
                content_type: "application/json".to_string(),
                body: "{\"mock\":true}".to_string(),
            },
            Field::Path,
            Op::Contains,
            "/v1/login",
        );
        match m.eval_respond(&f) {
            MapResult::Mock {
                status,
                headers,
                body,
            } => {
                assert_eq!(status, 503);
                assert_eq!(body, b"{\"mock\":true}");
                assert!(headers.iter().any(|(k, v)| k == "Content-Type" && v == "application/json"));
            }
            other => panic!("expected Mock, got {other:?}"),
        }
        // Remote 动作在 eval_respond 中视为 NoMatch(它走 remote_target)。
        let r = map(
            MapAction::Remote {
                to_host: "x".to_string(),
                to_port: 1,
            },
            Field::Path,
            Op::Contains,
            "/v1/login",
        );
        assert_eq!(r.eval_respond(&f), MapResult::NoMatch);
    }

    #[test]
    fn map_local_resolves_file_and_content_type() {
        let f = flow();
        let m = map(
            MapAction::Local {
                file: "/tmp/x.json".to_string(),
            },
            Field::Url,
            Op::Contains,
            "/v1/login",
        );
        match m.eval_respond(&f) {
            MapResult::LocalFile { path, content_type } => {
                assert_eq!(path, "/tmp/x.json");
                assert_eq!(content_type, "application/json; charset=utf-8");
            }
            other => panic!("expected LocalFile, got {other:?}"),
        }
    }

    #[test]
    fn content_type_guess() {
        assert_eq!(guess_content_type("a.png"), "image/png");
        assert_eq!(guess_content_type("a.HTML"), "text/html; charset=utf-8");
        assert_eq!(guess_content_type("noext"), "application/octet-stream");
    }

    #[test]
    fn ws_rules_serde_roundtrip() {
        use scry_proxy::websocket::{WsRewriteRule, WsRuleDir};
        let rules = vec![
            WsRewriteRule {
                dir: WsRuleDir::ToServer,
                find: "ping".into(),
                replace: "PWN".into(),
            },
            WsRewriteRule {
                dir: WsRuleDir::ToClient,
                find: "balance".into(),
                replace: "999".into(),
            },
        ];
        let json = serialize_ws_rules(&rules);
        let back = deserialize_ws_rules(&json);
        assert_eq!(back, rules);
        // 坏 JSON → 空。
        assert!(deserialize_ws_rules("not json").is_empty());
    }
}
