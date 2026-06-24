//! MCP 工具集:把 scry 引擎包装成「参数 JSON → 结果文本」的工具,供 `tools/call` 分发。
//!
//! 全部复用既有内核:历史库 [`scry_storage::Store`]、重放 [`scry_proxy::replay`]、
//! 扫描 [`scry_scan`](被动 / 主动 / 敏感文件 / 越权)、编解码 [`scry_codec`]。
//! 发包类工具用调用方传入的 tokio 运行时 `block_on` 驱动 async。

use serde_json::{json, Value};
use tokio::runtime::Runtime;

use scry_core::{Header, HttpFlow};
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};
use scry_proxy::upstream::UpstreamProxy;
use scry_scan::authz::{self, Identity};
use scry_scan::{discovery, Finding};
use scry_codec::{smart_decode, Transform};
use scry_storage::Store;

/// 历史库读取上限(`list_flows` / `get_flow` 共用,保证 `index` 在两次调用间对齐)。
const RECENT_FETCH: usize = 1000;
/// `list_flows` 默认返回条数。
const FLOW_LIMIT_DEFAULT: usize = 50;
/// 响应正文展示截断(字符)。
const BODY_CAP: usize = 4000;
/// 单次主动扫描最多发出的探测数(防狂轰)。
const ACTIVE_PROBE_CAP: usize = 80;
/// 发包工具用的中性 UA。
const USER_AGENT: &str = "Mozilla/5.0 (compatible; ScryMCP/1.0)";

/// `tools/list` 的工具清单(name + description + JSON Schema)。
pub fn schemas() -> Value {
    json!([
        {
            "name": "list_flows",
            "description": "列出 scry 抓到的最近 HTTP(S) 流量(代理历史)。返回每条的 index/method/url/status/大小,index 用于 get_flow。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "description": "返回条数上限(默认 50)" },
                    "filter": { "type": "string", "description": "按 method+url 子串过滤(大小写不敏感)" }
                }
            }
        },
        {
            "name": "get_flow",
            "description": "查看某条流量的完整请求 + 响应(头 + 解码后的正文)。用 list_flows 给的 index,或精确 url。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "index": { "type": "integer", "description": "list_flows 返回的 index" },
                    "url": { "type": "string", "description": "精确匹配的 URL(优先于 index)" }
                }
            }
        },
        {
            "name": "send_request",
            "description": "主动发送 / 重放一个 HTTP(S) 请求(= Repeater),返回响应。⚠️ 真实发包,仅对已授权目标使用。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "完整 URL,如 https://api.example.com/x?a=1" },
                    "method": { "type": "string", "description": "HTTP 方法(默认 GET)" },
                    "headers": { "type": "object", "description": "请求头键值对,如 {\"Authorization\":\"Bearer ..\"}" },
                    "body": { "type": "string", "description": "请求体(原文)" }
                },
                "required": ["url"]
            }
        },
        {
            "name": "passive_scan",
            "description": "对已抓到的历史流量跑被动安全规则(缺失安全头 / Cookie 标志 / CORS / 信息泄露等),返回 findings。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host": { "type": "string", "description": "只扫该 host(默认全部历史)" },
                    "limit": { "type": "integer", "description": "最多取多少条历史流参与(默认 1000)" }
                }
            }
        },
        {
            "name": "active_scan",
            "description": "主动探测注入点(报错型 SQLi / 反射 XSS / 路径穿越)。给 url(需带 ?参数)直接打,或对历史流量按 host 批量打。⚠️ 真实攻击载荷,仅对已授权目标使用。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "带查询参数的目标 URL" },
                    "host": { "type": "string", "description": "改为对历史里该 host 的带参请求批量探测" },
                    "limit": { "type": "integer", "description": "历史模式下最多取多少条带参流(默认 50)" }
                }
            }
        },
        {
            "name": "discovery_scan",
            "description": "Nikto 式敏感文件 / 路径探测(.git/.env/备份/Actuator/swagger 等高危路径库 + soft-404 基线压误报)。⚠️ 仅对已授权目标使用。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "目标 origin,如 https://example.com" }
                },
                "required": ["url"]
            }
        },
        {
            "name": "authz_test",
            "description": "越权 / 访问控制测试(对标 Burp Autorize):用 高权限 / 低权限 / 匿名 多身份重放同一 URL 比对。⚠️ 仅对已授权目标使用。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "受保护资源 URL" },
                    "high_headers": { "type": "string", "description": "高权限身份头,如 'Authorization: Bearer ADMIN'(可分号/换行多条);留空则匿名直接打该 URL 当基准" },
                    "low_headers": { "type": "string", "description": "低权限身份头(可选);匿名身份总会测" }
                },
                "required": ["url"]
            }
        },
        {
            "name": "decode",
            "description": "编解码 / 加解密 / 哈希。给 transform 指定变换,或省略走智能解码。变换名:url_encode/url_decode, base64_encode/base64_decode, base32_*, base58_*, hex_*, binary_*, html_*, unicode_escape/unicode_unescape, rot13, jwt_decode, xor_encrypt/xor_decrypt, rc4_encrypt/rc4_decrypt, aes_cbc_encrypt/aes_cbc_decrypt, aes_ecb_encrypt/aes_ecb_decrypt, md5/sha1/sha256/sha512/hmac_sha256。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "input": { "type": "string", "description": "待处理文本" },
                    "transform": { "type": "string", "description": "变换名(省略 = 智能解码一层)" },
                    "key": { "type": "string", "description": "密钥(仅 xor/rc4/aes/hmac;UTF-8 字节)" },
                    "iv": { "type": "string", "description": "IV(仅 aes_cbc;16 字节)" }
                },
                "required": ["input"]
            }
        }
    ])
}

/// 分发 `tools/call`。发包类工具用 `rt.block_on` 驱动。
pub fn call(
    rt: &Runtime,
    store: &Store,
    up: &Option<UpstreamProxy>,
    name: &str,
    args: &Value,
) -> Result<String, String> {
    match name {
        "list_flows" => list_flows(store, args),
        "get_flow" => get_flow(store, args),
        "send_request" => rt.block_on(send_request(up, args)),
        "passive_scan" => passive_scan(store, args),
        "active_scan" => rt.block_on(active_scan(store, up, args)),
        "discovery_scan" => rt.block_on(discovery_scan(up, args)),
        "authz_test" => rt.block_on(authz_test(up, args)),
        "decode" => decode(args),
        other => Err(format!("未知工具:{other}")),
    }
}

// ───────────────────────── 读历史 ─────────────────────────

fn list_flows(store: &Store, args: &Value) -> Result<String, String> {
    let limit = uint_arg(args, "limit").unwrap_or(FLOW_LIMIT_DEFAULT).clamp(1, RECENT_FETCH);
    let filter = str_arg(args, "filter").map(|s| s.to_lowercase());
    let flows = store.recent(RECENT_FETCH).map_err(|e| format!("读历史库失败:{e:#}"))?;
    let mut items = Vec::new();
    for (i, f) in flows.iter().enumerate() {
        if let Some(flt) = &filter {
            let hay = format!("{} {}", f.method, f.url()).to_lowercase();
            if !hay.contains(flt) {
                continue;
            }
        }
        items.push(json!({
            "index": i,
            "method": f.method,
            "url": f.url(),
            "status": f.status,
            "resp_len": f.resp_body.len(),
            "ms": f.duration_ms,
        }));
        if items.len() >= limit {
            break;
        }
    }
    Ok(pretty(json!({
        "fetched": flows.len(),
        "shown": items.len(),
        "flows": items,
    })))
}

fn get_flow(store: &Store, args: &Value) -> Result<String, String> {
    let flows = store.recent(RECENT_FETCH).map_err(|e| format!("读历史库失败:{e:#}"))?;
    let flow = if let Some(u) = str_arg(args, "url") {
        flows
            .iter()
            .find(|f| f.url() == u)
            .cloned()
            .ok_or_else(|| format!("未找到 url={u} 的流(可先 list_flows)"))?
    } else if let Some(i) = uint_arg(args, "index") {
        flows
            .get(i)
            .cloned()
            .ok_or_else(|| format!("index {i} 越界(共 {} 条)", flows.len()))?
    } else {
        return Err("需提供 index 或 url".to_string());
    };
    Ok(pretty(flow_to_value(&flow, true)))
}

// ───────────────────────── 发包 ─────────────────────────

async fn send_request(up: &Option<UpstreamProxy>, args: &Value) -> Result<String, String> {
    let url = str_arg(args, "url").ok_or("缺少参数 url")?;
    let method = str_arg(args, "method").unwrap_or_else(|| "GET".to_string());
    let headers = parse_headers_arg(args.get("headers"));
    let body = str_arg(args, "body").unwrap_or_default().into_bytes();
    let mut req = ReplayRequest::from_url(&method, &url, headers, body)
        .ok_or_else(|| format!("非法 URL:{url}"))?;
    ensure_host(&mut req);
    let flow = do_send(&req, up).await?;
    Ok(pretty(flow_to_value(&flow, false)))
}

// ───────────────────────── 扫描 ─────────────────────────

fn passive_scan(store: &Store, args: &Value) -> Result<String, String> {
    let limit = uint_arg(args, "limit").unwrap_or(RECENT_FETCH).clamp(1, RECENT_FETCH);
    let host = str_arg(args, "host");
    let all = store.recent(limit).map_err(|e| format!("读历史库失败:{e:#}"))?;
    let scoped: Vec<HttpFlow> = match &host {
        Some(h) => all.into_iter().filter(|f| &f.host == h).collect(),
        None => all,
    };
    let findings = scry_scan::scan_flows(&scoped);
    Ok(pretty(json!({
        "scanned_flows": scoped.len(),
        "count": findings.len(),
        "findings": findings_json(&findings),
    })))
}

async fn active_scan(
    store: &Store,
    up: &Option<UpstreamProxy>,
    args: &Value,
) -> Result<String, String> {
    let mut bases: Vec<HttpFlow> = Vec::new();
    if let Some(url) = str_arg(args, "url") {
        let mut req = ReplayRequest::from_url("GET", &url, vec![], vec![])
            .ok_or_else(|| format!("非法 URL:{url}"))?;
        ensure_host(&mut req);
        bases.push(flow_from_replay(&req));
    } else {
        let limit = uint_arg(args, "limit").unwrap_or(FLOW_LIMIT_DEFAULT).clamp(1, RECENT_FETCH);
        let host = str_arg(args, "host");
        let flows = store.recent(RECENT_FETCH).map_err(|e| format!("读历史库失败:{e:#}"))?;
        for f in flows {
            if let Some(h) = &host {
                if &f.host != h {
                    continue;
                }
            }
            if f.path.contains('?') {
                bases.push(f);
            }
            if bases.len() >= limit {
                break;
            }
        }
    }
    if bases.is_empty() {
        return Err("没有可注入的基准:给一个带 ?参数 的 url,或先抓些带查询参数的请求再按 host 扫".to_string());
    }

    let mut probes = Vec::new();
    for b in &bases {
        for p in scry_scan::generate_probes(b) {
            probes.push(p);
            if probes.len() >= ACTIVE_PROBE_CAP {
                break;
            }
        }
        if probes.len() >= ACTIVE_PROBE_CAP {
            break;
        }
    }

    let mut findings = Vec::new();
    for p in &probes {
        let req = ReplayRequest::from_flow(&p.flow);
        if let Ok(resp) = do_send(&req, up).await {
            if let Some(f) = scry_scan::evaluate(p, &resp) {
                findings.push(f);
            }
        }
    }
    Ok(pretty(json!({
        "probes_sent": probes.len(),
        "count": findings.len(),
        "findings": findings_json(&findings),
    })))
}

async fn discovery_scan(up: &Option<UpstreamProxy>, args: &Value) -> Result<String, String> {
    let url = str_arg(args, "url").ok_or("缺少参数 url")?;
    let req = ReplayRequest::from_url("GET", &url, vec![], vec![])
        .ok_or_else(|| format!("非法 URL:{url}"))?;
    let origin = discovery::Origin {
        scheme: req.scheme.clone(),
        host: req.host.clone(),
        port: req.port,
    };

    // soft-404 基线(失败则不做基线压制)。
    let baseline = {
        let bflow = discovery::probe_flow(&origin, discovery::baseline_path());
        match do_send(&ReplayRequest::from_flow(&bflow), up).await {
            Ok(resp) => Some(discovery::build_baseline(&resp)),
            Err(_) => None,
        }
    };

    let mut findings = Vec::new();
    for entry in discovery::PATHS {
        let pflow = discovery::probe_flow(&origin, entry.path);
        if let Ok(resp) = do_send(&ReplayRequest::from_flow(&pflow), up).await {
            if let Some(f) = discovery::evaluate_path(entry, &resp, baseline.as_ref()) {
                findings.push(f);
            }
        }
    }
    Ok(pretty(json!({
        "origin": origin.base_url(),
        "paths_probed": discovery::PATHS.len(),
        "count": findings.len(),
        "findings": findings_json(&findings),
    })))
}

async fn authz_test(up: &Option<UpstreamProxy>, args: &Value) -> Result<String, String> {
    let url = str_arg(args, "url").ok_or("缺少参数 url")?;
    let high_spec = str_arg(args, "high_headers");
    let low_spec = str_arg(args, "low_headers");

    let mut req = ReplayRequest::from_url("GET", &url, vec![], vec![])
        .ok_or_else(|| format!("非法 URL:{url}"))?;
    ensure_host(&mut req);
    let base_flow = flow_from_replay(&req);

    // 高权限基准:套用高权限身份(留空则直接打该 URL 当基准)。
    let priv_req = match &high_spec {
        Some(h) => ReplayRequest::from_flow(&authz::apply_identity(&base_flow, &Identity::parse("high", h))),
        None => req.clone(),
    };
    let privileged = do_send(&priv_req, up).await?;

    let mut verdicts = vec![format!(
        "high → HTTP {} ({} B)",
        privileged.status,
        privileged.resp_body.len()
    )];
    if !(200..300).contains(&privileged.status) {
        return Ok(pretty(json!({
            "verdicts": verdicts,
            "note": format!("基准非 2xx(HTTP {}),无法比对越权——请用能成功取数的高权限请求", privileged.status),
            "count": 0,
            "findings": [],
        })));
    }

    let mut tests: Vec<Identity> = Vec::new();
    if let Some(l) = &low_spec {
        tests.push(Identity::parse("low", l));
    }
    tests.push(Identity::anonymous());

    let mut findings = Vec::new();
    for id in &tests {
        let r = ReplayRequest::from_flow(&authz::apply_identity(&base_flow, id));
        match do_send(&r, up).await {
            Ok(resp) => {
                let verdict = authz::compare(&privileged, &resp);
                verdicts.push(format!(
                    "{} → HTTP {} ({} B) · {:?}",
                    id.name,
                    resp.status,
                    resp.resp_body.len(),
                    verdict
                ));
                if let Some(f) = authz::evaluate(&url, id, &privileged, &resp) {
                    findings.push(f);
                }
            }
            Err(e) => verdicts.push(format!("{} → 发送失败:{e}", id.name)),
        }
    }
    Ok(pretty(json!({
        "verdicts": verdicts,
        "count": findings.len(),
        "findings": findings_json(&findings),
    })))
}

// ───────────────────────── 编解码 ─────────────────────────

fn decode(args: &Value) -> Result<String, String> {
    let input = str_arg(args, "input").ok_or("缺少参数 input")?;
    let key = str_arg(args, "key").unwrap_or_default();
    let iv = str_arg(args, "iv").unwrap_or_default();
    match str_arg(args, "transform") {
        Some(name) => {
            let tf = parse_transform(&name)
                .ok_or_else(|| format!("未知变换:{name}(可用变换见工具描述)"))?;
            let out = tf.apply_with(&input, &key, &iv)?;
            Ok(pretty(json!({ "transform": name, "output": out })))
        }
        None => match smart_decode(&input) {
            Some((tf, out)) => Ok(pretty(json!({
                "transform": format!("{tf:?}"),
                "output": out,
            }))),
            None => Ok(pretty(json!({
                "transform": Value::Null,
                "output": Value::Null,
                "note": "未能识别出一层编码",
            }))),
        },
    }
}

/// 变换名(snake_case)→ [`Transform`]。
fn parse_transform(name: &str) -> Option<Transform> {
    Some(match name.to_ascii_lowercase().as_str() {
        "url_encode" => Transform::UrlEncode,
        "url_decode" | "url" => Transform::UrlDecode,
        "html_encode" => Transform::HtmlEncode,
        "html_decode" => Transform::HtmlDecode,
        "base64_encode" => Transform::Base64Encode,
        "base64_decode" | "base64" => Transform::Base64Decode,
        "base32_encode" => Transform::Base32Encode,
        "base32_decode" => Transform::Base32Decode,
        "base58_encode" => Transform::Base58Encode,
        "base58_decode" => Transform::Base58Decode,
        "hex_encode" => Transform::HexEncode,
        "hex_decode" | "hex" => Transform::HexDecode,
        "binary_encode" => Transform::BinaryEncode,
        "binary_decode" => Transform::BinaryDecode,
        "unicode_escape" => Transform::UnicodeEscape,
        "unicode_unescape" => Transform::UnicodeUnescape,
        "rot13" => Transform::Rot13,
        "jwt_decode" | "jwt" => Transform::JwtDecode,
        "xor_encrypt" => Transform::XorEncrypt,
        "xor_decrypt" => Transform::XorDecrypt,
        "rc4_encrypt" => Transform::Rc4Encrypt,
        "rc4_decrypt" => Transform::Rc4Decrypt,
        "aes_cbc_encrypt" => Transform::AesCbcEncrypt,
        "aes_cbc_decrypt" => Transform::AesCbcDecrypt,
        "aes_ecb_encrypt" => Transform::AesEcbEncrypt,
        "aes_ecb_decrypt" => Transform::AesEcbDecrypt,
        "md5" => Transform::Md5,
        "sha1" => Transform::Sha1,
        "sha256" => Transform::Sha256,
        "sha512" => Transform::Sha512,
        "hmac_sha256" => Transform::HmacSha256,
        _ => return None,
    })
}

// ───────────────────────── 公共辅助 ─────────────────────────

/// 发送一个重放请求(走配置的上游出网)。
async fn do_send(req: &ReplayRequest, up: &Option<UpstreamProxy>) -> Result<HttpFlow, String> {
    let cfg = ReplayConfig {
        upstream: up.clone(),
        ..Default::default()
    };
    replay::send(req, &cfg).await.map_err(|e| format!("{e:#}"))
}

/// 由重放请求拼一条「仅请求」的流(供探测生成 / 身份套用)。
fn flow_from_replay(r: &ReplayRequest) -> HttpFlow {
    HttpFlow::request(
        &r.method,
        &r.scheme,
        r.host.clone(),
        r.port,
        r.path.clone(),
        r.headers.clone(),
        r.body.clone(),
    )
}

/// 补齐发包必备头(Host / User-Agent / Accept)——`from_url` 不会自动加。
fn ensure_host(req: &mut ReplayRequest) {
    if !req.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        let h = host_header(&req.host, req.port, &req.scheme);
        req.headers.push(("Host".to_string(), h));
    }
    if !req.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("user-agent")) {
        req.headers.push(("User-Agent".to_string(), USER_AGENT.to_string()));
    }
    if !req.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("accept")) {
        req.headers.push(("Accept".to_string(), "*/*".to_string()));
    }
}

/// `Host` 头取值(非默认端口带端口)。
fn host_header(host: &str, port: u16, scheme: &str) -> String {
    if matches!((scheme, port), ("http", 80) | ("https", 443)) {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// 把一条流转成展示用 JSON(`include_req` 时含请求头 / 体)。
fn flow_to_value(flow: &HttpFlow, include_req: bool) -> Value {
    let mut o = serde_json::Map::new();
    o.insert("method".to_string(), json!(flow.method));
    o.insert("url".to_string(), json!(flow.url()));
    o.insert("status".to_string(), json!(flow.status));
    o.insert("ms".to_string(), json!(flow.duration_ms));
    if include_req {
        o.insert("req_headers".to_string(), headers_json(&flow.req_headers));
        if !flow.req_body.is_empty() {
            o.insert(
                "req_body".to_string(),
                json!(body_text(&flow.req_headers, &flow.req_body)),
            );
        }
    }
    o.insert("resp_headers".to_string(), headers_json(&flow.resp_headers));
    o.insert("resp_body_len".to_string(), json!(flow.resp_body.len()));
    o.insert(
        "resp_body".to_string(),
        json!(body_text(&flow.resp_headers, &flow.resp_body)),
    );
    Value::Object(o)
}

/// 头部 → JSON 数组(保留重复头与顺序):`[[name, value], ...]`。
fn headers_json(h: &[Header]) -> Value {
    Value::Array(h.iter().map(|(k, v)| json!([k, v])).collect())
}

/// findings → JSON 数组。
fn findings_json(findings: &[Finding]) -> Value {
    Value::Array(
        findings
            .iter()
            .map(|f| {
                json!({
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": format!("{:?}", f.severity),
                    "url": f.url,
                    "detail": f.detail,
                })
            })
            .collect(),
    )
}

/// 解码正文(按 Content-Encoding / charset)并截断展示。
fn body_text(headers: &[Header], body: &[u8]) -> String {
    if body.is_empty() {
        return String::new();
    }
    let text = scry_decode::display_text(headers, body);
    if text.chars().count() <= BODY_CAP {
        text
    } else {
        let head: String = text.chars().take(BODY_CAP).collect();
        format!("{head}…(truncated · {} bytes total)", body.len())
    }
}

fn str_arg(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

fn uint_arg(args: &Value, key: &str) -> Option<usize> {
    args.get(key).and_then(|v| v.as_u64()).map(|n| n as usize)
}

/// 解析 `headers` 参数:对象 `{k:v}` 或数组 `[[k,v],...]` → `Vec<Header>`。
fn parse_headers_arg(v: Option<&Value>) -> Vec<Header> {
    let Some(v) = v else {
        return Vec::new();
    };
    if let Some(obj) = v.as_object() {
        return obj
            .iter()
            .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();
    }
    if let Some(arr) = v.as_array() {
        return arr
            .iter()
            .filter_map(|pair| {
                let a = pair.as_array()?;
                let k = a.first()?.as_str()?;
                let val = a.get(1)?.as_str()?;
                Some((k.to_string(), val.to_string()))
            })
            .collect();
    }
    Vec::new()
}

fn pretty(v: Value) -> String {
    serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string())
}
