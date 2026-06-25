//! MCP 工具集:把 scry 引擎包装成「参数 JSON → 结果文本」的工具,供 `tools/call` 分发。
//!
//! 全部复用既有内核:历史库 [`scry_storage::Store`]、重放 [`scry_proxy::replay`]、
//! 扫描 [`scry_scan`](被动 / 主动 / 敏感文件 / 越权)、编解码 [`scry_codec`]。
//! 发包类工具用调用方传入的 tokio 运行时 `block_on` 驱动 async。

use serde_json::{json, Value};
use tokio::runtime::Runtime;

use scry_core::{Header, HttpFlow};
use scry_diff::Granularity;
use scry_httpql::{parse as httpql_parse, FlowFields};
use scry_nuclei::{RespData, Target};
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};
use scry_proxy::upstream::UpstreamProxy;
use scry_scan::authz::{self, Identity};
use scry_scan::{discovery, param_miner, Finding};
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
        },
        {
            "name": "query_flows",
            "description": "用 HTTPQL 查询语言筛抓到的历史流量(对标 Caido)。例:req.method.eq:\"GET\" AND resp.status.gte:400 AND req.host.cont:api。字段 method/host/path/url/ext/port/status/req.len/resp.len/mime/req.headers/resp.headers/req.body/resp.body;操作符 eq/ne/cont/ncont/regex/gt/lt/gte/lte;布尔 AND/OR/NOT + 括号;裸串=全文。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "HTTPQL 查询串" },
                    "limit": { "type": "integer", "description": "返回条数上限(默认 50)" }
                },
                "required": ["query"]
            }
        },
        {
            "name": "jwt",
            "description": "JWT 攻击套件(对标 jwt_tool):decode 解析 / none(alg:none 绕过)/ sign(HS256 密钥签)/ kid(kid 头注入)/ verify(校验)/ crack(弱密钥字典爆破)。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "description": "decode | none | sign | kid | verify | crack(默认 decode)" },
                    "token": { "type": "string", "description": "JWT(decode/verify/crack 用)" },
                    "payload": { "type": "string", "description": "payload JSON(none/sign/kid 用)" },
                    "secret": { "type": "string", "description": "HMAC 密钥(sign/kid/verify 用)" },
                    "kid": { "type": "string", "description": "kid 值(kid 注入用)" },
                    "alg": { "type": "string", "description": "none 变体大小写(none/None/NONE,默认 none)" },
                    "wordlist": { "type": "array", "items": { "type": "string" }, "description": "crack 候选密钥(省略用内置弱密钥表)" }
                }
            }
        },
        {
            "name": "sequencer",
            "description": "令牌随机性 / 熵分析(对标 Burp Sequencer):字符级+比特级香农熵、质量评级、重复检测、FIPS 140-2 四项自检。输入多行令牌样本。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tokens": { "type": "string", "description": "令牌样本,每行一个" }
                },
                "required": ["tokens"]
            }
        },
        {
            "name": "compare",
            "description": "比较两段文本(对标 Burp Comparer):LCS diff,返回相似度 / 增删统计 / 差异片段。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "a": { "type": "string", "description": "文本 A" },
                    "b": { "type": "string", "description": "文本 B" },
                    "granularity": { "type": "string", "description": "line | word | char(默认 line)" }
                },
                "required": ["a", "b"]
            }
        },
        {
            "name": "graphql",
            "description": "GraphQL 工作台:introspect(发 introspection 拉 schema,需 url)/ prettify / minify(需 query)。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "description": "introspect | prettify | minify(默认:有 url 则 introspect,否则 prettify)" },
                    "url": { "type": "string", "description": "GraphQL 端点(introspect 用)" },
                    "query": { "type": "string", "description": "查询串(prettify/minify 用)" },
                    "headers": { "type": "object", "description": "introspect 附加请求头(如鉴权)" }
                }
            }
        },
        {
            "name": "param_miner",
            "description": "隐藏参数挖掘(对标 Burp Param Miner):用内置字典给 URL 拼金丝雀参数,看响应反射出哪些被后端处理的隐藏参数。⚠️ 真实发包,仅对已授权目标。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "目标 URL" }
                },
                "required": ["url"]
            }
        },
        {
            "name": "nuclei_scan",
            "description": "nuclei 模板扫描(HTTP 子集):对目标跑内置模板(可加本地 nuclei-templates 目录白嫖社区模板),matchers 判命中 + extractors 抽证据。⚠️ 真实发包,仅对已授权目标。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "目标 origin,如 https://example.com" },
                    "dir": { "type": "string", "description": "本地 nuclei-templates 目录(可选;递归加载 .yaml/.yml)" }
                },
                "required": ["url"]
            }
        },
        {
            "name": "sqli_scan",
            "description": "SQL 注入专项检测(sqlmap 式,比 active_scan 强):对带参 URL 的注入点跑 报错型 + 布尔盲注(可选时间盲注),命中即指纹 DBMS。⚠️ 真实攻击载荷,仅对已授权目标。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "带查询参数的目标 URL,如 https://x/item?id=1" },
                    "time": { "type": "boolean", "description": "是否启用时间盲注(每发会真睡 secs 秒,默认 false)" },
                    "secs": { "type": "integer", "description": "时间盲注睡眠秒数(默认 5,2–15)" }
                },
                "required": ["url"]
            }
        },
        {
            "name": "xss_scan",
            "description": "反射型 XSS 专项检测(dalfox 式上下文感知):反射定位 → 上下文识别 → 可利用字符探测 → 针对性合成载荷 → 验证未编码回显;附 DOM sink 静态提示。⚠️ 真实脚本载荷,仅对已授权目标。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "带查询参数的目标 URL,如 https://x/search?q=test" }
                },
                "required": ["url"]
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
        "query_flows" => query_flows(store, args),
        "jwt" => jwt_tool(args),
        "sequencer" => sequencer_tool(args),
        "compare" => compare_tool(args),
        "graphql" => rt.block_on(graphql_tool(up, args)),
        "param_miner" => rt.block_on(param_miner_tool(up, args)),
        "nuclei_scan" => rt.block_on(nuclei_scan_tool(up, args)),
        "sqli_scan" => rt.block_on(sqli_scan_tool(up, args)),
        "xss_scan" => rt.block_on(xss_scan_tool(up, args)),
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

// ───────────────────────── HTTPQL 查询历史 ─────────────────────────

fn query_flows(store: &Store, args: &Value) -> Result<String, String> {
    let q = str_arg(args, "query").ok_or("缺少参数 query")?;
    let limit = uint_arg(args, "limit").unwrap_or(FLOW_LIMIT_DEFAULT).clamp(1, RECENT_FETCH);
    let query = httpql_parse(&q).map_err(|e| format!("HTTPQL 解析失败:{e}"))?;
    let flows = store.recent(RECENT_FETCH).map_err(|e| format!("读历史库失败:{e:#}"))?;
    let mut items = Vec::new();
    for (i, f) in flows.iter().enumerate() {
        let url = f.url();
        let ext = path_ext(&f.path);
        let mime = header_value(&f.resp_headers, "content-type");
        let reqh = join_headers(&f.req_headers);
        let resph = join_headers(&f.resp_headers);
        let searchable = build_searchable(f, &url, &reqh, &resph);
        let ff = FlowFields {
            method: &f.method,
            host: &f.host,
            path: &f.path,
            url: &url,
            ext: &ext,
            port: f.port,
            status: f.status,
            req_len: f.req_body.len(),
            resp_len: f.resp_body.len(),
            mime: &mime,
            req_headers: &reqh,
            resp_headers: &resph,
            searchable: &searchable,
        };
        if query.matches(&ff) {
            items.push(json!({
                "index": i,
                "method": f.method,
                "url": url,
                "status": f.status,
                "resp_len": f.resp_body.len(),
            }));
            if items.len() >= limit {
                break;
            }
        }
    }
    Ok(pretty(json!({
        "query": q,
        "matched": items.len(),
        "flows": items,
    })))
}

// ───────────────────────── JWT ─────────────────────────

fn jwt_tool(args: &Value) -> Result<String, String> {
    let action = str_arg(args, "action").unwrap_or_else(|| "decode".to_string());
    match action.as_str() {
        "decode" => {
            let token = str_arg(args, "token").ok_or("decode 需要 token")?;
            let d = scry_jwt::decode(&token)?;
            Ok(pretty(json!({
                "alg": d.alg,
                "header": d.header,
                "payload": d.payload,
                "signature": d.signature,
            })))
        }
        "none" => {
            let payload = str_arg(args, "payload").ok_or("none 需要 payload(JSON)")?;
            let token = match str_arg(args, "alg") {
                Some(a) => scry_jwt::forge_none_variant(&payload, &a),
                None => scry_jwt::forge_none(&payload),
            };
            Ok(pretty(json!({ "token": token })))
        }
        "sign" => {
            let payload = str_arg(args, "payload").ok_or("sign 需要 payload(JSON)")?;
            let secret = str_arg(args, "secret").unwrap_or_default();
            Ok(pretty(json!({ "token": scry_jwt::sign_hs256(&secret, &payload) })))
        }
        "kid" => {
            let payload = str_arg(args, "payload").ok_or("kid 需要 payload(JSON)")?;
            let secret = str_arg(args, "secret").unwrap_or_default();
            let kid = str_arg(args, "kid").ok_or("kid 需要 kid 值")?;
            Ok(pretty(json!({ "token": scry_jwt::forge_kid(&secret, &payload, &kid) })))
        }
        "verify" => {
            let token = str_arg(args, "token").ok_or("verify 需要 token")?;
            let secret = str_arg(args, "secret").unwrap_or_default();
            Ok(pretty(json!({ "valid": scry_jwt::verify_hs256(&token, &secret) })))
        }
        "crack" => {
            let token = str_arg(args, "token").ok_or("crack 需要 token")?;
            let custom: Vec<String> = args
                .get("wordlist")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let found = if custom.is_empty() {
                scry_jwt::crack_hs256(&token, scry_jwt::COMMON_SECRETS)
            } else {
                scry_jwt::crack_hs256(&token, &custom)
            };
            Ok(pretty(json!({
                "cracked": found.is_some(),
                "secret": found,
                "tried": if custom.is_empty() { scry_jwt::COMMON_SECRETS.len() } else { custom.len() },
            })))
        }
        other => Err(format!("未知 action:{other}(decode|none|sign|kid|verify|crack)")),
    }
}

// ───────────────────────── 序列器(熵分析)─────────────────────────

fn sequencer_tool(args: &Value) -> Result<String, String> {
    let text = str_arg(args, "tokens").ok_or("缺少参数 tokens(每行一个令牌)")?;
    let tokens = scry_seq::parse_tokens(&text);
    if tokens.is_empty() {
        return Err("没有解析到任何令牌".to_string());
    }
    let report = scry_seq::analyze(&tokens);
    serde_json::to_value(&report)
        .map(pretty)
        .map_err(|e| format!("序列化报告失败:{e}"))
}

// ───────────────────────── 比较器(diff)─────────────────────────

fn compare_tool(args: &Value) -> Result<String, String> {
    let a = str_arg(args, "a").unwrap_or_default();
    let b = str_arg(args, "b").unwrap_or_default();
    let g = match str_arg(args, "granularity").as_deref() {
        Some("word") => Granularity::Word,
        Some("char") => Granularity::Char,
        _ => Granularity::Line,
    };
    let r = scry_diff::diff(&a, &b, g);
    let mut changes = Vec::new();
    for s in &r.spans {
        let tag = match s.tag {
            scry_diff::ChangeTag::Insert => "+",
            scry_diff::ChangeTag::Delete => "-",
            scry_diff::ChangeTag::Equal => continue,
        };
        let snippet: String = s.text.chars().take(200).collect();
        changes.push(format!("{tag} {snippet}"));
        if changes.len() >= 100 {
            break;
        }
    }
    Ok(pretty(json!({
        "similarity": r.similarity,
        "identical": r.identical,
        "equal_tokens": r.equal_tokens,
        "inserted_tokens": r.inserted_tokens,
        "deleted_tokens": r.deleted_tokens,
        "changes": changes,
    })))
}

// ───────────────────────── GraphQL ─────────────────────────

async fn graphql_tool(up: &Option<UpstreamProxy>, args: &Value) -> Result<String, String> {
    let action = match str_arg(args, "action") {
        Some(a) => a,
        None => {
            if str_arg(args, "url").is_some() {
                "introspect".to_string()
            } else {
                "prettify".to_string()
            }
        }
    };
    match action.as_str() {
        "minify" => {
            let q = str_arg(args, "query").ok_or("minify 需要 query")?;
            Ok(pretty(json!({ "query": scry_graphql::minify(&q) })))
        }
        "prettify" => {
            let q = str_arg(args, "query").ok_or("prettify 需要 query")?;
            Ok(pretty(json!({ "query": scry_graphql::prettify(&q) })))
        }
        "introspect" => {
            let url = str_arg(args, "url").ok_or("introspect 需要 url")?;
            let body = scry_graphql::build_request_body(scry_graphql::INTROSPECTION_QUERY, "", None);
            let mut headers = parse_headers_arg(args.get("headers"));
            if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
                headers.push(("Content-Type".to_string(), "application/json".to_string()));
            }
            let mut req = ReplayRequest::from_url("POST", &url, headers, body.into_bytes())
                .ok_or_else(|| format!("非法 URL:{url}"))?;
            ensure_host(&mut req);
            let flow = do_send(&req, up).await?;
            let text = scry_decode::display_text(&flow.resp_headers, &flow.resp_body);
            let schema = scry_graphql::parse_introspection(&text)?;
            serde_json::to_value(&schema)
                .map(|v| pretty(json!({ "status": flow.status, "schema": v })))
                .map_err(|e| format!("序列化 schema 失败:{e}"))
        }
        other => Err(format!("未知 action:{other}(introspect|prettify|minify)")),
    }
}

// ───────────────────────── Param Miner ─────────────────────────

async fn param_miner_tool(up: &Option<UpstreamProxy>, args: &Value) -> Result<String, String> {
    let url = str_arg(args, "url").ok_or("缺少参数 url")?;
    let base = ReplayRequest::from_url("GET", &url, vec![], vec![])
        .ok_or_else(|| format!("非法 URL:{url}"))?;
    let authority = host_header(&base.host, base.port, &base.scheme);
    let origin = format!("{}://{}", base.scheme, authority);
    let mut found: Vec<String> = Vec::new();
    let mut sent = 0usize;
    for (batch, chunk) in param_miner::PARAM_WORDLIST.chunks(20).enumerate() {
        let probes = param_miner::make_probes(chunk, batch as u64);
        let new_path = param_miner::inject_query(&base.path, &probes);
        let full = format!("{origin}{new_path}");
        let mut req = ReplayRequest::from_url("GET", &full, vec![], vec![])
            .ok_or_else(|| format!("非法 URL:{full}"))?;
        ensure_host(&mut req);
        if let Ok(flow) = do_send(&req, up).await {
            sent += 1;
            let text = scry_decode::display_text(&flow.resp_headers, &flow.resp_body);
            let refl = param_miner::reflected(&text, &probes);
            if !param_miner::looks_like_url_echo(refl.len(), probes.len()) {
                for name in refl {
                    if !found.contains(&name) {
                        found.push(name);
                    }
                }
            }
        }
    }
    Ok(pretty(json!({
        "url": url,
        "requests_sent": sent,
        "hidden_params": found,
        "note": if found.is_empty() {
            "未发现被反射的隐藏参数(反射法只测回显型,不代表没有)"
        } else {
            "这些参数名的金丝雀在响应里被反射 = 后端可能在读取它们"
        },
    })))
}

// ───────────────────────── nuclei 模板扫描 ─────────────────────────

/// 单次 nuclei 扫描最多发出的请求数(防失控)。
const NUCLEI_REQUEST_BUDGET: usize = 300;

async fn nuclei_scan_tool(up: &Option<UpstreamProxy>, args: &Value) -> Result<String, String> {
    let url = str_arg(args, "url").ok_or("缺少参数 url")?;
    let target = Target::parse(&url).ok_or_else(|| format!("非法目标:{url}"))?;
    let mut templates = scry_nuclei::load_builtins();
    let builtin_n = templates.len();
    let mut loaded_from_dir = 0usize;
    if let Some(dir) = str_arg(args, "dir") {
        let mut paths = Vec::new();
        collect_yaml(std::path::Path::new(&dir), &mut paths);
        for p in paths {
            if let Ok(text) = std::fs::read_to_string(&p) {
                if let Ok(t) = scry_nuclei::parse_template(&text) {
                    templates.push(t);
                    loaded_from_dir += 1;
                }
            }
        }
    }
    let mut hits = Vec::new();
    let mut sent = 0usize;
    'outer: for t in &templates {
        for block in &t.requests {
            for b in scry_nuclei::build_block_requests(block, &target) {
                if sent >= NUCLEI_REQUEST_BUDGET {
                    break 'outer;
                }
                let flow = HttpFlow::request(
                    &b.method,
                    &b.scheme,
                    b.host.clone(),
                    b.port,
                    b.path.clone(),
                    b.headers.clone(),
                    b.body.clone(),
                );
                let req = ReplayRequest::from_flow(&flow);
                let hit_url = b.url();
                if let Ok(resp_flow) = do_send(&req, up).await {
                    sent += 1;
                    let resp = RespData::new(
                        resp_flow.status,
                        &resp_flow.resp_headers,
                        &resp_flow.resp_body,
                        resp_flow.duration_ms,
                    );
                    let res = scry_nuclei::evaluate_request(block, &resp);
                    if res.matched {
                        hits.push(json!({
                            "template_id": t.id.clone(),
                            "name": t.info.name.clone(),
                            "severity": t.severity().label(),
                            "url": hit_url,
                            "matchers": res.matched_names,
                            "extracted": res
                                .extracted
                                .iter()
                                .map(|(k, v)| json!([k, v]))
                                .collect::<Vec<_>>(),
                        }));
                    }
                }
            }
        }
    }
    Ok(pretty(json!({
        "target": target.base_url(),
        "templates": templates.len(),
        "builtin": builtin_n,
        "loaded_from_dir": loaded_from_dir,
        "requests_sent": sent,
        "count": hits.len(),
        "hits": hits,
    })))
}

/// 递归收集目录下的 nuclei 模板文件(`.yaml` / `.yml`),封顶防超大目录树。
fn collect_yaml(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    if out.len() >= 2000 || !dir.is_dir() {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_yaml(&p, out);
        } else if p.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            out.push(p);
            if out.len() >= 2000 {
                return;
            }
        }
    }
}

// ───────────────────────── SQL 注入(sqlmap 式)─────────────────────────

/// 单次 sqli 扫描最多测的注入点 / 最多发出的请求(防失控)。
const SQLI_POINT_CAP: usize = 12;
const SQLI_REQUEST_BUDGET: usize = 150;

async fn sqli_scan_tool(up: &Option<UpstreamProxy>, args: &Value) -> Result<String, String> {
    let url = str_arg(args, "url").ok_or("缺少参数 url(需带 ? 查询参数)")?;
    let do_time = args.get("time").and_then(|v| v.as_bool()).unwrap_or(false);
    let secs = uint_arg(args, "secs").unwrap_or(5).clamp(2, 15) as u32;
    let mut base = ReplayRequest::from_url("GET", &url, vec![], vec![])
        .ok_or_else(|| format!("非法 URL:{url}"))?;
    ensure_host(&mut base);
    let base_flow = flow_from_replay(&base);
    let points = scry_sqli::injection_points(&base_flow);
    if points.is_empty() {
        return Err("没有可注入点(URL 需带查询参数,如 ?id=1)".to_string());
    }
    let baseline = do_send(&base, up).await?;
    let base_view = scry_sqli::RespView::of(&baseline);
    let baseline_ms = baseline.duration_ms;
    let baseline_has_db_error = scry_sqli::match_error_dbms(&base_view.body).is_some();
    let nonce: u32 = 0x5c2a_7e31;

    let mut log: Vec<String> = Vec::new();
    let mut injectable = false;
    let mut hit_point: Option<String> = None;
    let mut dbms: Option<String> = None;
    let mut techniques: Vec<&str> = Vec::new();
    let mut sent = 0usize;

    'points: for point in points.iter().take(SQLI_POINT_CAP) {
        if sent >= SQLI_REQUEST_BUDGET {
            break;
        }
        // 1) 报错型:语法破坏字符触发数据库报错回显。
        if !baseline_has_db_error {
            for v in scry_sqli::error_probe_values(&point.value) {
                let probe = scry_sqli::build_probe(&base_flow, point, &v);
                if let Ok(resp) = do_send(&ReplayRequest::from_flow(&probe), up).await {
                    sent += 1;
                    if let Some(db) =
                        scry_sqli::match_error_dbms(&scry_sqli::RespView::of(&resp).body)
                    {
                        injectable = true;
                        hit_point = Some(point.label());
                        dbms = Some(db.label().to_string());
                        if !techniques.contains(&"Error-based") {
                            techniques.push("Error-based");
                        }
                        log.push(format!(
                            "✓ 报错型:点[{}] 载荷「{v}」触发 {} 报错",
                            point.label(),
                            db.label()
                        ));
                        break;
                    }
                }
            }
        }
        // 2) 布尔盲注:恒真 / 恒假条件下响应可区分。
        for bt in scry_sqli::boolean_tests(&point.value, nonce) {
            if sent >= SQLI_REQUEST_BUDGET {
                break;
            }
            let tp = scry_sqli::build_probe(&base_flow, point, &bt.truthy);
            let fp = scry_sqli::build_probe(&base_flow, point, &bt.falsy);
            if let (Ok(tr), Ok(fr)) = (
                do_send(&ReplayRequest::from_flow(&tp), up).await,
                do_send(&ReplayRequest::from_flow(&fp), up).await,
            ) {
                sent += 2;
                if scry_sqli::judge_boolean(
                    &base_view,
                    &scry_sqli::RespView::of(&tr),
                    &scry_sqli::RespView::of(&fr),
                ) {
                    injectable = true;
                    hit_point = Some(point.label());
                    if !techniques.contains(&"Boolean-based blind") {
                        techniques.push("Boolean-based blind");
                    }
                    log.push(format!(
                        "✓ 布尔盲注:点[{}] 边界「{}」可区分真 / 假",
                        point.label(),
                        bt.boundary.label()
                    ));
                    break;
                }
            }
        }
        // 3) 时间盲注(可选;每发真睡 secs 秒,故默认关 + 小预算)。
        if do_time && dbms.is_none() {
            let mut budget = 4usize;
            for tt in scry_sqli::time_tests(&point.value, secs) {
                if budget == 0 || sent >= SQLI_REQUEST_BUDGET {
                    break;
                }
                budget -= 1;
                let probe = scry_sqli::build_probe(&base_flow, point, &tt.value);
                if let Ok(resp) = do_send(&ReplayRequest::from_flow(&probe), up).await {
                    sent += 1;
                    if scry_sqli::judge_time_delta(secs, baseline_ms, resp.duration_ms) {
                        let probe2 = scry_sqli::build_probe(&base_flow, point, &tt.value);
                        if let Ok(resp2) = do_send(&ReplayRequest::from_flow(&probe2), up).await {
                            sent += 1;
                            if scry_sqli::judge_time_delta(secs, baseline_ms, resp2.duration_ms) {
                                injectable = true;
                                hit_point = Some(point.label());
                                dbms = Some(tt.dbms.label().to_string());
                                if !techniques.contains(&"Time-based blind") {
                                    techniques.push("Time-based blind");
                                }
                                log.push(format!(
                                    "✓ 时间盲注:点[{}] {} 延迟≈{secs}s",
                                    point.label(),
                                    tt.dbms.label()
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }
        if injectable {
            break 'points;
        }
    }

    Ok(pretty(json!({
        "url": url,
        "injectable": injectable,
        "point": hit_point,
        "dbms": dbms,
        "techniques": techniques,
        "points_total": points.len(),
        "requests_sent": sent,
        "log": log,
        "note": "报错 + 布尔默认开;时间盲注需 time=true(每发真睡 secs 秒)。仅对已授权目标使用。",
    })))
}

// ───────────────────────── 反射型 XSS(dalfox 式)─────────────────────────

const XSS_POINT_CAP: usize = 12;
const XSS_CANDIDATE_CAP: usize = 8;

async fn xss_scan_tool(up: &Option<UpstreamProxy>, args: &Value) -> Result<String, String> {
    let url = str_arg(args, "url").ok_or("缺少参数 url(需带 ? 查询参数)")?;
    let mut base = ReplayRequest::from_url("GET", &url, vec![], vec![])
        .ok_or_else(|| format!("非法 URL:{url}"))?;
    ensure_host(&mut base);
    let base_flow = flow_from_replay(&base);
    let points = scry_xss::injection_points(&base_flow);
    if points.is_empty() {
        return Err("没有可注入点(URL 需带查询参数,如 ?q=test)".to_string());
    }

    // 基线:静态扫 DOM sink(信息性)。
    let mut dom_sinks: Vec<String> = Vec::new();
    if let Ok(bl) = do_send(&base, up).await {
        let body = scry_decode::display_text(&bl.resp_headers, &bl.resp_body);
        dom_sinks = scry_xss::dom_sinks(&body).iter().map(|s| s.to_string()).collect();
    }

    let mut findings = Vec::new();
    let mut sent = 0usize;
    for point in points.iter().take(XSS_POINT_CAP) {
        // 1) 反射定位 + 上下文识别。
        let plain = scry_xss::build_probe(&base_flow, point, scry_xss::REFLECT_MARK);
        let Ok(pf) = do_send(&ReplayRequest::from_flow(&plain), up).await else {
            continue;
        };
        sent += 1;
        let plain_body = scry_decode::display_text(&pf.resp_headers, &pf.resp_body);
        let offs = scry_xss::reflections(&plain_body, scry_xss::REFLECT_MARK);
        if offs.is_empty() {
            continue;
        }
        let ctx = scry_xss::detect_context(&plain_body, offs[0]);
        // 2) 可利用字符探测。
        let canary_probe = scry_xss::build_probe(&base_flow, point, &scry_xss::canary());
        let Ok(cf) = do_send(&ReplayRequest::from_flow(&canary_probe), up).await else {
            continue;
        };
        sent += 1;
        let ab = scry_xss::abusable_chars(&scry_decode::display_text(&cf.resp_headers, &cf.resp_body));
        // 3) 按上下文合成候选载荷,逐个验证 proof 未编码回显。
        let candidates = scry_xss::synthesize(ctx, ab);
        if candidates.is_empty() {
            findings.push(json!({
                "point": point.label(),
                "confirmed": false,
                "context": ctx.label(),
                "reason": "反射但危险字符被编码,当前上下文不可利用",
            }));
            continue;
        }
        let mut confirmed: Option<scry_xss::Payload> = None;
        for p in candidates.into_iter().take(XSS_CANDIDATE_CAP) {
            let probe = scry_xss::build_probe(&base_flow, point, &p.value);
            if let Ok(rf) = do_send(&ReplayRequest::from_flow(&probe), up).await {
                sent += 1;
                let body = scry_decode::display_text(&rf.resp_headers, &rf.resp_body);
                if body.contains(&p.proof) {
                    confirmed = Some(p);
                    break;
                }
            }
        }
        match confirmed {
            Some(p) => findings.push(json!({
                "point": point.label(),
                "confirmed": true,
                "context": ctx.label(),
                "kind": p.kind,
                "payload": p.value,
            })),
            None => findings.push(json!({
                "point": point.label(),
                "confirmed": false,
                "context": ctx.label(),
                "reason": "反射且字符可用,但合成载荷未原样回显",
            })),
        }
    }

    Ok(pretty(json!({
        "url": url,
        "points_total": points.len(),
        "requests_sent": sent,
        "dom_sinks": dom_sinks,
        "findings": findings,
        "note": "反射型 XSS 上下文感知检测(dalfox 式)。仅对已授权目标使用。",
    })))
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

/// 路径扩展名(去 query/fragment 后取最后一段的扩展;无则空)。
fn path_ext(path: &str) -> String {
    let p = path.split(['?', '#']).next().unwrap_or(path);
    let last = p.rsplit('/').next().unwrap_or(p);
    last.rsplit_once('.').map(|(_, e)| e.to_string()).unwrap_or_default()
}

/// 拼接头部为 `Key: Value\n` 文本(HTTPQL 头字段 / 全文用)。
fn join_headers(h: &[Header]) -> String {
    let mut s = String::new();
    for (k, v) in h {
        s.push_str(k);
        s.push_str(": ");
        s.push_str(v);
        s.push('\n');
    }
    s
}

/// 取某个头的值(大小写不敏感;无则空)。
fn header_value(h: &[Header], name: &str) -> String {
    h.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

/// 组合**小写**可搜索文本(URL + 头 + 解码 body),供 HTTPQL 全文项 / body 子句匹配。
fn build_searchable(f: &HttpFlow, url: &str, reqh: &str, resph: &str) -> String {
    let mut s = String::new();
    s.push_str(url);
    s.push('\n');
    s.push_str(reqh);
    s.push('\n');
    s.push_str(resph);
    s.push('\n');
    if !f.req_body.is_empty() {
        s.push_str(&scry_decode::display_text(&f.req_headers, &f.req_body));
        s.push('\n');
    }
    if !f.resp_body.is_empty() {
        s.push_str(&scry_decode::display_text(&f.resp_headers, &f.resp_body));
    }
    s.to_lowercase()
}

fn pretty(v: Value) -> String {
    serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string())
}
