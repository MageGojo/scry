//! 展示数据与格式化辅助 —— 把 [`scry_core::HttpFlow`] 映射成界面要用的颜色 / 文案 / 列值,
//! 以及左栏 Session / Projects 的演示数据。纯函数,无 IO(读 DB 的 [`load_flows`] 除外)。

use mage_ui::prelude::*;
use scry_core::HttpFlow;

/// 等宽字体(代码 / 报文视图);macOS 自带 Menlo。
pub const MONO: &str = "Menlo";

// ── 左栏:Session ────────────────────────────────────────────────

/// 一个抓包会话(Burp 式工作区):各自独立的抓包数据。
pub struct Session {
    pub name: SharedString,
    /// 主题色序号(0..5),由 [`tone_color`] 解析成当前主题色。
    pub tone: usize,
    /// 该会话的抓包数据**存档**。约定:活动会话的工作集在 `ScryApp::flows`(切换时搬运),
    /// 故活动会话此处为空、非活动会话此处持有其数据。
    pub flows: Vec<HttpFlow>,
}

/// 把语义色序号映射到当前主题色(用于 Session / 项目协议点等)。
pub fn tone_color(tone: usize, c: ThemeColors) -> Hsla {
    match tone % 5 {
        0 => c.primary,
        1 => c.accent,
        2 => c.success,
        3 => c.warning,
        _ => c.danger,
    }
}

/// 新建一个空会话(指定名字与色调)。
pub fn new_session(name: impl Into<SharedString>, tone: usize) -> Session {
    Session {
        name: name.into(),
        tone,
        flows: Vec::new(),
    }
}

// ── 格式化 / 取色 ────────────────────────────────────────────────

/// 字节数人性化展示(对齐参考图:`842 B` / `12.34 KB` / `3.45 MB`)。
pub fn human_len(n: usize) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.2} KB", n as f64 / 1024.0)
    } else {
        format!("{:.2} MB", n as f64 / (1024.0 * 1024.0))
    }
}

/// 把 host 归并到「网站」(近似 eTLD+1,取末两段):`i0.hdslb.com` / `s1.hdslb.com` → `hdslb.com`。
/// IP 或单段直接原样返回(`.com.cn` 这类双后缀少见,取末两段已够日常分类)。
pub fn site_of(host: &str) -> String {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host.to_string();
    }
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() <= 2 {
        return host.to_string();
    }
    let n = labels.len();
    format!("{}.{}", labels[n - 2], labels[n - 1])
}

/// HTTP 方法 → 语义色。
pub fn method_color(method: &str, c: ThemeColors) -> Hsla {
    match method.to_ascii_uppercase().as_str() {
        "GET" => c.success,
        "POST" => c.accent,
        "PUT" | "PATCH" => c.warning,
        "DELETE" => c.danger,
        _ => c.primary,
    }
}

/// 状态码 → 语义色。
pub fn status_color(status: u16, c: ThemeColors) -> Hsla {
    match status {
        200..=299 => c.success,
        300..=399 => c.accent,
        400..=499 => c.warning,
        500..=599 => c.danger,
        _ => c.text_muted,
    }
}

/// 响应内容类型 → 简短标签(Type 列)。先看 `Content-Type`,退回路径扩展名。
pub fn type_label(flow: &HttpFlow) -> &'static str {
    if let Some(ct) = flow.content_type() {
        let ct = ct.to_ascii_lowercase();
        if ct.contains("json") {
            return "JSON";
        } else if ct.contains("html") {
            return "HTML";
        } else if ct.contains("javascript") || ct.contains("ecmascript") {
            return "JS";
        } else if ct.contains("css") {
            return "CSS";
        } else if ct.contains("image/") {
            return "IMG";
        } else if ct.contains("font") || ct.contains("woff") {
            return "FONT";
        } else if ct.contains("xml") {
            return "XML";
        } else if ct.contains("form-urlencoded") {
            return "FORM";
        } else if ct.contains("octet-stream") {
            return "BIN";
        } else if ct.contains("text/plain") {
            return "TEXT";
        }
    }
    let path = flow.path.as_str();
    let clean = path.split(['?', '#']).next().unwrap_or(path);
    let ext = clean.rsplit('.').next().unwrap_or("");
    match ext.to_ascii_lowercase().as_str() {
        "js" | "mjs" => "JS",
        "css" => "CSS",
        "json" => "JSON",
        "html" | "htm" => "HTML",
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "ico" => "IMG",
        "woff" | "woff2" | "ttf" | "otf" => "FONT",
        "xml" => "XML",
        _ => "—",
    }
}

/// 由 host 派生一个稳定的「伪 IP」(仅用于界面展示;真实抓包不解析 IP)。
pub fn pseudo_ip(host: &str) -> String {
    let mut h: u32 = 0x811c_9dc5; // FNV-1a 32
    for b in host.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    let a = 20 + (h & 0x3f); // 20..83,像公网段
    let b = (h >> 6) & 0xff;
    let c = (h >> 14) & 0xff;
    let d = 1 + ((h >> 22) % 254);
    format!("{a}.{b}.{c}.{d}")
}

/// 状态码 → 简短 reason 短语。
pub fn status_reason(s: u16) -> &'static str {
    match s {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

/// Unix 毫秒 → `HH:MM:SS`(UTC,仅展示)。
pub fn clock_hms(ts: i64) -> String {
    let secs = (ts / 1000).rem_euclid(86_400);
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    format!("{h:02}:{m:02}:{s:02}")
}

/// 秒数 → `HH:MM:SS`(状态栏运行时长)。
pub fn dur_hms(total: u64) -> String {
    let (h, m, s) = (total / 3600, (total % 3600) / 60, total % 60);
    format!("{h:02}:{m:02}:{s:02}")
}

// ── 启动数据 ─────────────────────────────────────────────────────

/// 优先读真 SQLite(`~/.scry/scry.sqlite`);为空则用内置演示流量。
///
/// 返回 `(flows, is_demo)`:`is_demo == true` 表示用的是演示数据(界面会标注,避免误以为已抓到)。
pub fn load_flows() -> (Vec<HttpFlow>, bool) {
    if let Ok(store) = scry_storage::Store::open_default() {
        if let Ok(v) = store.recent(500) {
            if !v.is_empty() {
                return (v, false);
            }
        }
    }
    (mock_flows(), true)
}

/// 内置演示流量(代理还没抓到东西时,用来展示界面布局,围绕 target.com 编排)。
pub fn mock_flows() -> Vec<HttpFlow> {
    let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36";
    let req = |method: &str, host: &str, path: &str, ctype: &str, cookie: bool, body: &str| {
        let mut headers = vec![
            ("Host".to_string(), host.to_string()),
            ("User-Agent".to_string(), ua.to_string()),
            ("Accept".to_string(), "*/*".to_string()),
            ("Accept-Encoding".to_string(), "gzip, deflate, br".to_string()),
            ("Accept-Language".to_string(), "zh-CN,zh;q=0.9".to_string()),
            ("Connection".to_string(), "keep-alive".to_string()),
        ];
        if !ctype.is_empty() {
            headers.push(("Content-Type".to_string(), ctype.to_string()));
        }
        if cookie {
            headers.push((
                "Cookie".to_string(),
                "sid=4f3a9c2e8b71; theme=dark".to_string(),
            ));
        }
        HttpFlow::request(method, "https", host, 443, path, headers, body.as_bytes().to_vec())
    };
    let resp = |flow: HttpFlow, status: u16, ctype: &str, setcookie: bool, body: &str, ms: u64| {
        let mut headers = vec![
            ("Server".to_string(), "nginx/1.21.6".to_string()),
            ("Content-Type".to_string(), ctype.to_string()),
            ("X-Frame-Options".to_string(), "SAMEORIGIN".to_string()),
            ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
            ("Cache-Control".to_string(), "no-store".to_string()),
        ];
        if setcookie {
            headers.push((
                "Set-Cookie".to_string(),
                "sid=eyJhbGc; Path=/; HttpOnly; Secure".to_string(),
            ));
        }
        flow.with_response(status, headers, body.as_bytes().to_vec(), ms)
    };

    vec![
        resp(req("GET", "target.com", "/dashboard", "", true, ""), 200, "text/html; charset=utf-8", false,
            "<!doctype html><html><head><title>Dashboard</title></head><body><h1>Welcome</h1></body></html>", 142),
        resp(req("POST", "api.target.com", "/login", "application/json", false,
            "{\n  \"username\": \"admin\",\n  \"password\": \"P@ssw0rd!\",\n  \"remember\": true\n}"),
            200, "application/json; charset=utf-8", true,
            "{\n  \"code\": 0,\n  \"message\": \"success\",\n  \"data\": {\n    \"token\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\",\n    \"user\": { \"id\": 1, \"username\": \"admin\", \"role\": \"administrator\" }\n  }\n}", 211),
        resp(req("GET", "target.com", "/static/app.4f3a.js", "", false, ""), 200, "application/javascript", false,
            "/*! app bundle */\n(function(){\"use strict\";console.log(\"scry demo\");})();", 64),
        resp(req("GET", "api.target.com", "/user/info", "", true, ""), 200, "application/json", false,
            "{\"id\":1,\"name\":\"Admin\",\"email\":\"admin@target.com\"}", 73),
        resp(req("POST", "api.target.com", "/graphql", "application/json", true,
            "{\"query\":\"{ me { id name } }\"}"), 200, "application/json", false,
            "{\"data\":{\"me\":{\"id\":1,\"name\":\"Admin\"}}}", 96),
        resp(req("GET", "target.com", "/favicon.ico", "", false, ""), 404, "text/html", false,
            "<html><body>404 Not Found</body></html>", 18),
        resp(req("GET", "api.target.com", "/api/config?env=prod", "", true, ""), 200, "application/json", false,
            "{\"feature_flags\":{\"beta\":true},\"cdn\":\"https://cdn.target.com\"}", 51),
        resp(req("POST", "api.target.com", "/upload", "application/octet-stream", true, "<binary upload>"),
            200, "application/json", false, "{\"ok\":true,\"file_id\":\"f_88213\"}", 503),
        resp(req("GET", "target.com", "/", "", false, ""), 200, "text/html; charset=utf-8", false,
            "<!doctype html><html><body>home</body></html>", 88),
        resp(req("GET", "target.com", "/static/style.css", "", false, ""), 200, "text/css", false,
            ":root{--bg:#0a0c16}body{margin:0;background:var(--bg)}", 31),
        resp(req("PUT", "api.target.com", "/user/42", "application/json", true, "{\"name\":\"Neo\"}"),
            200, "application/json", false, "{\"ok\":true}", 120),
        resp(req("DELETE", "api.target.com", "/session/current", "", true, ""), 204, "application/json", false, "", 40),
        resp(req("GET", "track.ads.target.com", "/pixel?id=99&ts=1717", "", false, ""), 302, "image/gif", false, "", 22),
        resp(req("POST", "pay.target.com", "/charge", "application/json", true, "{\"amount\":4200}"),
            500, "application/json", false, "{\"error\":\"upstream_timeout\"}", 311),
        resp(req("GET", "api.target.com", "/feed", "", false, ""), 401, "application/json", false,
            "{\"error\":\"unauthorized\"}", 35),
    ]
}
