//! HAR / XHR 文件导入 —— 把浏览器 DevTools「Network」面板导出的 `.har`(HTTP Archive,
//! 内含所有 XHR / fetch / 文档请求)解析成 [`HttpFlow`],灌进历史(**先落盘去重**,再刷新 UI)。
//!
//! 解析走 `serde_json` 动态取值(HAR 字段繁杂,只取需要的),对缺字段 / 异常条目宽容跳过。
//! 纯解析逻辑做成可单测的自由函数;`impl ScryApp` 只做接线(文件对话框 → 后台解析 → 落盘 → 刷新)。

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use mage_ui::gpui::PathPromptOptions;
use mage_ui::prelude::*;
use serde_json::Value;

use scry_core::{now_millis, Header, HttpFlow};
use scry_storage::Store;

use crate::logger::LogLevel;
use crate::state::{ScryApp, Tab};

/// 解析一段 HAR(JSON)字节为流量列表。`log.entries` 缺失即报错;单条异常则跳过。
pub fn parse_har(bytes: &[u8]) -> Result<Vec<HttpFlow>> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| anyhow!("不是有效的 JSON:{e}"))?;
    let entries = v
        .get("log")
        .and_then(|l| l.get("entries"))
        .and_then(|e| e.as_array())
        // 容错:个别工具直接导出 entries 数组(没有外层 log)。
        .or_else(|| v.as_array())
        .ok_or_else(|| anyhow!("不是有效的 HAR:缺 log.entries"))?;
    let n = entries.len();
    let base = now_millis();
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if let Some(mut flow) = entry_to_flow(e) {
            // HAR entries 通常按时间升序;给每条递减毫秒,保证「最新在前」展示顺序稳定。
            flow.ts = base - (n - 1 - i) as i64;
            out.push(flow);
        }
    }
    if out.is_empty() {
        return Err(anyhow!("HAR 中没有可导入的 HTTP 请求"));
    }
    Ok(out)
}

/// 单条 HAR entry → [`HttpFlow`](纯函数;关键字段缺失则返回 `None`,非 http(s) 跳过)。
fn entry_to_flow(e: &Value) -> Option<HttpFlow> {
    let req = e.get("request")?;
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("GET");
    let url = req.get("url").and_then(|u| u.as_str())?;
    let (scheme, host, port, path) = split_url(url)?;
    let req_headers = parse_headers(req.get("headers"));
    let req_body = req
        .get("postData")
        .and_then(|p| p.get("text"))
        .and_then(|t| t.as_str())
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_default();

    // 响应(HAR 里 status==0 表示无响应 / 被浏览器拦截)。
    let resp = e.get("response");
    let status = resp
        .and_then(|r| r.get("status"))
        .and_then(|s| s.as_i64())
        .unwrap_or(0)
        .clamp(0, 599) as u16;
    let resp_headers = parse_headers(resp.and_then(|r| r.get("headers")));
    let resp_body = resp
        .and_then(|r| r.get("content"))
        .map(decode_content)
        .unwrap_or_default();
    let duration_ms = e
        .get("time")
        .and_then(|t| t.as_f64())
        .unwrap_or(0.0)
        .max(0.0) as u64;

    Some(
        HttpFlow::request(method, scheme, host, port, path, req_headers, req_body)
            .with_response(status, resp_headers, resp_body, duration_ms),
    )
}

/// 拆 URL 为 `(scheme, host, port, path+query)`;非 http(s)(ws/data/blob…)返回 `None`。
fn split_url(raw: &str) -> Option<(String, String, u16, String)> {
    let u = url::Url::parse(raw).ok()?;
    let scheme = u.scheme().to_string();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let host = u.host_str()?.to_string();
    let port = u
        .port_or_known_default()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    let mut path = u.path().to_string();
    if let Some(q) = u.query() {
        path.push('?');
        path.push_str(q);
    }
    if path.is_empty() {
        path.push('/');
    }
    Some((scheme, host, port, path))
}

/// HAR headers 数组(`[{name,value}]`)→ [`Header`] 列表;过滤 HTTP/2 伪头(`:method` 等)。
fn parse_headers(v: Option<&Value>) -> Vec<Header> {
    let Some(arr) = v.and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|h| {
            let name = h.get("name").and_then(|n| n.as_str())?;
            // 伪头(:method/:authority/:scheme/:path)不是真实 HTTP 头,跳过。
            if name.starts_with(':') {
                return None;
            }
            let value = h.get("value").and_then(|v| v.as_str()).unwrap_or("");
            Some((name.to_string(), value.to_string()))
        })
        .collect()
}

/// 解码 HAR `content`:`encoding == "base64"` 则 base64 解码,否则按文本字节。
fn decode_content(content: &Value) -> Vec<u8> {
    let Some(text) = content.get("text").and_then(|t| t.as_str()) else {
        return Vec::new();
    };
    let is_b64 = content.get("encoding").and_then(|e| e.as_str()) == Some("base64");
    if is_b64 {
        base64_decode(text).unwrap_or_else(|| text.as_bytes().to_vec())
    } else {
        text.as_bytes().to_vec()
    }
}

/// 标准 base64 编码(带 `=` 填充)。导出 HAR 时给二进制响应体用。
fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// 标准 base64 解码(忽略空白与 `=` 填充);非法字符返回 `None`。
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut buf = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = val(c)?;
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

// ───────────────────────────── HAR 导出 ─────────────────────────────

/// Unix 毫秒 → ISO8601 UTC 字符串(`2026-06-25T18:03:01.234Z`)。
///
/// 不引时间库,手算公历(Howard Hinnant `civil_from_days` 算法),与项目「纯 Rust / 免依赖」风格一致。
fn iso8601_from_millis(ms: i64) -> String {
    let ms = ms.max(0);
    let secs = ms / 1000;
    let millis = ms % 1000;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // civil_from_days:从 1970-01-01 的天数还原 (year, month, day)。
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

/// 头部列表 → HAR `[{name,value}]`。
fn headers_to_har(headers: &[Header]) -> Vec<Value> {
    headers
        .iter()
        .map(|(k, v)| serde_json::json!({ "name": k, "value": v }))
        .collect()
}

/// 把字节体编码为 HAR content/postData 的文本表示:有效 UTF-8 直接放文本,否则 base64。
fn body_to_text(body: &[u8]) -> (String, bool) {
    match std::str::from_utf8(body) {
        Ok(s) => (s.to_string(), false),
        Err(_) => (base64_encode(body), true),
    }
}

/// 把流量列表序列化为标准 HAR 1.2 JSON 字符串(纯函数,可单测)。
///
/// 与 [`parse_har`] 对称:导出再导入应保持 method/url/headers/body/status 一致。
pub fn flows_to_har(flows: &[HttpFlow]) -> String {
    let entries: Vec<Value> = flows
        .iter()
        .map(|f| {
            let (req_text, _) = body_to_text(&f.req_body);
            let post_data = if f.req_body.is_empty() {
                Value::Null
            } else {
                let mime = f
                    .req_header("content-type")
                    .unwrap_or("application/octet-stream");
                serde_json::json!({ "mimeType": mime, "text": req_text })
            };
            let (resp_text, resp_b64) = body_to_text(&f.resp_body);
            let mut content = serde_json::json!({
                "size": f.resp_body.len(),
                "mimeType": f.content_type().unwrap_or(""),
                "text": resp_text,
            });
            if resp_b64 {
                content["encoding"] = Value::from("base64");
            }
            serde_json::json!({
                "startedDateTime": iso8601_from_millis(f.ts),
                "time": f.duration_ms,
                "request": {
                    "method": f.method,
                    "url": f.url(),
                    "httpVersion": "HTTP/1.1",
                    "headers": headers_to_har(&f.req_headers),
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": f.req_body.len(),
                    "postData": post_data,
                },
                "response": {
                    "status": f.status,
                    "statusText": crate::model::status_reason(f.status),
                    "httpVersion": "HTTP/1.1",
                    "headers": headers_to_har(&f.resp_headers),
                    "cookies": [],
                    "content": content,
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": f.resp_body.len(),
                },
                "cache": {},
                "timings": { "send": 0, "wait": f.duration_ms, "receive": 0 },
            })
        })
        .collect();

    let har = serde_json::json!({
        "log": {
            "version": "1.2",
            "creator": { "name": "Scry", "version": env!("CARGO_PKG_VERSION") },
            "entries": entries,
        }
    });
    serde_json::to_string_pretty(&har).unwrap_or_else(|_| "{}".to_string())
}

/// 把流量写成 `.har` 文件到 `~/.scry/exports/`,返回 (路径, 条数)。阻塞,放后台线程调。
fn export_har_blocking(flows: &[HttpFlow]) -> Result<(PathBuf, usize)> {
    let dir = scry_ca::default_ca_dir().join("exports");
    std::fs::create_dir_all(&dir).map_err(|e| anyhow!("创建导出目录失败:{e}"))?;
    let path = dir.join(format!("scry-export-{}.har", now_millis()));
    std::fs::write(&path, flows_to_har(flows)).map_err(|e| anyhow!("写入失败:{e}"))?;
    Ok((path, flows.len()))
}

/// 读取并解析一个 HAR 文件,逐条**先落盘去重**(save-first)。返回 `(新增条数, 解析总数, 文件名)`。
fn import_har_file(path: &Path) -> Result<(usize, usize, String)> {
    let bytes = std::fs::read(path).map_err(|e| anyhow!("读取文件失败:{e}"))?;
    let flows = parse_har(&bytes)?;
    let total = flows.len();
    let store = Store::open_default().map_err(|e| anyhow!("打开存储失败:{e:#}"))?;
    let mut added = 0usize;
    for f in &flows {
        if store.save(f).unwrap_or(false) {
            added += 1;
        }
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("HAR")
        .to_string();
    Ok((added, total, name))
}

impl ScryApp {
    /// 弹文件对话框选 `.har` 文件 → 后台解析 → 落盘去重 → 刷新历史并跳到 Proxy 页。
    pub fn import_har_dialog(&mut self, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some(self.lang.t("Import")),
        });
        let bg = cx.background_executor().clone();
        cx.spawn(async move |this, cx| {
            let path: Option<PathBuf> = match rx.await {
                Ok(Ok(Some(paths))) => paths.into_iter().next(),
                _ => None,
            };
            let Some(path) = path else {
                return;
            };
            // 文件 IO + 解析 + sqlite 写入放后台线程,避免卡 UI。
            let result = bg
                .spawn(async move { import_har_file(&path).map_err(|e| format!("{e:#}")) })
                .await;
            let _ = this.update(cx, |this, cx| {
                match result {
                    Ok((added, total, name)) => {
                        this.push_log(
                            LogLevel::Success,
                            "import",
                            format!("从 {name} 导入 {added} 条流量(共解析 {total} 条,已去重)"),
                        );
                        this.cert_msg = Some(if this.lang.is_zh() {
                            format!("已导入 {added} 条流量(共解析 {total} 条,已去重)")
                        } else {
                            format!("Imported {added} flows ({total} parsed, deduped)")
                        });
                        this.reload_flows();
                        if added > 0 {
                            this.tab = Tab::Proxy;
                        }
                    }
                    Err(msg) => {
                        this.push_log(LogLevel::Error, "import", format!("导入失败:{msg}"));
                        this.cert_msg = Some(if this.lang.is_zh() {
                            format!("导入失败:{msg}")
                        } else {
                            format!("Import failed: {msg}")
                        });
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// 把当前会话的全部流量导出为 `.har` 文件(写到 `~/.scry/exports/` 并在访达定位)。
    pub fn export_har_dialog(&mut self, cx: &mut Context<Self>) {
        if self.flows.is_empty() {
            self.cert_msg = Some(if self.lang.is_zh() {
                "当前没有可导出的流量".to_string()
            } else {
                "No flows to export".to_string()
            });
            cx.notify();
            return;
        }
        let flows = self.flows.clone();
        let bg = cx.background_executor().clone();
        cx.spawn(async move |this, cx| {
            let result = bg
                .spawn(async move { export_har_blocking(&flows).map_err(|e| format!("{e:#}")) })
                .await;
            let _ = this.update(cx, |this, cx| {
                match result {
                    Ok((path, n)) => {
                        let _ = std::process::Command::new("open")
                            .arg("-R")
                            .arg(&path)
                            .spawn();
                        this.push_log(
                            LogLevel::Success,
                            "export",
                            format!("已导出 {n} 条流量到 {}", path.display()),
                        );
                        this.cert_msg = Some(if this.lang.is_zh() {
                            format!("已导出 {n} 条流量为 HAR")
                        } else {
                            format!("Exported {n} flows as HAR")
                        });
                    }
                    Err(msg) => {
                        this.push_log(LogLevel::Error, "export", format!("导出失败:{msg}"));
                        this.cert_msg = Some(if this.lang.is_zh() {
                            format!("导出失败:{msg}")
                        } else {
                            format!("Export failed: {msg}")
                        });
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "log": {
        "version": "1.2",
        "entries": [
          {
            "time": 42.5,
            "request": {
              "method": "POST",
              "url": "https://api.example.com/login?next=/home",
              "headers": [
                {"name": ":authority", "value": "api.example.com"},
                {"name": "Content-Type", "value": "application/json"},
                {"name": "X-Token", "value": "abc"}
              ],
              "postData": {"mimeType": "application/json", "text": "{\"u\":\"bob\"}"}
            },
            "response": {
              "status": 200,
              "headers": [{"name": "Content-Type", "value": "text/plain"}],
              "content": {"mimeType": "text/plain", "text": "aGVsbG8=", "encoding": "base64"}
            }
          },
          {
            "request": {"method": "GET", "url": "wss://socket.example.com/ws"},
            "response": {"status": 101}
          }
        ]
      }
    }"#;

    #[test]
    fn parse_har_basic_fields() {
        let flows = parse_har(SAMPLE.as_bytes()).unwrap();
        // 第 2 条是 wss(非 http)应被跳过,只剩 1 条。
        assert_eq!(flows.len(), 1);
        let f = &flows[0];
        assert_eq!(f.method, "POST");
        assert_eq!(f.scheme, "https");
        assert_eq!(f.host, "api.example.com");
        assert_eq!(f.port, 443);
        assert_eq!(f.path, "/login?next=/home");
        assert_eq!(f.status, 200);
        assert_eq!(f.duration_ms, 42);
        assert_eq!(f.req_body, b"{\"u\":\"bob\"}");
        // base64 "aGVsbG8=" → "hello"。
        assert_eq!(f.resp_body, b"hello");
    }

    #[test]
    fn pseudo_headers_filtered() {
        let flows = parse_har(SAMPLE.as_bytes()).unwrap();
        let f = &flows[0];
        assert!(f.req_header("content-type").is_some());
        assert!(f.req_header("x-token").is_some());
        // 伪头 :authority 不应进入真实头列表。
        assert!(!f.req_headers.iter().any(|(k, _)| k.starts_with(':')));
    }

    #[test]
    fn invalid_har_errs() {
        assert!(parse_har(b"not json").is_err());
        assert!(parse_har(br#"{"log":{"entries":[]}}"#).is_err());
    }

    #[test]
    fn base64_decode_roundtrip() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
    }

    #[test]
    fn base64_encode_matches_decode() {
        for s in ["", "a", "ab", "abc", "hello world", "\u{4f60}\u{597d}"] {
            assert_eq!(base64_decode(&base64_encode(s.as_bytes())).unwrap(), s.as_bytes());
        }
        // 已知向量。
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b"a"), "YQ==");
    }

    #[test]
    fn iso8601_known_epochs() {
        assert_eq!(iso8601_from_millis(0), "1970-01-01T00:00:00.000Z");
        // 1782756181234 ms = 2026-06-29T18:03:01.234Z(date -u -r 1782756181 核对)。
        assert_eq!(iso8601_from_millis(1_782_756_181_234), "2026-06-29T18:03:01.234Z");
    }

    #[test]
    fn export_then_import_roundtrips() {
        use scry_core::HttpFlow;
        let flows = vec![
            HttpFlow::request(
                "POST",
                "https",
                "api.example.com",
                443,
                "/login?next=/home",
                vec![("Content-Type".into(), "application/json".into())],
                br#"{"u":"bob"}"#.to_vec(),
            )
            .with_response(
                200,
                vec![("Content-Type".into(), "text/plain".into())],
                b"hello".to_vec(),
                42,
            ),
            // 二进制响应体 → 应走 base64 编码并能解回。
            HttpFlow::request("GET", "https", "cdn.example.com", 443, "/i.png", vec![], vec![])
                .with_response(200, vec![], vec![0x89, 0x50, 0x4e, 0x47, 0x00, 0xff], 7),
        ];
        let har = flows_to_har(&flows);
        let parsed = parse_har(har.as_bytes()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].method, "POST");
        assert_eq!(parsed[0].url(), "https://api.example.com/login?next=/home");
        assert_eq!(parsed[0].status, 200);
        assert_eq!(parsed[0].req_body, br#"{"u":"bob"}"#);
        assert_eq!(parsed[0].resp_body, b"hello");
        assert_eq!(parsed[1].resp_body, vec![0x89, 0x50, 0x4e, 0x47, 0x00, 0xff]);
    }
}
