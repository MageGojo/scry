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
}
