//! `scry-mcp` —— 把 scry 的引擎能力暴露成 **MCP 服务**(stdio,行分隔 JSON-RPC 2.0),
//! 让 AI(Cursor / Claude Desktop)直接「操作 scry」:列流量、发请求、跑扫描、越权、解码。
//!
//! 设计见 `docs/设计-MCP.md`。与现有 [`scry_ext_host`] 进程协议同风格:**stdout 专用于协议**
//! (每行一个完整 JSON),诊断日志一律走 **stderr**;读 `~/.scry/scry.sqlite` 历史库 + 复用
//! `scry_proxy::replay` / `scry_scan` / `scry_codec`,与 GUI 同源、**不抢 8888 端口**。

mod tools;

use std::io::{BufRead, Write};

use serde_json::{json, Value};

use scry_proxy::upstream::UpstreamProxy;
use scry_storage::Store;

/// 默认回应的 MCP 协议版本(客户端给了就回显它的)。
const PROTOCOL_VERSION: &str = "2025-06-18";
const SERVER_NAME: &str = "scry";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    eprintln!("[scry-mcp] starting · db={:?}", scry_storage::default_db_path());
    // 历史库:打开失败也照常起服务(读类工具会回报错误,发包 / 解码类不依赖库)。
    let store = Store::open_default();
    if let Err(e) = &store {
        eprintln!("[scry-mcp] warning: 打开历史库失败:{e:#}(读历史类工具不可用,其余正常)");
    }
    // 出网上游(墙内 / sing-box / QX):SCRY_UPSTREAM=socks5://127.0.0.1:8899 之类。
    let upstream = UpstreamProxy::from_env();
    if upstream.is_some() {
        eprintln!("[scry-mcp] upstream = SCRY_UPSTREAM(链式出网)");
    }

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("[scry-mcp] fatal: 构建 tokio 运行时失败:{e}");
            std::process::exit(1);
        }
    };

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[scry-mcp] stdin 读取结束:{e}");
                break;
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                write_msg(&mut out, error_obj(Value::Null, -32700, &format!("parse error: {e}")));
                continue;
            }
        };

        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let is_request = id.is_some();

        match method {
            "initialize" => {
                if let Some(id) = id {
                    let client_ver = params
                        .get("protocolVersion")
                        .and_then(|v| v.as_str())
                        .unwrap_or(PROTOCOL_VERSION)
                        .to_string();
                    let result = json!({
                        "protocolVersion": client_ver,
                        "capabilities": { "tools": { "listChanged": false } },
                        "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
                    });
                    write_msg(&mut out, result_obj(id, result));
                }
            }
            // 客户端通知:无需响应。
            "notifications/initialized" | "notifications/cancelled" => {}
            "ping" => {
                if let Some(id) = id {
                    write_msg(&mut out, result_obj(id, json!({})));
                }
            }
            "tools/list" => {
                if let Some(id) = id {
                    write_msg(&mut out, result_obj(id, json!({ "tools": tools::schemas() })));
                }
            }
            "tools/call" => {
                if let Some(id) = id {
                    let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                    let result = match &store {
                        Ok(st) => match tools::call(&rt, st, &upstream, name, &args) {
                            Ok(text) => json!({ "content": [text_block(text)] }),
                            Err(e) => json!({ "content": [text_block(e)], "isError": true }),
                        },
                        Err(e) => json!({
                            "content": [text_block(format!("打开历史库失败:{e:#}"))],
                            "isError": true,
                        }),
                    };
                    write_msg(&mut out, result_obj(id, result));
                }
            }
            other => {
                // 未知方法:是请求才回错误;通知则静默忽略。
                if is_request {
                    if let Some(id) = id {
                        write_msg(
                            &mut out,
                            error_obj(id, -32601, &format!("method not found: {other}")),
                        );
                    }
                }
            }
        }
    }
}

/// 一个 MCP 文本内容块。
fn text_block(text: impl Into<String>) -> Value {
    json!({ "type": "text", "text": text.into() })
}

/// JSON-RPC 成功响应对象。
fn result_obj(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// JSON-RPC 错误响应对象。
fn error_obj(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// 把一条 JSON-RPC 消息写到 stdout(单行 + 换行 + flush)。
fn write_msg(out: &mut impl Write, msg: Value) {
    let line = msg.to_string();
    if out.write_all(line.as_bytes()).is_ok() && out.write_all(b"\n").is_ok() {
        let _ = out.flush();
    }
}
