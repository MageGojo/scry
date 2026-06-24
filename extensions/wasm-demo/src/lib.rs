//! Scry **WASM 沙箱扩展示例**(对标 `extensions/py-demo`,但跑在 wasmtime 强隔离沙箱里)。
//!
//! 编译目标 `wasm32-unknown-unknown`,导出 scry 约定的 C-ABI(见 `scry_ext_host::wasm`):
//! - `scry_alloc(len) -> ptr`:宿主在本模块线性内存里分配一段、写入输入 JSON。
//! - `scry_manifest() -> i64`:返回自述清单 JSON 的「打包指针」(高 32 位 = 指针,低 32 位 = 长度)。
//! - `scry_on_request(ptr,len) -> i64` / `scry_on_flow_complete(ptr,len) -> i64`:
//!   入参是 `HttpFlow` 的 JSON,返回 reply JSON 的打包指针。
//!
//! 行为:给每个请求加 `X-Scry-Wasm` 头(演示改写实时流量);响应 4xx/5xx 时上报一个 finding。
//! 全程纯计算 —— 不碰文件 / 网络 / 进程(沙箱默认就不给这些能力)。

use serde_json::{json, Value};

/// 自述清单(握手返回)。`abi` 必须与宿主 `scry_ext_api::ABI_VERSION` 一致。
const MANIFEST: &str = r#"{"manifest":{"id":"wasm-demo","name":"WASM 演示扩展","version":"0.1.0","description":"示例:加 X-Scry-Wasm 头 + 4xx/5xx 报 finding(wasmtime 沙箱,纯计算)","abi":1,"permissions":["traffic.modify"],"hooks":["on_request","on_flow_complete"]}}"#;

/// 打包 `(ptr<<32)|len` 并把缓冲区「泄漏」给宿主读取。
///
/// 内存安全:宿主每次钩子调用都新建一个 WASM 实例,调用结束即销毁整块线性内存,
/// 故此处不回收不会累积泄漏(实例级一次性内存)。
fn pack(data: Vec<u8>) -> i64 {
    let ptr = data.as_ptr() as u64;
    let len = data.len() as u64;
    core::mem::forget(data);
    ((ptr << 32) | (len & 0xffff_ffff)) as i64
}

/// 退化回复(解析失败时放行,绝不卡流量)。
fn passthrough() -> i64 {
    pack(br#"{"action":"continue"}"#.to_vec())
}

/// 宿主用它在本模块线性内存里要一段空间写输入。
///
/// # Safety
/// 由宿主按 ABI 调用;返回的指针仅在本次实例生命周期内有效。
#[no_mangle]
pub extern "C" fn scry_alloc(len: i32) -> i32 {
    let mut buf = Vec::<u8>::with_capacity(len.max(0) as usize);
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr as i32
}

#[no_mangle]
pub extern "C" fn scry_manifest() -> i64 {
    pack(MANIFEST.as_bytes().to_vec())
}

/// # Safety
/// `ptr`/`len` 必须指向宿主刚写入的合法输入区(由 ABI 保证)。
#[no_mangle]
pub unsafe extern "C" fn scry_on_request(ptr: i32, len: i32) -> i64 {
    let data = core::slice::from_raw_parts(ptr as *const u8, len.max(0) as usize);
    match on_request(data) {
        Some(v) => pack(v),
        None => passthrough(),
    }
}

fn on_request(data: &[u8]) -> Option<Vec<u8>> {
    let mut flow: Value = serde_json::from_slice(data).ok()?;
    let headers = flow.get_mut("req_headers")?.as_array_mut()?;
    headers.push(json!(["X-Scry-Wasm", "1"]));
    let reply = json!({
        "action": "continue",
        "flow": flow,
        "logs": [{"level": "Debug", "msg": "wasm: tagged request"}],
    });
    serde_json::to_vec(&reply).ok()
}

/// # Safety
/// 同 [`scry_on_request`]。
#[no_mangle]
pub unsafe extern "C" fn scry_on_flow_complete(ptr: i32, len: i32) -> i64 {
    let data = core::slice::from_raw_parts(ptr as *const u8, len.max(0) as usize);
    match on_flow_complete(data) {
        Some(v) => pack(v),
        None => passthrough(),
    }
}

fn on_flow_complete(data: &[u8]) -> Option<Vec<u8>> {
    let flow: Value = serde_json::from_slice(data).ok()?;
    let status = flow.get("status").and_then(Value::as_u64).unwrap_or(0);
    let mut findings = Vec::new();
    if status >= 400 {
        let scheme = flow.get("scheme").and_then(Value::as_str).unwrap_or("http");
        let host = flow.get("host").and_then(Value::as_str).unwrap_or("");
        let path = flow.get("path").and_then(Value::as_str).unwrap_or("");
        findings.push(json!({
            "severity": if status >= 500 { "Medium" } else { "Low" },
            "title": format!("HTTP {status}"),
            "detail": "wasm 扩展观测到错误响应",
            "url": format!("{scheme}://{host}{path}"),
        }));
    }
    serde_json::to_vec(&json!({"action": "continue", "findings": findings})).ok()
}
