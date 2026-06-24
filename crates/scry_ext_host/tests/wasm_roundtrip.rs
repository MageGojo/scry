//! 集成测试:WASM 沙箱 Runner(`WasmExt`)。
//!
//! 用**内联 WAT**(WebAssembly 文本)动态生成最小扩展模块 —— 无需 `wasm32` 目标 / `wit-bindgen` 工具链,
//! 完整验证宿主侧链路:编译加载 → manifest 握手 → 写入 flow → 调钩子 → 读回 reply → 解析 →
//! 应用副作用(log/finding)+ 改写 flow + 映射动作(Continue/Drop/Respond);并验证缺失钩子 no-op、
//! fuel 死循环 fail-open、ABI 不匹配拒绝加载。

use scry_core::HttpFlow;
use scry_ext_api::{
    ExtKind, Extension, Finding, HookAction, HostServices, LogLevel, Permission,
};
use scry_ext_host::{WasmExt, DEFAULT_FUEL};

/// 收集副作用的测试用 HostServices。
#[derive(Default)]
struct TestHost {
    logs: Vec<(LogLevel, String)>,
    findings: Vec<Finding>,
}
impl HostServices for TestHost {
    fn log(&mut self, level: LogLevel, msg: &str) {
        self.logs.push((level, msg.to_string()));
    }
    fn emit_finding(&mut self, f: Finding) {
        self.findings.push(f);
    }
}

/// WAT 字符串字面量转义(只需处理反斜杠与双引号;其余测试用 JSON 均为 ASCII)。
fn wat_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// 生成一个最小 WASM 扩展模块(WAT):
/// - `scry_manifest` 返回 `manifest` JSON 的打包指针;
/// - 每个 `(export, reply_json)` 生成一个忽略入参、返回该 reply 打包指针的钩子导出;
/// - 所有字符串入 data 段(偏移由 Rust 精确累加),`scry_alloc` 为 bump 分配器(分配在 data 段之后)。
fn build_wat(manifest: &str, hooks: &[(&str, &str)]) -> String {
    let mut data = String::new();
    let mut funcs = String::new();
    let mut off: usize = 0;

    data.push_str(&format!(
        "  (data (i32.const {off}) \"{}\")\n",
        wat_escape(manifest)
    ));
    funcs.push_str(&format!(
        "  (func (export \"scry_manifest\") (result i64)\n    (i64.or (i64.shl (i64.const {off}) (i64.const 32)) (i64.const {})))\n",
        manifest.len()
    ));
    off += manifest.len();

    for (name, reply) in hooks {
        data.push_str(&format!(
            "  (data (i32.const {off}) \"{}\")\n",
            wat_escape(reply)
        ));
        funcs.push_str(&format!(
            "  (func (export \"{name}\") (param i32 i32) (result i64)\n    (i64.or (i64.shl (i64.const {off}) (i64.const 32)) (i64.const {})))\n",
            reply.len()
        ));
        off += reply.len();
    }

    // bump 分配区从 data 段之后的下一个 64KiB 边界起,给宿主写入 flow 留足空间。
    let bump_start = ((off / 65536) + 1) * 65536;
    let pages = (bump_start / 65536) + 16; // 额外 ~1MiB 容纳输入
    format!(
        "(module\n  (memory (export \"memory\") {pages})\n{data}  (global $bump (mut i32) (i32.const {bump_start}))\n  (func (export \"scry_alloc\") (param $n i32) (result i32)\n    (local $p i32)\n    (local.set $p (global.get $bump))\n    (global.set $bump (i32.add (global.get $bump) (local.get $n)))\n    (local.get $p))\n{funcs})\n"
    )
}

fn load(manifest: &str, hooks: &[(&str, &str)]) -> WasmExt {
    let wat = build_wat(manifest, hooks);
    WasmExt::from_bytes(wat.as_bytes(), DEFAULT_FUEL).expect("WASM 扩展应加载成功")
}

const MANIFEST: &str = r#"{"manifest":{"id":"wasm-demo","name":"WASM Demo","version":"0.2.0","abi":1,"permissions":["traffic.modify","net.outbound"],"hooks":["on_request","on_response","on_flow_complete"]}}"#;

#[test]
fn manifest_handshake() {
    let ext = load(MANIFEST, &[]);
    let m = ext.manifest();
    assert_eq!(m.id, "wasm-demo");
    assert_eq!(m.name, "WASM Demo");
    assert_eq!(m.kind, ExtKind::Wasm);
    assert!(m.hooks.iter().any(|h| h == "on_request"));
    assert!(m
        .permissions
        .iter()
        .any(|p| matches!(p, Permission::NetOutbound)));
    assert!(m
        .permissions
        .iter()
        .any(|p| matches!(p, Permission::TrafficModify)));
}

#[test]
fn on_flow_complete_emits_finding_and_log() {
    let reply = r#"{"action":"continue","logs":[{"level":"Info","msg":"wasm saw flow"}],"findings":[{"severity":"Medium","title":"wasm-finding","detail":"detected by wasm","url":"https://t.test/x"}]}"#;
    let ext = load(MANIFEST, &[("scry_on_flow_complete", reply)]);

    let mut host = TestHost::default();
    let flow = HttpFlow::request("GET", "https", "t.test", 443, "/x", vec![], vec![]);
    ext.on_flow_complete(&flow, &mut host);

    assert_eq!(host.findings.len(), 1, "应上报 1 个 finding");
    assert_eq!(host.findings[0].title, "wasm-finding");
    assert!(host.findings[0].url.contains("t.test"));
    assert!(
        host.logs.iter().any(|(_, m)| m.contains("wasm saw flow")),
        "应收到 wasm 的日志"
    );
}

#[test]
fn on_request_can_drop() {
    let ext = load(MANIFEST, &[("scry_on_request", r#"{"action":"drop"}"#)]);
    let mut host = TestHost::default();
    let mut flow = HttpFlow::request("GET", "https", "t.test", 443, "/", vec![], vec![]);
    let act = ext.on_request(&mut flow, &mut host);
    assert!(matches!(act, HookAction::Drop), "应丢弃该请求");
}

#[test]
fn on_response_can_short_circuit() {
    // body=[104,105] = "hi"
    let reply = r#"{"action":"respond","response":{"status":418,"headers":[["X-Wasm","1"]],"body":[104,105]}}"#;
    let ext = load(MANIFEST, &[("scry_on_response", reply)]);
    let mut host = TestHost::default();
    let mut flow = HttpFlow::request("GET", "https", "t.test", 443, "/", vec![], vec![]);
    flow.status = 200;
    match ext.on_response(&mut flow, &mut host) {
        HookAction::Respond(r) => {
            assert_eq!(r.status, 418);
            assert_eq!(r.body, b"hi");
            assert!(r.headers.iter().any(|(k, v)| k == "X-Wasm" && v == "1"));
        }
        other => panic!("应短路自造响应,实际:{other:?}"),
    }
}

#[test]
fn on_request_can_rewrite_flow() {
    let reply = r#"{"action":"continue","flow":{"ts":0,"method":"GET","scheme":"https","host":"t.test","port":443,"path":"/wasm-rewrote","req_headers":[["X-Wasm-Mark","yes"]],"req_body":[],"status":0,"resp_headers":[],"resp_body":[],"duration_ms":0}}"#;
    let ext = load(MANIFEST, &[("scry_on_request", reply)]);
    let mut host = TestHost::default();
    let mut flow = HttpFlow::request("GET", "https", "t.test", 443, "/orig", vec![], vec![]);
    let act = ext.on_request(&mut flow, &mut host);
    assert!(matches!(act, HookAction::Continue));
    assert_eq!(flow.path, "/wasm-rewrote", "flow 应被 wasm 改写");
    assert_eq!(flow.req_header("x-wasm-mark"), Some("yes"));
}

#[test]
fn missing_hook_is_noop() {
    // 只声明 manifest、不导出任何钩子 → 钩子调用应放行且无副作用。
    let ext = load(MANIFEST, &[]);
    let mut host = TestHost::default();
    let mut flow = HttpFlow::request("GET", "https", "t.test", 443, "/", vec![], vec![]);
    let act = ext.on_request(&mut flow, &mut host);
    assert!(matches!(act, HookAction::Continue));
    ext.on_flow_complete(&flow, &mut host);
    assert!(host.findings.is_empty());
    assert!(host.logs.is_empty(), "无钩子时不应有任何副作用");
}

#[test]
fn infinite_loop_fails_open_via_fuel() {
    // on_request 是死循环 → 应被 fuel 配额打断 → fail-open 放行 + 一条警告日志。
    let manifest = r#"{"manifest":{"id":"loop","name":"loop","abi":1,"hooks":["on_request"]}}"#;
    let wat = format!(
        "(module\n  (memory (export \"memory\") 1)\n  (data (i32.const 0) \"{}\")\n  (global $b (mut i32) (i32.const 1024))\n  (func (export \"scry_alloc\") (param $n i32) (result i32)\n    (local $p i32) (local.set $p (global.get $b)) (global.set $b (i32.add (global.get $b) (local.get $n))) (local.get $p))\n  (func (export \"scry_manifest\") (result i64)\n    (i64.or (i64.shl (i64.const 0) (i64.const 32)) (i64.const {})))\n  (func (export \"scry_on_request\") (param i32 i32) (result i64)\n    (loop $l (br $l))\n    (i64.const 0)))\n",
        wat_escape(manifest),
        manifest.len()
    );
    // 给较小的 fuel 让死循环尽快触发(仍够实例化 + 写入)。
    let ext = WasmExt::from_bytes(wat.as_bytes(), 5_000_000).expect("应加载");
    let mut host = TestHost::default();
    let mut flow = HttpFlow::request("GET", "https", "t.test", 443, "/", vec![], vec![]);
    let act = ext.on_request(&mut flow, &mut host);
    assert!(matches!(act, HookAction::Continue), "fuel 耗尽应 fail-open 放行");
    assert!(
        host.logs.iter().any(|(lvl, _)| *lvl == LogLevel::Warning),
        "应记录一条放行警告"
    );
}

#[test]
fn abi_mismatch_rejected() {
    let manifest = r#"{"manifest":{"id":"bad","name":"bad","abi":999,"hooks":[]}}"#;
    let wat = build_wat(manifest, &[]);
    let r = WasmExt::from_bytes(wat.as_bytes(), DEFAULT_FUEL);
    assert!(r.is_err(), "ABI 不匹配应拒绝加载");
}

#[test]
fn bad_wasm_bytes_rejected() {
    // 非法字节 → 编译失败。
    let r = WasmExt::from_bytes(b"\x00not a wasm module", DEFAULT_FUEL);
    assert!(r.is_err());
}

/// 端到端:加载**真实编译的** Rust→wasm 示例扩展(`extensions/wasm-demo`),
/// 走完整 ABI(alloc 写入 flow JSON → 钩子 → serde_json 解析改写 → 宿主读回 reply)。
/// 未构建 `wasm_demo.wasm` 时优雅跳过(运行 `extensions/wasm-demo/build.sh` 生成)。
#[test]
fn real_wasm_demo_module() {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../extensions/wasm-demo/wasm_demo.wasm");
    if !p.exists() {
        eprintln!("跳过:未构建 wasm_demo.wasm(运行 extensions/wasm-demo/build.sh)");
        return;
    }
    let ext = WasmExt::load(&p, DEFAULT_FUEL).expect("加载真实 wasm-demo 失败");
    assert_eq!(ext.manifest().id, "wasm-demo");
    assert_eq!(ext.manifest().kind, ExtKind::Wasm);

    let mut host = TestHost::default();
    // on_request:真实 wasm 模块用 serde_json 给请求加 X-Scry-Wasm 头。
    let mut flow = HttpFlow::request("GET", "https", "t.test", 443, "/", vec![], vec![]);
    let act = ext.on_request(&mut flow, &mut host);
    assert!(matches!(act, HookAction::Continue));
    assert_eq!(flow.req_header("x-scry-wasm"), Some("1"));

    // on_flow_complete:500 响应应上报一个 finding。
    let mut bad = HttpFlow::request("GET", "https", "t.test", 443, "/oops", vec![], vec![]);
    bad.status = 500;
    ext.on_flow_complete(&bad, &mut host);
    assert_eq!(host.findings.len(), 1);
    assert!(host.findings[0].url.contains("/oops"));
}
