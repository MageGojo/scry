//! 集成测试:用真实 `python3` 拉起示例扩展(`extensions/py-demo`),验证 stdio JSON-RPC 往返:
//! manifest 握手 / on_request 改写请求 / on_flow_complete 上报 finding。
//! 若环境无 `python3` 则优雅跳过(不算失败)。

use std::path::PathBuf;
use std::process::Command;

use scry_core::HttpFlow;
use scry_ext_api::{ExtKind, ExtRequest, ExtResponse, Finding, HookAction, HostServices, LogLevel};

#[derive(Default)]
struct TestHost {
    logs: Vec<(LogLevel, String)>,
    findings: Vec<Finding>,
    /// 记录扩展反向调用 send_request 的次数与最后一次的 URL。
    send_calls: usize,
    last_url: String,
}

impl HostServices for TestHost {
    fn log(&mut self, level: LogLevel, msg: &str) {
        self.logs.push((level, msg.to_string()));
    }
    fn emit_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }
    fn send_request(&mut self, req: ExtRequest) -> ExtResponse {
        self.send_calls += 1;
        self.last_url = req.url;
        ExtResponse {
            status: 200,
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: b"probed-ok".to_vec(),
            error: None,
        }
    }
}

fn python_available() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn ext_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = scry/crates/scry_ext_host → 上两级到 scry/,再进 extensions/
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../extensions")
}

#[test]
fn python_extension_roundtrip() {
    if !python_available() {
        eprintln!("跳过:环境无 python3");
        return;
    }

    let found = scry_ext_host::discover(&ext_root());
    let demo = found
        .into_iter()
        .find(|d| d.dir_name == "py-demo")
        .expect("未发现 py-demo 扩展目录");
    let ext = demo.result.expect("py-demo 加载失败(握手?)");

    // 握手:进程自述的 manifest 应被解析为 Process 类型。
    assert_eq!(ext.manifest().id, "py-demo");
    assert_eq!(ext.manifest().kind, ExtKind::Process);
    assert!(ext.manifest().hooks.iter().any(|h| h == "on_request"));

    let mut host = TestHost::default();

    // on_request:Python 侧给请求加 X-Scry-Py 头,改写应回灌到 flow。
    let mut flow = HttpFlow::request("GET", "https", "example.com", 443, "/", vec![], vec![]);
    let act = ext.on_request(&mut flow, &mut host);
    assert!(matches!(act, HookAction::Continue));
    assert_eq!(flow.req_header("x-scry-py"), Some("1"));
    assert!(!host.logs.is_empty(), "应收到 Python 的调试日志");

    // on_flow_complete:5xx 响应应触发一个 finding。
    let mut bad = HttpFlow::request("GET", "https", "example.com", 443, "/oops", vec![], vec![]);
    bad.status = 500;
    ext.on_flow_complete(&bad, &mut host);
    assert_eq!(host.findings.len(), 1, "5xx 应上报一个 finding");
    assert!(host.findings[0].url.contains("/oops"));
}

#[test]
fn python_active_probe_calls_host_send_request() {
    if !python_available() {
        eprintln!("跳过:环境无 python3");
        return;
    }

    let found = scry_ext_host::discover(&ext_root());
    let demo = found
        .into_iter()
        .find(|d| d.dir_name == "py-demo")
        .expect("未发现 py-demo 扩展目录");
    let ext = demo.result.expect("py-demo 加载失败");
    // 应声明了 net.outbound 权限。
    assert!(ext
        .manifest()
        .permissions
        .iter()
        .any(|p| matches!(p, scry_ext_api::Permission::NetOutbound)));

    let mut host = TestHost::default();
    // 路径 /active-probe 触发扩展在钩子内**反向调用** host.send_request(双向 RPC)。
    let probe = HttpFlow::request("GET", "https", "demo.test", 443, "/active-probe", vec![], vec![]);
    ext.on_flow_complete(&probe, &mut host);

    assert_eq!(host.send_calls, 1, "扩展应反向调用 host.send_request 一次");
    assert_eq!(host.last_url, "https://example.com/");
    // 扩展应把宿主返回的 status(200)写进日志 / finding。
    assert!(
        host.logs.iter().any(|(_, m)| m.contains("200"))
            || host.findings.iter().any(|f| f.detail.contains("200")),
        "扩展应记录主动探测得到的 200"
    );
}
