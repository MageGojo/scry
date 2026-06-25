//! `scry_ext_api` —— 扩展系统的**契约层**(唯一真相源)。
//!
//! 纯类型 + trait,**无 IO**。被两边共用:
//! - [`scry_proxy`](../scry_proxy):在 MITM 接缝调用 [`ExtensionHost`](无行为时为 `None`)。
//! - `scry_app::ext`:实现 `ExtRegistry`(= [`ExtensionHost`]),fan-out 到各 [`Extension`]。
//!
//! 设计见 `docs/设计-扩展系统.md`。三种 Runner(builtin / native dylib / wasm / process)
//! 最终都被适配成同一个 [`Extension`] 契约,宿主只认 [`ExtensionHost`] 一个抽象。

use scry_core::HttpFlow;
use serde::{Deserialize, Serialize};

/// 契约 ABI 版本。native dylib 加载时必须匹配,否则拒绝加载(防 ABI 漂移崩溃)。
pub const ABI_VERSION: u32 = 1;

/// 钩子返回的动作。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum HookAction {
    /// 放行(`flow` 可能已被原地修改)。
    #[default]
    Continue,
    /// 丢弃:不转发,直接断连。
    Drop,
    /// 短路:由扩展直接给客户端造一个响应(Match&Replace / mock)。
    Respond(SynthResponse),
    /// 转人工拦截队列(对接将来的 Intercept 断点)。
    Pause,
}

/// 扩展短路时自造的响应。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// 日志级别(与 `scry_app::logger::LogLevel` 对齐;此处独立定义,避免对 app 的反向依赖)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Error,
    Warning,
    Success,
    Info,
    Debug,
}

/// 严重度(与 `scry_scan` 的发现模型对齐的子集)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// 扩展产生的一条「发现」(被动/主动扫描),由宿主汇聚后送 Scanner / Logger。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub url: String,
}

/// 扩展主动发包的请求(经 [`HostServices::send_request`] 走 scry 自己的出网,不直接拿 socket)。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtRequest {
    #[serde(default)]
    pub method: String,
    /// 完整 URL,如 `https://host[:port]/path?q=1`。
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: Vec<u8>,
}

/// [`HostServices::send_request`] 的结果(`error` 非空表示发送失败,`status`=0)。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtResponse {
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: Vec<u8>,
    #[serde(default)]
    pub error: Option<String>,
}

impl ExtResponse {
    /// 构造一个错误结果(发送失败 / 不支持)。
    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            status: 0,
            headers: Vec::new(),
            body: Vec::new(),
            error: Some(msg.into()),
        }
    }
}

/// 扩展运行时类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtKind {
    /// 第一方,进程内直接 `impl Extension`(随包)。
    Builtin,
    /// 本地动态库(C-ABI,`libloading`)—— 最快,仅可信。
    Native,
    /// WASM 沙箱(wasmtime)—— 安全,第三方默认推荐。
    Wasm,
    /// 外部进程(stdio JSON/msgpack RPC)—— 崩溃隔离,Python/任意语言。
    Process,
}

/// 扩展权限(安装时按此提示授权;高危项 `TrafficModify`/`NetOutbound`/`Fs*` 明确告知)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    /// 读流量(请求/响应内容)。
    TrafficRead,
    /// 改流量(改写 / 丢弃 / 短路)。
    TrafficModify,
    /// 主动外联(经 `HostServices::send_request` 走 scry 自己的出网,不直接拿 socket)。
    NetOutbound,
    /// 读写扩展私有存储。
    Storage,
    /// 读文件(限定前缀路径)。
    FsRead(String),
    /// 写文件(限定前缀路径)。
    FsWrite(String),
}

/// 设置项类型(驱动 Extender 页自动渲染表单,对标 sing-box manifest 的 Input/Switch)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SettingKind {
    Text,
    Number,
    Switch,
    Select(Vec<String>),
}

/// 一个可配置项(由 manifest 声明,Extender 页据此生成控件)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingField {
    pub key: String,
    pub label: String,
    pub kind: SettingKind,
    /// 默认值(统一以字符串承载;数字/开关按需解析)。
    pub default: String,
}

/// 扩展清单(builtin 在 Rust 里构造;native/wasm/process 从 `manifest.yaml` 解析)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub description: String,
    pub kind: ExtKind,
    /// 该扩展声明的契约 ABI 版本;须 == [`ABI_VERSION`]。
    pub abi: u32,
    #[serde(default)]
    pub permissions: Vec<Permission>,
    /// 声明用到的钩子名(如 `on_request` / `on_flow_complete` / `scanner_check`)。
    #[serde(default)]
    pub hooks: Vec<String>,
    #[serde(default)]
    pub settings_schema: Vec<SettingField>,
}

impl ExtManifest {
    /// 构造一个最小 builtin 清单(便于第一方扩展直接 new)。
    pub fn builtin(id: &str, name: &str, version: &str, description: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            author: "scry".to_string(),
            description: description.to_string(),
            kind: ExtKind::Builtin,
            abi: ABI_VERSION,
            permissions: Vec::new(),
            hooks: Vec::new(),
            settings_schema: Vec::new(),
        }
    }

    pub fn with_permissions(mut self, perms: Vec<Permission>) -> Self {
        self.permissions = perms;
        self
    }

    pub fn with_hooks(mut self, hooks: &[&str]) -> Self {
        self.hooks = hooks.iter().map(|s| s.to_string()).collect();
        self
    }
}

/// 宿主回调:扩展通过它调用 scry 的能力。
///
/// 关键:实现必须能从 **proxy 线程**调用(代理在独立 tokio 线程跑),
/// 因此真实实现是线程安全的事件汇聚(`Arc<Mutex<…>>` / channel),UI 主线程再排空刷新。
pub trait HostServices {
    /// 写一条日志(→ Logger 页)。
    fn log(&mut self, level: LogLevel, msg: &str);
    /// 上报一条发现(→ Scanner)。
    fn emit_finding(&mut self, finding: Finding);
    /// 读该扩展的配置项(来自 manifest `settings_schema` + 用户填值)。
    fn get_setting(&self, key: &str) -> Option<String> {
        let _ = key;
        None
    }
    /// 写扩展私有持久化 KV。
    fn set_kv(&mut self, key: &str, val: &str) {
        let _ = (key, val);
    }

    /// 主动发一个 HTTP(S) 请求(经 scry 自己的出网 / 上游 → 复用 `scry_proxy::replay`),用于主动扫描 / 取数据。
    ///
    /// 需要 `net.outbound` 权限。默认实现表示「该宿主不支持」(如纯展示场景)。
    fn send_request(&mut self, req: ExtRequest) -> ExtResponse {
        let _ = req;
        ExtResponse::error("该宿主不支持 send_request")
    }
}

/// 单个扩展契约。builtin 直接实现;native/wasm/process 由各自 Runner 适配成它。
///
/// 默认实现都是「不参与」(Continue / no-op),扩展只需覆写关心的钩子。
pub trait Extension: Send + Sync {
    fn manifest(&self) -> &ExtManifest;

    /// 内联:转发前,可改 `method/path/headers/body`。
    fn on_request(&self, _flow: &mut HttpFlow, _host: &mut dyn HostServices) -> HookAction {
        HookAction::Continue
    }

    /// 内联:回传前,可改 `status/headers/body`(响应体改写见设计 §6,P1 落地)。
    fn on_response(&self, _flow: &mut HttpFlow, _host: &mut dyn HostServices) -> HookAction {
        HookAction::Continue
    }

    /// 被动:落盘后对副本只读调用(给扫描/索引/日志,**绝不阻塞流量**)。
    fn on_flow_complete(&self, _flow: &HttpFlow, _host: &mut dyn HostServices) {}
}

/// 宿主聚合契约:`scry_proxy` **只认这一个抽象**(挂在 `ProxyConfig.hooks`)。
///
/// `scry_app::ext::ExtRegistry` 实现它:按加载顺序 fan-out 到各 [`Extension`],
/// 内部用自己的 [`HostServices`] 收集副作用。代理侧只传 `&mut HttpFlow`,不感知 HostServices。
pub trait ExtensionHost: Send + Sync {
    fn on_request(&self, _flow: &mut HttpFlow) -> HookAction {
        HookAction::Continue
    }
    fn on_response(&self, _flow: &mut HttpFlow) -> HookAction {
        HookAction::Continue
    }
    fn on_flow_complete(&self, _flow: &HttpFlow) {}

    /// 是否有启用的扩展声明了 `on_response` 钩子。
    ///
    /// 代理据此决定**是否重建响应字节**(改写响应需丢弃 chunked 框架 / 重算 Content-Length)。
    /// 默认 `false` → 代理按原貌转发 `raw`,**对未用响应钩子的场景零保真损失**。
    fn wants_response_hook(&self) -> bool {
        false
    }

    /// Map Remote:在**连接上游之前**询问是否把目标 `host:port` 重定向到别处。
    ///
    /// 返回 `Some((新 host, 新 port))` 则代理连到新目标(HTTPS 下叶子证书仍按**原** host 签发,
    /// 客户端无感知);`None` = 不重定向。默认不重定向。
    fn remap_target(&self, _host: &str, _port: u16) -> Option<(String, u16)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 收集副作用的测试用 HostServices。
    #[derive(Default)]
    struct TestHost {
        logs: Vec<String>,
        findings: usize,
    }
    impl HostServices for TestHost {
        fn log(&mut self, _level: LogLevel, msg: &str) {
            self.logs.push(msg.to_string());
        }
        fn emit_finding(&mut self, _f: Finding) {
            self.findings += 1;
        }
    }

    /// 给所有响应加一个标记头、并对每条流量上报一次的演示扩展。
    struct TagExt {
        m: ExtManifest,
    }
    impl Extension for TagExt {
        fn manifest(&self) -> &ExtManifest {
            &self.m
        }
        fn on_request(&self, flow: &mut HttpFlow, host: &mut dyn HostServices) -> HookAction {
            flow.req_headers
                .push(("X-Scry-Ext".to_string(), self.m.id.clone()));
            host.log(LogLevel::Debug, "tagged request");
            HookAction::Continue
        }
        fn on_flow_complete(&self, _flow: &HttpFlow, host: &mut dyn HostServices) {
            host.emit_finding(Finding {
                severity: Severity::Info,
                title: "seen".into(),
                detail: "demo".into(),
                url: _flow.url(),
            });
        }
    }

    #[test]
    fn default_host_is_noop() {
        struct Noop;
        impl ExtensionHost for Noop {}
        let mut f = HttpFlow::request("GET", "https", "h", 443, "/", vec![], vec![]);
        assert!(matches!(Noop.on_request(&mut f), HookAction::Continue));
        Noop.on_flow_complete(&f);
        assert!(f.req_headers.is_empty());
    }

    #[test]
    fn extension_can_mutate_and_report() {
        let ext = TagExt {
            m: ExtManifest::builtin("tag", "Tag", "0.1.0", "demo")
                .with_hooks(&["on_request", "on_flow_complete"]),
        };
        let mut host = TestHost::default();
        let mut f = HttpFlow::request("GET", "https", "h", 443, "/", vec![], vec![]);
        let act = ext.on_request(&mut f, &mut host);
        assert!(matches!(act, HookAction::Continue));
        assert_eq!(f.req_header("x-scry-ext"), Some("tag"));
        ext.on_flow_complete(&f, &mut host);
        assert_eq!(host.findings, 1);
        assert_eq!(host.logs.len(), 1);
    }

    #[test]
    fn manifest_abi_matches() {
        let m = ExtManifest::builtin("x", "X", "0.1.0", "");
        assert_eq!(m.abi, ABI_VERSION);
        assert_eq!(m.kind, ExtKind::Builtin);
    }
}
