//! 扩展**线路协议**(JSON)—— 进程 Runner(`process`)与 WASM Runner(`wasm`)复用同一套
//! `reply` / `manifest` 反序列化结构与副作用应用逻辑。
//!
//! 两个 Runner 的差异只在「运输层」:进程走 stdio JSONL,WASM 走线性内存里的 JSON 字节;
//! **载荷格式完全一致**,故抽到这里,避免两边定义漂移。
//!
//! reply(ext → host):
//! ```json
//! {"action":"continue|drop|respond|pause","flow":{…改写后…},
//!  "response":{"status":…,"headers":[…],"body":[…]},
//!  "logs":[{"level":"Info","msg":"…"}],"findings":[{…}]}
//! ```
//! manifest(握手):
//! ```json
//! {"manifest":{"id":"x","name":"X","version":"0.1.0","abi":1,
//!  "hooks":["on_request"],"permissions":["traffic.modify"]}}
//! ```

use anyhow::{anyhow, Result};
use serde::Deserialize;

use scry_core::HttpFlow;
use scry_ext_api::{
    ExtKind, ExtManifest, Finding, HookAction, HostServices, LogLevel, Permission, SynthResponse,
    ABI_VERSION,
};

/// 钩子回复(`on_request` / `on_response` / `on_flow_complete` 共用)。
#[derive(Deserialize, Default)]
pub(crate) struct HookReply {
    #[allow(dead_code)]
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub action: WireAction,
    /// 改写后的 flow(`None` = 不改)。
    #[serde(default)]
    pub flow: Option<HttpFlow>,
    /// 短路自造响应(配合 `action == Respond`)。
    #[serde(default)]
    pub response: Option<SynthResponse>,
    #[serde(default)]
    pub logs: Vec<WireLog>,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

/// 线路上的动作枚举(小写字符串)。
#[derive(Deserialize, Default, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub(crate) enum WireAction {
    #[default]
    Continue,
    Drop,
    Respond,
    Pause,
}

/// 一条日志(级别为字符串,大小写不敏感解析)。
#[derive(Deserialize)]
pub(crate) struct WireLog {
    #[serde(default = "default_level")]
    pub level: String,
    #[serde(default)]
    pub msg: String,
}

fn default_level() -> String {
    "Info".to_string()
}

/// 握手回复外层(`{"manifest":{…}}`)。
#[derive(Deserialize)]
pub(crate) struct ManifestReply {
    pub manifest: WireManifest,
}

/// 扩展自述的清单(运行时握手时给出)。
#[derive(Deserialize)]
pub(crate) struct WireManifest {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub abi: u32,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub hooks: Vec<String>,
}

/// 把线路动作 + 可选短路响应映射成宿主的 [`HookAction`]。
pub(crate) fn map_action(action: WireAction, response: Option<SynthResponse>) -> HookAction {
    match action {
        WireAction::Continue => HookAction::Continue,
        WireAction::Drop => HookAction::Drop,
        WireAction::Pause => HookAction::Pause,
        // 声明了 Respond 却没给响应体 → 退化为放行(不卡流量)。
        WireAction::Respond => response.map(HookAction::Respond).unwrap_or(HookAction::Continue),
    }
}

/// 把扩展回复里的日志 / 发现应用到宿主回调。
pub(crate) fn apply_side_effects(
    logs: Vec<WireLog>,
    findings: Vec<Finding>,
    host: &mut dyn HostServices,
) {
    for l in logs {
        host.log(parse_level(&l.level), &l.msg);
    }
    for f in findings {
        host.emit_finding(f);
    }
}

/// 由扩展自述的 [`WireManifest`] 构造宿主 [`ExtManifest`](校验 ABI、打上运行时类型)。
pub(crate) fn manifest_from_wire(wm: WireManifest, kind: ExtKind) -> Result<ExtManifest> {
    if wm.abi != 0 && wm.abi != ABI_VERSION {
        return Err(anyhow!(
            "扩展 ABI={} 与宿主 ABI={} 不匹配",
            wm.abi,
            ABI_VERSION
        ));
    }
    let mut m = ExtManifest::builtin(&wm.id, &wm.name, &wm.version, &wm.description);
    m.kind = kind;
    m.abi = ABI_VERSION;
    m.hooks = wm.hooks;
    m.permissions = wm.permissions.iter().filter_map(|s| parse_perm(s)).collect();
    Ok(m)
}

/// 权限字符串 → [`Permission`](未识别则忽略)。
pub(crate) fn parse_perm(s: &str) -> Option<Permission> {
    match s {
        "traffic.read" => Some(Permission::TrafficRead),
        "traffic.modify" => Some(Permission::TrafficModify),
        "net.outbound" => Some(Permission::NetOutbound),
        "storage" => Some(Permission::Storage),
        other => other
            .strip_prefix("fs.read:")
            .map(|p| Permission::FsRead(p.to_string()))
            .or_else(|| {
                other
                    .strip_prefix("fs.write:")
                    .map(|p| Permission::FsWrite(p.to_string()))
            }),
    }
}

/// 日志级别字符串 → [`LogLevel`](大小写不敏感,未知归 `Info`)。
pub(crate) fn parse_level(s: &str) -> LogLevel {
    match s.to_ascii_lowercase().as_str() {
        "error" => LogLevel::Error,
        "warning" | "warn" => LogLevel::Warning,
        "success" => LogLevel::Success,
        "debug" => LogLevel::Debug,
        _ => LogLevel::Info,
    }
}
