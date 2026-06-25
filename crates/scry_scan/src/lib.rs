//! Scry 扫描引擎 —— 被动 + 主动安全扫描的**纯函数内核**(不碰存储;主动发送由 UI 复用
//! `scry_proxy::replay`)。设计与 `scry_decode` / `scry_analyze` 一致:只读、可单测。
//!
//! 模块:
//! - [`types`]:[`Severity`] 严重度 + [`Finding`] 发现项。
//! - [`passive`]:对已抓到的 [`scry_core::HttpFlow`] 跑只读规则([`scan_flow`] / [`scan_flows`])。
//! - [`active`]:由基准流生成主动探测变异请求([`generate_probes`])+ 命中判定([`evaluate`])。
//! - [`discovery`]:Nikto 式「敏感文件 / 路径」主动探测(内置高危路径库 + soft-404 基线)。
//! - [`authz`]:越权 / 访问控制测试(Autorize 式多身份重放比对:未授权访问 / 水平+垂直越权)。
//! - [`oob`]:OOB 带外盲注探测生成(盲 SSRF/RCE/SQLi/XXE/盲打 XSS;配合 `scry_oob` 客户端确认回连)。

pub mod active;
pub mod authz;
pub mod discovery;
pub mod oob;
pub mod param_miner;
pub mod passive;
pub mod types;

pub use active::{evaluate, generate_probes, Probe, ProbeKind};
pub use authz::{apply_identity, AuthVerdict, Identity};
pub use discovery::{evaluate_path, origins, probe_flow, Origin, SensitivePath, Sig};
pub use oob::{generate_oob_probes, OobProbe, OobProbeKind};
pub use param_miner::{inject_query, make_probes, reflected, ParamProbe, PARAM_WORDLIST};
pub use passive::{scan_flow, scan_flows};
pub use types::{Finding, Severity};
