//! WASM 沙箱扩展运行时(Runner ②)—— 用 [`wasmtime`] 在强隔离沙箱里跑第三方扩展。
//!
//! **为什么是默认推荐的第三方运行时**:WASM 模块默认**无任何宿主能力**(不开 WASI、不给 import),
//! 只能做纯计算 —— 看不到文件系统 / 网络 / 进程,天生安全;再叠加 **fuel**(指令配额,防死循环)
//! 与**内存上限**(防内存炸弹),即使装了恶意/有 bug 的扩展也不会拖垮 scry 或泄露数据。
//!
//! ## ABI(core wasm module,非 component model)
//! 选 core module + 线性内存里的 JSON,而不是 component/WIT:① 测试可内联 WAT、免 `wit-bindgen` 工具链;
//! ② 与 [`crate::process`] 进程 Runner 的 JSON 协议同构(reply 见 [`crate::wire`])。
//!
//! 扩展模块需导出(缺哪个钩子即视为「不关心、放行」):
//! - `memory`:线性内存(名必须为 `memory`)。
//! - `scry_alloc(len: i32) -> i32`:在内存里分配 `len` 字节、返回指针(宿主写入输入 JSON 用)。
//! - `scry_manifest() -> i64`:返回 manifest JSON 的 `(ptr<<32)|len`(打包)。
//! - `scry_on_request(ptr,len) -> i64` / `scry_on_response(ptr,len) -> i64` /
//!   `scry_on_flow_complete(ptr,len) -> i64`:入参是 `HttpFlow` JSON 的指针/长度,
//!   返回 reply JSON 的打包指针/长度。
//!
//! 打包约定:`u64` 高 32 位 = 指针,低 32 位 = 字节长度。
//!
//! ## 并发
//! 每次钩子调用都**新建 `Store` + 实例**(`Engine`/`Module` 跨线程共享、只编译一次)。实例间零共享状态,
//! 故 `&self` 钩子可被代理多 worker **并发调用而无需加锁**(对比进程 Runner 要 `Mutex<conn>`)。

use std::path::Path;

use anyhow::{anyhow, bail, Result};
use wasmtime::{
    Config, Engine, Instance, Memory, Module, ResourceLimiter, Store, StoreLimits,
    StoreLimitsBuilder,
};

use scry_core::HttpFlow;
use scry_ext_api::{ExtKind, ExtManifest, Extension, HookAction, HostServices, LogLevel};

use crate::wire::{self, HookReply, ManifestReply};

/// 默认 fuel 配额(WASM 指令数上限,防死循环;约 2 亿条,正常钩子远用不到)。
pub const DEFAULT_FUEL: u64 = 200_000_000;
/// 单个 WASM 实例线性内存上限(防内存炸弹)。
const MAX_MEMORY: usize = 64 * 1024 * 1024;
/// 钩子回复 JSON 的最大字节数(防越界读 / OOM)。
const MAX_REPLY: usize = 16 * 1024 * 1024;

/// 一个由 WASM 模块承载的扩展。
pub struct WasmExt {
    manifest: ExtManifest,
    engine: Engine,
    /// 已编译模块(线程安全,实例化时零编译开销)。
    module: Module,
    fuel: u64,
}

impl WasmExt {
    /// 从 `.wasm` 文件加载并完成 manifest 握手。
    pub fn load(wasm_path: &Path, fuel: u64) -> Result<Self> {
        let bytes = std::fs::read(wasm_path)
            .map_err(|e| anyhow!("读 WASM 文件 {} 失败:{e}", wasm_path.display()))?;
        Self::from_bytes(&bytes, fuel)
    }

    /// 从字节(`.wasm` 二进制,或开启 `wat` feature 时的 WAT 文本)编译并握手。
    pub fn from_bytes(bytes: &[u8], fuel: u64) -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true); // 启用 fuel,配合 Store::set_fuel 限制执行
        let engine = Engine::new(&config).map_err(|e| anyhow!("创建 WASM 引擎失败:{e}"))?;
        let module = Module::new(&engine, bytes).map_err(|e| anyhow!("编译 WASM 模块失败:{e}"))?;
        let mut ext = Self {
            manifest: ExtManifest::builtin("wasm", "wasm", "0.0.0", ""),
            engine,
            module,
            fuel: fuel.max(1), // 0 fuel 会立即 trap,至少给 1
        };
        ext.manifest = ext.handshake()?;
        Ok(ext)
    }

    /// 新建一个隔离实例:`Store`(带内存上限 + fuel)+ 实例 + 取出 `memory` 导出。
    fn instantiate(&self) -> Result<(Store<StoreLimits>, Instance, Memory)> {
        let limits = StoreLimitsBuilder::new().memory_size(MAX_MEMORY).build();
        let mut store = Store::new(&self.engine, limits);
        store.limiter(|l| l as &mut dyn ResourceLimiter);
        store
            .set_fuel(self.fuel)
            .map_err(|e| anyhow!("设置 fuel 失败:{e}"))?;
        let instance = Instance::new(&mut store, &self.module, &[])
            .map_err(|e| anyhow!("实例化 WASM 失败:{e}"))?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow!("WASM 扩展未导出 memory"))?;
        Ok((store, instance, memory))
    }

    /// 调用无参导出 `scry_manifest`,读回 manifest JSON 字节。
    fn call_manifest(&self) -> Result<Vec<u8>> {
        let (mut store, instance, memory) = self.instantiate()?;
        let f = instance
            .get_typed_func::<(), i64>(&mut store, "scry_manifest")
            .map_err(|e| anyhow!("WASM 扩展缺少 scry_manifest 导出:{e}"))?;
        let packed = f
            .call(&mut store, ())
            .map_err(|e| anyhow!("调用 scry_manifest 失败:{e}"))?;
        read_packed(&store, &memory, packed)
    }

    /// 调用一个钩子导出:把 `input`(flow JSON)写进 wasm 内存 → 调 `export(ptr,len)->i64` → 读回 reply 字节。
    ///
    /// 导出不存在 → `Ok(None)`(该扩展不关心此钩子)。其它失败 → `Err`(上层 fail-open)。
    fn call_hook(&self, export: &str, input: &[u8]) -> Result<Option<Vec<u8>>> {
        let (mut store, instance, memory) = self.instantiate()?;
        // 钩子未导出 = 不关心此钩子 → no-op 放行。
        let func = match instance.get_typed_func::<(i32, i32), i64>(&mut store, export) {
            Ok(f) => f,
            Err(_) => return Ok(None),
        };
        if input.len() > i32::MAX as usize {
            bail!("输入过大({} 字节)", input.len());
        }
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "scry_alloc")
            .map_err(|e| anyhow!("WASM 扩展缺少 scry_alloc 导出:{e}"))?;
        let ptr = alloc
            .call(&mut store, input.len() as i32)
            .map_err(|e| anyhow!("调用 scry_alloc 失败:{e}"))?;
        if ptr < 0 {
            bail!("scry_alloc 返回非法指针 {ptr}");
        }
        memory
            .write(&mut store, ptr as usize, input)
            .map_err(|e| anyhow!("写入 WASM 内存失败:{e}"))?;
        let packed = func
            .call(&mut store, (ptr, input.len() as i32))
            .map_err(|e| anyhow!("调用 {export} 失败:{e}"))?;
        Ok(Some(read_packed(&store, &memory, packed)?))
    }

    /// 握手:实例化调 `scry_manifest` → 解析 → 校验 ABI、打上 `Wasm` 类型。
    fn handshake(&self) -> Result<ExtManifest> {
        let bytes = self.call_manifest()?;
        let reply: ManifestReply =
            serde_json::from_slice(&bytes).map_err(|e| anyhow!("解析 WASM manifest 失败:{e}"))?;
        wire::manifest_from_wire(reply.manifest, ExtKind::Wasm)
    }

    /// 内联钩子(on_request / on_response):序列化 flow → 调用 → 应用副作用 + 改写 flow + 映射动作;失败 fail-open。
    fn inline(&self, export: &str, flow: &mut HttpFlow, host: &mut dyn HostServices) -> HookAction {
        let input = match serde_json::to_vec(&*flow) {
            Ok(v) => v,
            Err(e) => {
                host.log(
                    LogLevel::Warning,
                    &format!("[{}] 序列化 flow 失败,放行:{e}", self.manifest.id),
                );
                return HookAction::Continue;
            }
        };
        match self.call_hook(export, &input) {
            Ok(None) => HookAction::Continue, // 钩子未导出
            Ok(Some(bytes)) => match serde_json::from_slice::<HookReply>(&bytes) {
                Ok(reply) => {
                    wire::apply_side_effects(reply.logs, reply.findings, host);
                    if let Some(nf) = reply.flow {
                        *flow = nf;
                    }
                    wire::map_action(reply.action, reply.response)
                }
                Err(e) => {
                    host.log(
                        LogLevel::Warning,
                        &format!("[{}] 解析 {export} 回复失败,放行:{e}", self.manifest.id),
                    );
                    HookAction::Continue
                }
            },
            Err(e) => {
                host.log(
                    LogLevel::Warning,
                    &format!("[{}] {export} 执行失败,放行:{e}", self.manifest.id),
                );
                HookAction::Continue // fail-open:坏扩展绝不卡死流量
            }
        }
    }
}

impl Extension for WasmExt {
    fn manifest(&self) -> &ExtManifest {
        &self.manifest
    }

    fn on_request(&self, flow: &mut HttpFlow, host: &mut dyn HostServices) -> HookAction {
        self.inline("scry_on_request", flow, host)
    }

    fn on_response(&self, flow: &mut HttpFlow, host: &mut dyn HostServices) -> HookAction {
        self.inline("scry_on_response", flow, host)
    }

    fn on_flow_complete(&self, flow: &HttpFlow, host: &mut dyn HostServices) {
        let input = match serde_json::to_vec(flow) {
            Ok(v) => v,
            Err(_) => return,
        };
        match self.call_hook("scry_on_flow_complete", &input) {
            Ok(Some(bytes)) => {
                if let Ok(reply) = serde_json::from_slice::<HookReply>(&bytes) {
                    wire::apply_side_effects(reply.logs, reply.findings, host);
                }
            }
            Ok(None) => {}
            Err(e) => host.log(
                LogLevel::Warning,
                &format!("[{}] on_flow_complete 失败(忽略):{e}", self.manifest.id),
            ),
        }
    }
}

/// 解打包指针/长度并从线性内存读出字节(带长度上限,防越界 / OOM)。
fn read_packed(store: &Store<StoreLimits>, memory: &Memory, packed: i64) -> Result<Vec<u8>> {
    let u = packed as u64;
    let ptr = (u >> 32) as usize;
    let len = (u & 0xffff_ffff) as usize;
    if len == 0 {
        return Ok(Vec::new());
    }
    if len > MAX_REPLY {
        bail!("WASM 返回数据过大({len} 字节)");
    }
    let mut buf = vec![0u8; len];
    memory
        .read(store, ptr, &mut buf)
        .map_err(|e| anyhow!("读 WASM 内存越界(ptr={ptr},len={len}):{e}"))?;
    Ok(buf)
}
