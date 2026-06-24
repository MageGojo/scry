//! `scry_ext_host` —— 扩展**运行时(Runner)宿主层**。
//!
//! 把各类外部扩展适配成统一的 [`scry_ext_api::Extension`],交给 `scry_app::ext::ExtRegistry` 装载。
//! **不依赖 gpui**,可独立单测(见 `tests/`)。
//!
//! - 外部进程 + stdio JSON-RPC —— [`ProcessExt`](process::ProcessExt)(P1,Python⭐/任意语言)。
//! - WASM 沙箱(wasmtime)—— [`WasmExt`](wasm::WasmExt)(P2,强隔离,第三方默认推荐)。
//! - native dylib(libloading)—— 后续加同级模块(P3)。
//!
//! 两类外部 Runner 的 reply / manifest **JSON 协议完全一致**,共用 [`wire`] 模块。
//!
//! 发现约定:扫描某目录下的每个子目录,含 `manifest.json` 即视为一个扩展。二选一:
//! ```json
//! { "command": ["python3", "main.py"], "timeout_ms": 1500 }   // 进程扩展
//! { "wasm": "ext.wasm", "fuel": 200000000 }                   // WASM 沙箱扩展
//! ```
//! 扩展的名字 / 版本 / 钩子 / 权限由运行时在 `manifest` 握手时自述。

mod process;
mod wasm;
mod wire;

pub use process::ProcessExt;
pub use wasm::{WasmExt, DEFAULT_FUEL};

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use scry_ext_api::Extension;

/// `manifest.json`(发现用;描述「怎么拉起」,扩展自身元数据走运行时握手)。
///
/// 二选一:声明了 `wasm`(相对扩展目录的 `.wasm` 路径)→ 按 WASM 沙箱加载;否则用 `command`(外部进程)。
#[derive(Deserialize)]
struct DiscoverManifest {
    /// 进程扩展拉起命令,如 `["python3", "main.py"]`(相对扩展目录)。
    #[serde(default)]
    command: Vec<String>,
    /// WASM 扩展模块文件(相对扩展目录,如 `ext.wasm`);给出即按 WASM 沙箱加载。
    #[serde(default)]
    wasm: Option<String>,
    /// 进程扩展单次 RPC 超时(毫秒)。
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    /// WASM 扩展每次钩子的 fuel 配额(指令数上限,防死循环)。
    #[serde(default = "default_fuel")]
    fuel: u64,
}

fn default_timeout_ms() -> u64 {
    1500
}

fn default_fuel() -> u64 {
    DEFAULT_FUEL
}

/// 发现一个扩展目录的结果(成功 = 已握手的扩展;失败 = 原因,供 UI 展示)。
pub struct Discovered {
    pub dir_name: String,
    pub result: Result<Box<dyn Extension>>,
}

/// 扫描 `dir` 下所有「含 `manifest.json` 的子目录」,逐个尝试拉起为进程扩展。
pub fn discover(dir: &Path) -> Vec<Discovered> {
    let mut out = Vec::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return out,
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest = path.join("manifest.json");
        if !manifest.exists() {
            continue;
        }
        let dir_name = entry.file_name().to_string_lossy().to_string();
        let result = load_one(&path, &manifest);
        out.push(Discovered { dir_name, result });
    }
    out
}

fn load_one(dir: &Path, manifest_path: &Path) -> Result<Box<dyn Extension>> {
    let txt = std::fs::read_to_string(manifest_path).context("读 manifest.json 失败")?;
    let dm: DiscoverManifest = serde_json::from_str(&txt).context("解析 manifest.json 失败")?;
    // WASM 沙箱优先:声明了 wasm 文件即按 WASM 加载(强隔离,第三方默认)。
    if let Some(rel) = &dm.wasm {
        let wasm_path = dir.join(rel);
        let ext = WasmExt::load(&wasm_path, dm.fuel)?;
        return Ok(Box::new(ext));
    }
    if dm.command.is_empty() {
        anyhow::bail!("manifest.json 既未声明 wasm,也未给出 command");
    }
    let ext = ProcessExt::spawn(dir, &dm.command, Duration::from_millis(dm.timeout_ms))?;
    Ok(Box::new(ext))
}

/// 默认扩展目录 `~/.scry/extensions`(不存在则 `None`,默认不加载任何进程扩展)。
pub fn default_ext_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let dir = PathBuf::from(home).join(".scry").join("extensions");
    dir.is_dir().then_some(dir)
}
