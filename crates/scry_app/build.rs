//! Windows 零环境出包关键:让 `wpcap.dll`(Npcap)**延迟加载**。
//!
//! `pcap` crate(被动嗅探 `scry_sniff` 用)在 Windows 上会把 `wpcap.dll` 写进**加载期**
//! (load-time)导入表。干净机器没装 Npcap 时,加载器在进程启动前就找不到 `wpcap.dll`,
//! 直接以 `0xC0000135`(STATUS_DLL_NOT_FOUND)闪退——连 `main` 都进不去。
//!
//! 解决:把 `wpcap.dll` 标成 `/DELAYLOAD`,只有真正调用 wpcap 函数(启动被动嗅探)时才加载。
//! 于是没装 Npcap 也能双击启动;被动嗅探入口在 `scry_sniff` 里先探测 `wpcap.dll` 是否存在,
//! 缺失则友好报错而非崩溃。MITM 代理 / 扫描 / 重放等核心功能与 Npcap 无关。
//!
//! `delayimp.lib` 提供延迟加载辅助 `__delayLoadHelper2`(随 MSVC 工具链分发)。只对最终
//! 可执行文件生效(`-bins`),不影响构建脚本 / 依赖的链接。
fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        println!("cargo:rustc-link-arg-bins=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-arg-bins=delayimp.lib");
    }
}
