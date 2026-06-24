//! 根证书:一键安装信任 / 手动安装辅助 / 信任状态检查(macOS `security` + `osascript`)。
//!
//! - **一键**:`osascript ... with administrator privileges` 弹原生管理员密码框,把 `ca.pem`
//!   以 `trustRoot` 装进**系统钥匙串**(`security add-trusted-cert -d`)。
//! - **手动**:在访达里定位 / 用钥匙串打开 / 复制路径,配合面板里的步骤说明。
//! - **检查**:`security verify-cert` 看是否已被系统信任。
//!
//! 外部命令是阻塞的(尤其一键安装会等用户输密码),放 gpui `background_executor` 线程跑,
//! 完成后 `cx.spawn` 回主线程写回结果。

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result};
use mage_ui::gpui::PathPromptOptions;
use mage_ui::prelude::*;
use scry_ca::{default_ca_dir, Ca};

use crate::logger::LogLevel;
use crate::state::{CertStatus, ScryApp};

/// 根证书路径 `~/.scry/ca.pem`。
pub fn ca_path() -> PathBuf {
    default_ca_dir().join("ca.pem")
}

/// 确保根 CA 已生成并落盘,返回其路径。
pub fn ensure_ca() -> Result<PathBuf> {
    Ca::load_or_create_default()?;
    Ok(ca_path())
}

/// 一键安装并信任(系统钥匙串;弹管理员密码框)。阻塞,放后台线程调。
fn install_trusted_blocking() -> Result<String> {
    let path = ensure_ca()?;
    let p = path.to_string_lossy().to_string();
    // AppleScript 里再套一层 shell;路径无空格/引号,单引号包裹即可。
    let script = format!(
        "do shell script \"security add-trusted-cert -d -r trustRoot \
         -k /Library/Keychains/System.keychain '{p}'\" with administrator privileges"
    );
    let out = Command::new("osascript").arg("-e").arg(&script).output()?;
    if out.status.success() {
        Ok("已安装并信任(系统钥匙串)".to_string())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = err.trim();
        if err.contains("-128") {
            anyhow::bail!("已取消");
        }
        anyhow::bail!("安装失败:{err}");
    }
}

/// 检查根证书是否已被系统信任(SSL 用途)。阻塞,放后台线程调。
fn verify_blocking() -> Result<bool> {
    let path = ca_path();
    if !path.exists() {
        return Ok(false);
    }
    let out = Command::new("security")
        .arg("verify-cert")
        .arg("-c")
        .arg(&path)
        .arg("-p")
        .arg("ssl")
        .output()?;
    Ok(out.status.success())
}

/// 在访达里定位 ca.pem。
pub fn reveal_in_finder() {
    if ensure_ca().is_ok() {
        let _ = Command::new("open").arg("-R").arg(ca_path()).spawn();
    }
}

/// 用「钥匙串访问」打开 ca.pem(触发导入)。
pub fn open_in_keychain() {
    if ensure_ca().is_ok() {
        let _ = Command::new("open").arg(ca_path()).spawn();
    }
}

/// 授权内核抓包:给 `/dev/bpf*` 加读写权限(弹管理员框)。阻塞,放后台线程调。
pub(crate) fn authorize_bpf_blocking() -> Result<String> {
    let script =
        "do shell script \"chmod o+rw /dev/bpf*\" with administrator privileges".to_string();
    let out = Command::new("osascript").arg("-e").arg(&script).output()?;
    if out.status.success() {
        Ok("已授权 BPF,可开始内核抓包".to_string())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = err.trim();
        if err.contains("-128") {
            anyhow::bail!("已取消");
        }
        anyhow::bail!("授权失败:{err}");
    }
}

// ───────────────────── 证书安装包导出(让其他电脑一键配置信任) ─────────────────────

/// 把根证书导出成一个**跨平台一键安装包**到 `~/.scry/cert-bundle/`:
/// 含 PEM/DER 证书 + macOS/Windows/Linux 一键脚本 + Apple 描述文件 + 中英说明。
/// 整个文件夹拷到任意电脑即可双击安装信任。阻塞,放后台线程调。
/// 安装包内的一个文件(文件名 + 内容 + 是否需要可执行位)。
struct BundleFile {
    name: &'static str,
    content: Vec<u8>,
    exec: bool,
}

/// 生成安装包的**全部文件内容**(纯逻辑、不碰文件系统,便于单测)。
fn build_bundle(ca: &Ca) -> Vec<BundleFile> {
    let mobile = mobileconfig(&ca.cert_der_base64(), &ca.cert_sha256_hex());
    vec![
        BundleFile {
            name: "ca.pem",
            content: ca.cert_pem().into_bytes(),
            exec: false,
        },
        BundleFile {
            name: "Scry-CA.crt",
            content: ca.cert_der(),
            exec: false,
        },
        BundleFile {
            name: "Scry-CA.mobileconfig",
            content: mobile.into_bytes(),
            exec: false,
        },
        BundleFile {
            name: "README.txt",
            content: README.as_bytes().to_vec(),
            exec: false,
        },
        BundleFile {
            name: "install-macos.command",
            content: MAC_SCRIPT.as_bytes().to_vec(),
            exec: true,
        },
        BundleFile {
            name: "install-linux.sh",
            content: LINUX_SCRIPT.as_bytes().to_vec(),
            exec: true,
        },
        BundleFile {
            name: "install-windows.bat",
            content: WIN_SCRIPT.as_bytes().to_vec(),
            exec: false,
        },
    ]
}

fn export_bundle_blocking() -> Result<PathBuf> {
    let ca = Ca::load_or_create_default()?;
    let dir = default_ca_dir().join("cert-bundle");
    std::fs::create_dir_all(&dir).context("创建导出目录失败")?;
    for f in build_bundle(&ca) {
        let path = dir.join(f.name);
        if f.exec {
            write_exec(&path, &f.content)?;
        } else {
            std::fs::write(&path, &f.content)
                .with_context(|| format!("写 {} 失败", path.display()))?;
        }
    }
    Ok(dir)
}

/// 写文件并(类 Unix 上)加可执行位,让 `.command`/`.sh` 双击 / 直接运行。
fn write_exec(path: &Path, content: &[u8]) -> Result<()> {
    std::fs::write(path, content).with_context(|| format!("写 {} 失败", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).ok();
    }
    Ok(())
}

/// 32 位十六进制 → `8-4-4-4-12` 形式的 UUID(给描述文件用,内容稳定)。
fn hex_to_uuid(h: &str) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
    .to_uppercase()
}

/// 生成 iOS / iPadOS / macOS 的描述文件(`.mobileconfig`),内嵌 DER 证书。
fn mobileconfig(der_b64: &str, sha_hex: &str) -> String {
    let uuid_top = hex_to_uuid(&sha_hex[0..32]);
    let uuid_cert = hex_to_uuid(&sha_hex[32..64]);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>com.scry.ca.root</string>
      <key>PayloadUUID</key><string>{uuid_cert}</string>
      <key>PayloadDisplayName</key><string>Scry Root CA</string>
      <key>PayloadCertificateFileName</key><string>Scry-CA.crt</string>
      <key>PayloadContent</key>
      <data>{der_b64}</data>
    </dict>
  </array>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>com.scry.ca</string>
  <key>PayloadUUID</key><string>{uuid_top}</string>
  <key>PayloadDisplayName</key><string>Scry Root CA</string>
  <key>PayloadDescription</key><string>Install and trust the Scry root CA for HTTPS interception.</string>
</dict>
</plist>
"#
    )
}

const MAC_SCRIPT: &str = r#"#!/bin/bash
# Scry 根证书一键安装(macOS):装入系统钥匙串并设为始终信任。
cd "$(dirname "$0")" || exit 1
echo "即将把 Scry Root CA 安装到【系统钥匙串】并设为信任,需要管理员密码。"
if sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "ca.pem"; then
  echo "✅ 安装成功:Scry Root CA 已被系统信任。"
else
  echo "❌ 安装失败,请重试,或按 README.txt 手动安装。"
fi
printf "按回车键关闭…"; read -r _
"#;

const LINUX_SCRIPT: &str = r#"#!/bin/bash
# Scry 根证书一键安装(Linux):兼容 Debian/Ubuntu 与 RHEL/Fedora。
set -e
cd "$(dirname "$0")" || exit 1
if [ "$(id -u)" -ne 0 ]; then
  echo "需要 root 权限,正在用 sudo 重新运行…"
  exec sudo "$0" "$@"
fi
if [ -d /usr/local/share/ca-certificates ]; then
  cp ca.pem /usr/local/share/ca-certificates/scry-ca.crt
  update-ca-certificates
  echo "✅ 已安装(Debian/Ubuntu 体系)。"
elif [ -d /etc/pki/ca-trust/source/anchors ]; then
  cp ca.pem /etc/pki/ca-trust/source/anchors/scry-ca.pem
  update-ca-trust
  echo "✅ 已安装(RHEL/Fedora 体系)。"
else
  echo "未识别的发行版,请手动安装 ca.pem(见 README.txt)。"
  exit 1
fi
echo "提示:Firefox/Chrome 可能使用各自证书库,需在浏览器内另行导入 ca.pem。"
"#;

const WIN_SCRIPT: &str = concat!(
    "@echo off\r\n",
    "chcp 65001 >nul\r\n",
    "REM Scry root CA one-click installer (Windows): import into Trusted Root store.\r\n",
    "net session >nul 2>&1\r\n",
    "if %errorlevel% neq 0 (\r\n",
    "  echo Requesting administrator privileges...\r\n",
    "  powershell -Command \"Start-Process -FilePath '%~f0' -Verb RunAs\"\r\n",
    "  exit /b\r\n",
    ")\r\n",
    "certutil -addstore -f Root \"%~dp0Scry-CA.crt\"\r\n",
    "if %errorlevel%==0 (\r\n",
    "  echo [OK] Scry Root CA installed into Trusted Root.\r\n",
    ") else (\r\n",
    "  echo [FAIL] Install failed. See README.txt for manual steps.\r\n",
    ")\r\n",
    "pause\r\n",
);

const README: &str = r#"Scry 根证书安装包 / Scry Root CA Installer
==========================================

把本文件夹整个拷到目标电脑,按其系统选对应方式安装,即可让该电脑信任 Scry 根证书,
从而用 Scry 解密(抓取)该设备的 HTTPS 流量。

[macOS]
  双击 install-macos.command,按提示输入管理员密码。
  (若提示来自身份不明开发者:右键 → 打开。)

[Windows]
  双击 install-windows.bat,在 UAC 弹窗点「是」授权。
  (或右键 → 以管理员身份运行。)

[Linux]
  终端执行:  sudo ./install-linux.sh
  (兼容 Debian/Ubuntu 与 RHEL/Fedora。Firefox/Chrome 需在浏览器内另行导入 ca.pem。)

[iPhone / iPad / 其他 Apple 设备]
  把 Scry-CA.mobileconfig 发到设备(隔空投送 / 邮件 / 网盘)并安装描述文件,
  再到「设置 → 通用 → 关于本机 → 证书信任设置」打开对该证书的「完全信任」。

文件清单:
  ca.pem                根证书(PEM 文本)
  Scry-CA.crt           根证书(DER 二进制,Windows 双击可直接装)
  install-macos.command macOS 一键安装脚本
  install-windows.bat   Windows 一键安装脚本(自动提权)
  install-linux.sh      Linux 一键安装脚本
  Scry-CA.mobileconfig  Apple 描述文件

验证:浏览器访问 HTTPS 网站无证书告警、且 Scry 能看到明文请求即成功。

安全提示:这是用于抓包调试的私有根证书,只在你自己掌控的设备上安装;
          不再需要时请从系统信任中移除。
"#;

// ───────────────────── CA 身份迁移(多机共用同一根 CA) ─────────────────────

/// 把**完整 CA(含私钥)**导出到 `~/.scry/ca-identity/Scry-CA-identity.pem`,
/// 可在另一台电脑「导入 CA」,使多台 Scry 共用同一根证书。阻塞,放后台线程调。
fn export_identity_blocking() -> Result<PathBuf> {
    // 确保已生成,然后**直接读磁盘原始 PEM**拼接(保证与导入端字节完全一致 = 真正同一套 CA)。
    Ca::load_or_create_default()?;
    let ca_dir = default_ca_dir();
    let cert_pem = std::fs::read_to_string(ca_dir.join("ca.pem")).context("读取 ca.pem 失败")?;
    let key_pem = std::fs::read_to_string(ca_dir.join("ca.key")).context("读取 ca.key 失败")?;
    let combined = format!("{}\n{}\n", key_pem.trim_end(), cert_pem.trim_end());

    let dir = ca_dir.join("ca-identity");
    std::fs::create_dir_all(&dir).context("创建导出目录失败")?;
    let path = dir.join("Scry-CA-identity.pem");
    std::fs::write(&path, &combined).context("写身份文件失败")?;
    #[cfg(unix)]
    {
        // 私钥文件收紧到 0600(仅本人可读写)。
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).ok();
    }
    std::fs::write(dir.join("README.txt"), IDENTITY_README).context("写 README.txt 失败")?;
    Ok(dir)
}

/// 从身份文件导入 CA:校验后覆盖 `~/.scry/ca.pem` 与 `ca.key`(旧的备份为 `*.bak`)。阻塞。
fn import_identity_blocking(src: &Path) -> Result<()> {
    let combined = std::fs::read_to_string(src).context("读取身份文件失败")?;
    // 先校验能重建为合法 CA(私钥与证书匹配),再落盘。
    Ca::from_identity_pem(&combined).context("身份文件无效(需同时含证书与私钥)")?;
    // 落**原始** cert/key 段,保证与来源机器字节一致(真正同一套 CA)。
    let (cert_pem, key_pem) = Ca::split_identity_pem(&combined)?;
    let dir = default_ca_dir();
    std::fs::create_dir_all(&dir).ok();
    let cert_path = dir.join("ca.pem");
    let key_path = dir.join("ca.key");
    backup_if_exists(&cert_path);
    backup_if_exists(&key_path);
    std::fs::write(&cert_path, format!("{}\n", cert_pem.trim_end())).context("写 ca.pem 失败")?;
    std::fs::write(&key_path, format!("{}\n", key_pem.trim_end())).context("写 ca.key 失败")?;
    Ok(())
}

/// 若文件已存在,改名为 `<原名>.bak`(再次导入会覆盖旧备份,可接受)。
fn backup_if_exists(p: &Path) {
    if p.exists() {
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        let _ = std::fs::rename(p, p.with_extension(format!("{ext}.bak")));
    }
}

const IDENTITY_README: &str = r#"Scry CA 身份文件(含私钥) / Scry CA Identity — PRIVATE KEY INCLUDED
====================================================================

⚠️ 安全警告:Scry-CA-identity.pem 内含根 CA 的【私钥】。
   拿到它的人可以伪造任意 HTTPS 网站证书。请仅在你自己掌控的设备间传输
   (隔空投送 / U 盘 / 加密通道),用完即删;切勿上传网盘、发群或提交到 Git。

用途:让多台电脑的 Scry 共用同一个根 CA —— 在 A 机签发 / 信任的证书,B 机也认。

在另一台电脑导入:
  打开 Scry → 设置 → 根证书 → 「导入 CA」→ 选择本文件 Scry-CA-identity.pem。
  导入会覆盖该机原有的 ~/.scry/ca.pem 与 ca.key(旧的自动备份为 *.bak)。
  导入后在该机点「一键安装并信任」把这张 CA 装入系统信任,再重新开始抓包。
"#;

impl ScryApp {
    /// 一键安装信任(后台跑 osascript,回主线程写状态)。
    pub fn install_cert(&mut self, cx: &mut Context<Self>) {
        if self.cert_busy {
            return;
        }
        self.cert_busy = true;
        self.cert_msg = None;
        cx.notify();

        let task = cx
            .background_executor()
            .spawn(async move { install_trusted_blocking().map_err(|e| format!("{e:#}")) });
        cx.spawn(async move |this, cx| {
            let res = task.await;
            let _ = this.update(cx, |this, cx| {
                this.cert_busy = false;
                match res {
                    Ok(msg) => {
                        this.push_log(LogLevel::Success, "cert", msg.clone());
                        this.cert_msg = Some(msg);
                        this.cert_status = CertStatus::Trusted;
                    }
                    Err(e) => {
                        this.push_log(LogLevel::Error, "cert", format!("安装证书失败:{e}"));
                        this.cert_msg = Some(e);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// 导出跨平台证书安装包(后台写盘,完成后在访达打开该文件夹)。
    pub fn export_cert_bundle(&mut self, cx: &mut Context<Self>) {
        if self.cert_busy {
            return;
        }
        self.cert_busy = true;
        self.cert_msg = None;
        cx.notify();

        let task = cx
            .background_executor()
            .spawn(async move { export_bundle_blocking().map_err(|e| format!("{e:#}")) });
        cx.spawn(async move |this, cx| {
            let res = task.await;
            let _ = this.update(cx, |this, cx| {
                this.cert_busy = false;
                match res {
                    Ok(dir) => {
                        let _ = Command::new("open").arg(&dir).spawn();
                        let msg = format!("已导出证书安装包到 {}", dir.display());
                        this.push_log(LogLevel::Success, "cert", msg.clone());
                        this.cert_msg = Some(msg);
                    }
                    Err(e) => {
                        this.push_log(LogLevel::Error, "cert", format!("导出证书安装包失败:{e}"));
                        this.cert_msg = Some(e);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// 导出完整 CA(含私钥),用于多台设备共用同一根证书(后台写盘 + 在访达打开)。
    pub fn export_ca_identity(&mut self, cx: &mut Context<Self>) {
        if self.cert_busy {
            return;
        }
        self.cert_busy = true;
        self.cert_msg = None;
        cx.notify();

        let task = cx
            .background_executor()
            .spawn(async move { export_identity_blocking().map_err(|e| format!("{e:#}")) });
        cx.spawn(async move |this, cx| {
            let res = task.await;
            let _ = this.update(cx, |this, cx| {
                this.cert_busy = false;
                match res {
                    Ok(dir) => {
                        let _ = Command::new("open").arg(&dir).spawn();
                        let msg = format!("已导出 CA 身份(含私钥)到 {}", dir.display());
                        this.push_log(LogLevel::Success, "cert", msg.clone());
                        this.cert_msg = Some(msg);
                    }
                    Err(e) => {
                        this.push_log(LogLevel::Error, "cert", format!("导出 CA 身份失败:{e}"));
                        this.cert_msg = Some(e);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// 弹文件框选身份文件 → 后台导入(覆盖本机 CA,旧的自动备份)→ 提示后续步骤。
    pub fn import_ca_identity(&mut self, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some(self.lang.t("Import CA")),
        });
        let bg = cx.background_executor().clone();
        cx.spawn(async move |this, cx| {
            let path: Option<PathBuf> = match rx.await {
                Ok(Ok(Some(paths))) => paths.into_iter().next(),
                _ => None,
            };
            let Some(path) = path else {
                return;
            };
            let result = bg
                .spawn(
                    async move { import_identity_blocking(&path).map_err(|e| format!("{e:#}")) },
                )
                .await;
            let _ = this.update(cx, |this, cx| {
                match result {
                    Ok(()) => {
                        this.cert_status = CertStatus::Unknown;
                        let msg = if this.lang.is_zh() {
                            "已导入 CA(本机根证书已替换,旧的备份为 *.bak)。请『一键安装并信任』这张 CA,重启抓包后用新 CA 签发。".to_string()
                        } else {
                            "CA imported (local root replaced; old backed up as *.bak). Install & trust it, then restart capture.".to_string()
                        };
                        this.push_log(LogLevel::Success, "cert", msg.clone());
                        this.cert_msg = Some(msg);
                    }
                    Err(msg) => {
                        this.push_log(LogLevel::Error, "cert", format!("导入 CA 失败:{msg}"));
                        this.cert_msg = Some(if this.lang.is_zh() {
                            format!("导入 CA 失败:{msg}")
                        } else {
                            format!("Import CA failed: {msg}")
                        });
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// 授权内核抓包 BPF(后台跑 osascript chmod /dev/bpf*)。
    pub fn authorize_bpf(&mut self, cx: &mut Context<Self>) {
        if self.cert_busy {
            return;
        }
        self.cert_busy = true;
        self.cert_msg = None;
        cx.notify();
        let task = cx
            .background_executor()
            .spawn(async move { authorize_bpf_blocking().map_err(|e| format!("{e:#}")) });
        cx.spawn(async move |this, cx| {
            let res = task.await;
            let _ = this.update(cx, |this, cx| {
                this.cert_busy = false;
                match &res {
                    Ok(m) => this.push_log(LogLevel::Success, "cert", m.clone()),
                    Err(e) => this.push_log(LogLevel::Error, "cert", format!("BPF 授权失败:{e}")),
                }
                this.cert_msg = Some(match res {
                    Ok(m) => m,
                    Err(e) => e,
                });
                cx.notify();
            });
        })
        .detach();
    }

    /// 检查信任状态(后台跑 security verify-cert)。
    pub fn check_cert(&mut self, cx: &mut Context<Self>) {
        if self.cert_busy {
            return;
        }
        self.cert_busy = true;
        self.cert_status = CertStatus::Checking;
        cx.notify();

        let task = cx
            .background_executor()
            .spawn(async move { verify_blocking().unwrap_or(false) });
        cx.spawn(async move |this, cx| {
            let trusted = task.await;
            let _ = this.update(cx, |this, cx| {
                this.cert_busy = false;
                this.cert_status = if trusted {
                    CertStatus::Trusted
                } else {
                    CertStatus::Untrusted
                };
                if trusted {
                    this.push_log(LogLevel::Success, "cert", "根证书已被系统信任,可解密 HTTPS");
                } else {
                    this.push_log(
                        LogLevel::Warning,
                        "cert",
                        "根证书未被系统信任,HTTPS 将无法解密(去设置页一键安装)",
                    );
                }
                cx.notify();
            });
        })
        .detach();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_format_is_canonical() {
        assert_eq!(
            hex_to_uuid("0123456789abcdef0123456789abcdef"),
            "01234567-89AB-CDEF-0123-456789ABCDEF"
        );
    }

    #[test]
    fn bundle_contains_all_files_with_valid_content() {
        let ca = Ca::generate().unwrap(); // 内存 CA,不落盘
        let files = build_bundle(&ca);

        let find = |name: &str| files.iter().find(|f| f.name == name).expect(name);

        for must in [
            "ca.pem",
            "Scry-CA.crt",
            "Scry-CA.mobileconfig",
            "README.txt",
            "install-macos.command",
            "install-linux.sh",
            "install-windows.bat",
        ] {
            find(must);
        }

        // 证书本体:DER 与 scry_ca 一致;PEM 是文本。
        assert_eq!(find("Scry-CA.crt").content, ca.cert_der());
        assert!(String::from_utf8_lossy(&find("ca.pem").content).contains("BEGIN CERTIFICATE"));

        // 各平台脚本含关键安装命令。
        assert!(
            String::from_utf8_lossy(&find("install-macos.command").content)
                .contains("add-trusted-cert")
        );
        let win = String::from_utf8(find("install-windows.bat").content.clone()).unwrap();
        assert!(win.contains("certutil -addstore -f Root"));
        assert!(win.contains("\r\n"), "Windows 批处理必须是 CRLF 换行");
        assert!(
            String::from_utf8_lossy(&find("install-linux.sh").content)
                .contains("update-ca-certificates")
        );

        // 脚本带可执行位标记(.command / .sh),.bat 不需要。
        assert!(find("install-macos.command").exec);
        assert!(find("install-linux.sh").exec);
        assert!(!find("install-windows.bat").exec);

        // 描述文件:是根证书 payload,且内嵌的 base64 与 DER 对应。
        let mc = String::from_utf8(find("Scry-CA.mobileconfig").content.clone()).unwrap();
        assert!(mc.contains("com.apple.security.root"));
        assert!(mc.contains(&ca.cert_der_base64()));
    }

    #[test]
    fn mobileconfig_is_valid_plist() {
        let ca = Ca::generate().unwrap();
        let files = build_bundle(&ca);
        let mc = files
            .iter()
            .find(|f| f.name == "Scry-CA.mobileconfig")
            .unwrap();

        let dir = std::env::temp_dir().join(format!("scry-bundle-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Scry-CA.mobileconfig");
        std::fs::write(&path, &mc.content).unwrap();

        // macOS 上用 plutil 校验合法性(非 mac / 无 plutil 时自动跳过)。
        if let Ok(out) = Command::new("plutil").arg("-lint").arg(&path).output() {
            assert!(
                out.status.success(),
                "mobileconfig 不是合法 plist:{}",
                String::from_utf8_lossy(&out.stdout)
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
