//! 外部进程扩展运行时(Runner ③)。
//!
//! scry `spawn` 一个子进程(`python3 main.py` / 任意命令),用 **newline-delimited JSON**(JSONL)
//! 在 stdin/stdout 上做一问一答 RPC。每个钩子一次往返;内联钩子带**超时 + fail-open**
//! (超时/出错 → 按 `Continue` 放行,绝不卡死实时流量)。子进程崩溃只影响该扩展,不波及 scry。
//!
//! 线路协议(host → ext,每行一条):
//! ```json
//! {"id":1,"hook":"manifest"}
//! {"id":2,"hook":"on_request","flow":{...HttpFlow...}}
//! ```
//! ext → host:
//! ```json
//! {"id":1,"manifest":{"id":"x","name":"X","version":"0.1.0","abi":1,"hooks":["on_request"],"permissions":["traffic.modify"]}}
//! {"id":2,"action":"continue","flow":{...改写后...},"logs":[{"level":"Info","msg":"…"}],"findings":[{...}]}
//! ```

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Serialize;

use scry_core::HttpFlow;
use scry_ext_api::{
    ExtKind, ExtManifest, ExtRequest, ExtResponse, Extension, HookAction, HostServices, LogLevel,
};

use crate::wire::{self, HookReply, ManifestReply};

/// 一个由外部进程承载的扩展。
pub struct ProcessExt {
    manifest: ExtManifest,
    conn: Mutex<Option<ProcessConn>>,
    timeout: Duration,
}

/// 子进程连接:持有 stdin + 后台读 stdout 的行通道(避免阻塞读卡死,可配合 `recv_timeout`)。
struct ProcessConn {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<String>,
    _reader: JoinHandle<()>,
    next_id: u64,
}

impl ProcessExt {
    /// 在 `dir` 下用 `command` 拉起子进程并做 manifest 握手。
    pub fn spawn(dir: &Path, command: &[String], timeout: Duration) -> Result<Self> {
        let prog = command
            .first()
            .ok_or_else(|| anyhow!("扩展 command 为空"))?;
        let mut cmd = Command::new(prog);
        cmd.args(&command[1..])
            .current_dir(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().with_context(|| format!("spawn 扩展进程失败:{prog}"))?;
        let stdin = child.stdin.take().context("拿不到扩展 stdin")?;
        let stdout = child.stdout.take().context("拿不到扩展 stdout")?;

        let (tx, rx) = mpsc::channel::<String>();
        let reader = std::thread::spawn(move || {
            let r = BufReader::new(stdout);
            for line in r.lines() {
                match line {
                    Ok(l) => {
                        if tx.send(l).is_err() {
                            break; // 接收端已丢弃(扩展被卸载)
                        }
                    }
                    Err(_) => break, // 子进程退出 / 管道关闭
                }
            }
        });

        let mut conn = ProcessConn {
            child,
            stdin,
            rx,
            _reader: reader,
            next_id: 0,
        };
        let manifest = handshake(&mut conn, timeout)?;
        Ok(Self {
            manifest,
            conn: Mutex::new(Some(conn)),
            timeout,
        })
    }

    /// 一次 RPC 往返(发请求行 → 等响应行,带超时)。调用前清掉上次超时遗留的陈旧响应防错位。
    ///
    /// 读循环:扩展在发出**最终回复**前,可发若干 `{"call":"send_request","request":{…}}` **反向调用宿主**
    /// (双向 RPC);本端代为执行 `host.send_request` 并回 `{"id":…,"result":{…}}`,然后继续等最终回复。
    fn rpc(
        &self,
        hook: &str,
        flow: Option<&HttpFlow>,
        host: &mut dyn HostServices,
    ) -> Result<HookReply> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| anyhow!("扩展连接锁中毒"))?;
        let conn = guard.as_mut().ok_or_else(|| anyhow!("扩展进程已停止"))?;
        while conn.rx.try_recv().is_ok() {} // 丢弃陈旧行(上次超时的迟到响应)
        conn.next_id += 1;
        let id = conn.next_id;
        let line = serde_json::to_string(&HookCall { id, hook, flow })?;
        conn.stdin.write_all(line.as_bytes())?;
        conn.stdin.write_all(b"\n")?;
        conn.stdin.flush()?;
        loop {
            let resp = conn
                .rx
                .recv_timeout(self.timeout)
                .map_err(|e| anyhow!("等待扩展响应超时/断开:{e}"))?;
            let v: serde_json::Value = serde_json::from_str(&resp).context("解析扩展消息失败")?;
            if v.get("call").and_then(|c| c.as_str()) == Some("send_request") {
                let cid = v.get("id").and_then(|i| i.as_u64()).unwrap_or(0);
                let req: ExtRequest = v
                    .get("request")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()?
                    .unwrap_or_default();
                let result = host.send_request(req);
                let out = serde_json::to_string(&CallResult { id: cid, result })?;
                conn.stdin.write_all(out.as_bytes())?;
                conn.stdin.write_all(b"\n")?;
                conn.stdin.flush()?;
                continue; // 继续等最终回复
            }
            let reply: HookReply = serde_json::from_value(v).context("解析扩展响应失败")?;
            return Ok(reply);
        }
    }

    /// 内联钩子(on_request / on_response):应用副作用 + 改写 flow + 映射动作;失败 fail-open。
    fn inline(&self, hook: &str, flow: &mut HttpFlow, host: &mut dyn HostServices) -> HookAction {
        match self.rpc(hook, Some(&*flow), host) {
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
                    &format!("[{}] {hook} 失败,放行:{e}", self.manifest.id),
                );
                HookAction::Continue // fail-open
            }
        }
    }
}

impl Extension for ProcessExt {
    fn manifest(&self) -> &ExtManifest {
        &self.manifest
    }

    fn on_request(&self, flow: &mut HttpFlow, host: &mut dyn HostServices) -> HookAction {
        self.inline("on_request", flow, host)
    }

    fn on_response(&self, flow: &mut HttpFlow, host: &mut dyn HostServices) -> HookAction {
        self.inline("on_response", flow, host)
    }

    fn on_flow_complete(&self, flow: &HttpFlow, host: &mut dyn HostServices) {
        match self.rpc("on_flow_complete", Some(flow), host) {
            Ok(reply) => wire::apply_side_effects(reply.logs, reply.findings, host),
            Err(e) => host.log(
                LogLevel::Warning,
                &format!("[{}] on_flow_complete 失败(忽略):{e}", self.manifest.id),
            ),
        }
    }
}

impl Drop for ProcessExt {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.conn.lock() {
            if let Some(mut conn) = guard.take() {
                let _ = conn.child.kill();
                let _ = conn.child.wait();
            }
        }
    }
}

/// 握手:取扩展自述的 manifest(失败则拒绝加载)。
fn handshake(conn: &mut ProcessConn, timeout: Duration) -> Result<ExtManifest> {
    conn.next_id += 1;
    let id = conn.next_id;
    let line = serde_json::to_string(&HookCall {
        id,
        hook: "manifest",
        flow: None,
    })?;
    conn.stdin.write_all(line.as_bytes())?;
    conn.stdin.write_all(b"\n")?;
    conn.stdin.flush()?;
    let resp = conn
        .rx
        .recv_timeout(timeout)
        .map_err(|e| anyhow!("扩展 manifest 握手超时/断开:{e}"))?;
    let reply: ManifestReply = serde_json::from_str(&resp).context("解析扩展 manifest 失败")?;
    wire::manifest_from_wire(reply.manifest, ExtKind::Process)
}

// ───────────────────────── 线路消息(进程 Runner 的发送侧) ─────────────────────────
//
// 接收侧(`HookReply` / `ManifestReply` / `WireAction` / …)与 WASM Runner 共用,见 `crate::wire`。

#[derive(Serialize)]
struct HookCall<'a> {
    id: u64,
    hook: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    flow: Option<&'a HttpFlow>,
}

/// 宿主对扩展反向调用(`send_request`)的回执。
#[derive(Serialize)]
struct CallResult {
    id: u64,
    result: ExtResponse,
}
