//! 抓包接线:启动 / 停止 `scry_proxy`(127.0.0.1:8888,MITM 解密)+ 把抓到的流量实时拉进 UI。
//!
//! 进程模型:代理跑在独立 OS 线程的多线程 tokio 运行时里(`run` 内部 `tokio::spawn` 每连接一任务);
//! UI 主线程与之**共享同一个 `Arc<Mutex<Store>>`**,每秒 `recent()` 拉最新流量刷新 history 表。
//! 停止:`oneshot` 发信号 → 代理线程的 `select!` 结束 → 运行时析构 → 监听端口释放。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use mage_ui::prelude::*;
use scry_ca::Ca;
use scry_core::{HttpFlow, WsMessage};
use scry_proxy::ProxyConfig;
use scry_storage::Store;
use tokio::sync::oneshot;

use crate::logger::LogLevel;
use crate::state::{CaptureMode, Proto, ScryApp};

impl ScryApp {
    /// 开关抓包。
    pub fn toggle_capture(&mut self, cx: &mut Context<Self>) {
        if self.capturing {
            self.stop_capture(cx);
        } else {
            self.start_capture(cx);
        }
    }

    /// 按当前模式启动抓包。
    pub fn start_capture(&mut self, cx: &mut Context<Self>) {
        if self.capturing {
            return;
        }
        // 内核模式:先确保 BPF 可用;不可用则自动弹管理员授权框,授权成功后自动重试(避免静默失败)。
        if self.capture_mode == CaptureMode::Kernel && scry_sniff::check_available().is_err() {
            self.prompt_bpf_then_start(cx);
            return;
        }
        // 建实时推流通道:Store 每条新流量 clone 推到 rx,UI 增量追加(替代全量轮询)。
        let (tx, rx) = std::sync::mpsc::channel::<HttpFlow>();
        // WebSocket 消息独立通道(不去重,逐条推)。
        let (ws_tx, ws_rx) = std::sync::mpsc::channel::<WsMessage>();
        let store = match Store::open_default() {
            Ok(mut s) => {
                s.set_sender(tx);
                s.set_ws_sender(ws_tx);
                Arc::new(Mutex::new(s))
            }
            Err(e) => {
                let msg = format!("打开存储失败:{e:#}");
                self.push_log(LogLevel::Error, "capture", msg.clone());
                self.cert_msg = Some(msg);
                cx.notify();
                return;
            }
        };

        match self.capture_mode {
            CaptureMode::Kernel => {
                // 选中的网卡(None = 自动探测默认路由网卡)。
                let iface = self.ifaces.get(self.iface_sel).cloned();
                let iface_name = iface.clone().unwrap_or_else(|| "默认网卡".to_string());
                // 可选 pcapng 落盘:`~/.scry/capture-<unixsecs>.pcapng`(Wireshark 可直接打开)。
                let pcapng = self.pcapng_enabled.then(pcapng_out_path).flatten();
                let pcapng_log = pcapng.as_ref().map(|p| p.display().to_string());
                if let Some(p) = &pcapng {
                    self.cert_msg = Some(format!("pcapng 同步保存到 {}", p.display()));
                }
                let stop = Arc::new(AtomicBool::new(false));
                let stop_t = stop.clone();
                let store_t = store.clone();
                std::thread::Builder::new()
                    .name("scry-sniff".into())
                    .spawn(move || {
                        if let Err(e) = scry_sniff::run(iface, store_t, stop_t, pcapng) {
                            eprintln!("内核抓包退出:{e:#}");
                        }
                    })
                    .ok();
                self.sniff_stop = Some(stop);
                self.push_log(
                    LogLevel::Success,
                    "capture",
                    format!(
                        "内核抓包已启动 · 网卡 {iface_name}(HTTPS 仅 SNI · HTTP/3/QUIC 仅 SNI/ALPN)"
                    ),
                );
                if let Some(p) = pcapng_log {
                    self.push_log(LogLevel::Info, "capture", format!("pcapng 同步保存到 {p}"));
                }
            }
            CaptureMode::Proxy => {
                // 监听端口 / 绑定地址可配:局域网开关 = 绑 0.0.0.0(同 Wi‑Fi 的手机等设备可连),否则仅本机。
                let port: u16 = self
                    .proxy_port
                    .read(cx)
                    .text()
                    .trim()
                    .parse::<u16>()
                    .ok()
                    .filter(|p| *p > 0)
                    .unwrap_or(8888);
                let bind_ip = if self.proxy_lan { "0.0.0.0" } else { "127.0.0.1" };
                let addr: std::net::SocketAddr = format!("{bind_ip}:{port}")
                    .parse()
                    .unwrap_or_else(|_| ProxyConfig::default().addr);
                save_net_cfg(port, self.proxy_lan); // 持久化:下次启动自动恢复
                if std::net::TcpListener::bind(addr).is_err() {
                    let msg = format!("端口 {addr} 被占用,无法启动代理抓包");
                    self.push_log(LogLevel::Error, "capture", msg.clone());
                    self.cert_msg = Some(msg);
                    cx.notify();
                    return;
                }
                let ca = match Ca::load_or_create_default() {
                    Ok(c) => Arc::new(c),
                    Err(e) => {
                        let msg = format!("加载根证书失败:{e:#}");
                        self.push_log(LogLevel::Error, "capture", msg.clone());
                        self.cert_msg = Some(msg);
                        cx.notify();
                        return;
                    }
                };
                let (stop_tx, stop_rx) = oneshot::channel::<()>();
                let store_thread = store.clone();
                // 上游代理:从 SCRY_UPSTREAM 读(sing-box/QX 链式抓包);未设则直连。
                let upstream = self.upstream_proxy(cx);
                let up_note = if upstream.is_some() {
                    "经上游代理出网"
                } else {
                    "直连出网"
                };
                // 让扩展 send_request 与抓包同源出网。
                self.ext.set_upstream(upstream.clone());
                // 交互式拦截:装上回传通道(UI 每拍排空 intercept_rx;改包决策经各 item.reply 回传)。
                let (itx, irx) = std::sync::mpsc::channel::<crate::ext::InterceptItem>();
                self.ext.arm_intercept(itx);
                self.intercept_rx = Some(irx);
                self.intercept_queue.clear();
                self.intercept_edit_id = None;
                // 把当前拦截范围 / Match & Replace 规则推给引擎(确保抓包时规则已就位)。
                self.sync_rules_to_engine();
                // 注入扩展钩子:proxy 线程在三个接缝回调 ExtRegistry(经 Arc 共享)。
                let proxy_cfg = ProxyConfig {
                    addr,
                    upstream,
                    hooks: Some(scry_proxy::ExtHooks(self.ext.clone())),
                    // 弱网/限速:选中非 Off 档则注入(回写客户端时延迟 + 限带宽)。
                    throttle: scry_proxy::throttle::PRESETS
                        .get(self.throttle_sel)
                        .map(|(_, t)| *t)
                        .filter(|t| !t.is_noop()),
                    // 活动 WS 改帧规则:非空则注入(升级的 WS 连接走解帧改写转发);空 = 字节透传。
                    ws_rewrite: (!self.ws_rules.is_empty())
                        .then(|| std::sync::Arc::new(self.ws_rules.clone())),
                    ..ProxyConfig::default()
                };
                std::thread::Builder::new()
                    .name("scry-proxy".into())
                    .spawn(move || {
                        let rt = match tokio::runtime::Builder::new_multi_thread()
                            .enable_all()
                            .build()
                        {
                            Ok(rt) => rt,
                            Err(e) => {
                                eprintln!("抓包运行时创建失败:{e}");
                                return;
                            }
                        };
                        rt.block_on(async move {
                            tokio::select! {
                                r = scry_proxy::run(proxy_cfg, store_thread, ca) => {
                                    if let Err(e) = r { eprintln!("代理退出:{e:#}"); }
                                }
                                _ = stop_rx => { eprintln!("收到停止信号,代理关闭"); }
                            }
                        });
                    })
                    .ok();
                self.capture_stop = Some(stop_tx);
                let lan_note = if self.proxy_lan {
                    match lan_ip() {
                        Some(ip) => format!(" · 局域网设备代理 {ip}:{port}"),
                        None => " · 已允许局域网设备".to_string(),
                    }
                } else {
                    String::new()
                };
                self.push_log(
                    LogLevel::Success,
                    "capture",
                    format!("MITM 代理已启动 · 监听 {addr} · {up_note}{lan_note}"),
                );
            }
        }

        self.store = Some(store);
        self.flow_rx = Some(rx);
        self.ws_rx = Some(ws_rx);
        self.capturing = true;
        self.cert_msg = None;
        self.demo = false; // 抓包后展示真实流量,不再是演示数据
        self.reload_flows(); // 先载入库里已有的真实流量,之后靠推流增量增长
        cx.notify();
    }

    /// 内核抓包前 BPF 未授权:弹管理员授权框(`chmod o+rw /dev/bpf*`),授权成功后**自动开始抓包**。
    ///
    /// 防循环:授权回来后只有在 `check_available()` 真的通过时才重启抓包,否则只报错、不再弹框。
    fn prompt_bpf_then_start(&mut self, cx: &mut Context<Self>) {
        if self.cert_busy {
            return;
        }
        self.cert_busy = true;
        self.cert_msg = Some("内核抓包需要 BPF 授权,请在弹窗输入管理员密码…".to_string());
        cx.notify();
        let task = cx.background_executor().spawn(async move {
            crate::cert::authorize_bpf_blocking().map_err(|e| format!("{e:#}"))
        });
        cx.spawn(async move |this, cx| {
            let res = task.await;
            let _ = this.update(cx, |this, cx| {
                this.cert_busy = false;
                match res {
                    Ok(_) if scry_sniff::check_available().is_ok() => {
                        this.push_log(LogLevel::Success, "cert", "已授权 BPF,开始内核抓包");
                        this.cert_msg = Some("已授权 BPF,开始抓包".to_string());
                        this.start_capture(cx);
                    }
                    Ok(_) => {
                        this.push_log(
                            LogLevel::Warning,
                            "cert",
                            "已授权但仍打不开 BPF,建议改用 MITM 代理模式",
                        );
                        this.cert_msg =
                            Some("已授权但仍打不开 BPF,请检查权限或改用 MITM 代理模式".to_string());
                    }
                    Err(e) => {
                        this.push_log(LogLevel::Error, "cert", format!("BPF 授权失败:{e}"));
                        this.cert_msg = Some(format!("BPF 授权失败:{e}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// 停止抓包(两种模式各自的停止)。
    pub fn stop_capture(&mut self, cx: &mut Context<Self>) {
        let was_capturing = self.capturing;
        if let Some(tx) = self.capture_stop.take() {
            let _ = tx.send(());
        }
        // 拦截收尾:停激活(唤醒阻塞的钩子放行)+ 清队列(丢弃 reply 端 → 钩子放行)+ 清编辑器。
        self.ext.disarm_intercept();
        self.intercept_rx = None;
        self.intercept_queue.clear();
        self.intercept_edit_id = None;
        self.intercept_edit.update(cx, |s, cx| s.set_text(String::new(), cx));
        if let Some(flag) = self.sniff_stop.take() {
            flag.store(true, Ordering::Relaxed);
        }
        // 收掉 scry 自己拉起的流量源(内置浏览器 / 托管程序)。
        let n_launched = self.launched.len();
        self.kill_launched();
        self.capturing = false;
        if was_capturing {
            let msg = if n_launched > 0 {
                format!("抓包已停止 · 已关闭 {n_launched} 个 scry 拉起的进程")
            } else {
                "抓包已停止".to_string()
            };
            self.push_log(LogLevel::Info, "capture", msg);
        }
        cx.notify();
    }

    /// 从库里整表重载 history(启动抓包时载入既有数据;刷新按钮手动重载)。
    ///
    /// 优先用抓包共享的 store;未抓包时打开默认库,这样「刷新」按钮在停止状态也能读盘。
    pub fn reload_flows(&mut self) {
        let v = if let Some(store) = &self.store {
            store.lock().ok().and_then(|s| s.recent(500).ok())
        } else {
            Store::open_default().ok().and_then(|s| s.recent(500).ok())
        };
        if let Some(v) = v {
            self.flows = v;
            self.demo = false;
            // 选中下标可能越界(列表变化),收敛。
            if let Some(i) = self.selected {
                if i >= self.flows.len() {
                    self.selected = (!self.flows.is_empty()).then_some(0);
                }
            }
        }
        // WebSocket 消息同样整表重载。
        let ws = if let Some(store) = &self.store {
            store.lock().ok().and_then(|s| s.recent_ws(2000).ok())
        } else {
            Store::open_default().ok().and_then(|s| s.recent_ws(2000).ok())
        };
        if let Some(ws) = ws {
            self.ws_msgs = ws;
            if let Some(i) = self.ws_selected {
                if i >= self.ws_msgs.len() {
                    self.ws_selected = (!self.ws_msgs.is_empty()).then_some(0);
                }
            }
        }
    }

    /// 从推流通道**增量**取新流量,插到表头(最新在前,与 `recent()` DESC 一致)。
    pub fn drain_new_flows(&mut self) {
        // 顺带回收已退出的拉起进程(用户关了内置浏览器 / curl 跑完),防句柄堆积 + 让「浏览器运行中」状态准确。
        self.reap_finished();
        let mut n_added = 0usize;
        // 借用 rx 期间先把新流量收集出来,借用结束后再统一记日志 + 入表(规避对 self 的双重借用)。
        let mut incoming = Vec::new();
        if let Some(rx) = &self.flow_rx {
            while let Ok(f) = rx.try_recv() {
                incoming.push(f);
            }
        }
        for f in incoming {
            self.push_flow_log(&f);
            self.flows.insert(0, f);
            n_added += 1;
        }
        if n_added > 0 {
            const MAX: usize = 2000; // 上限,防内存无限增长
            if self.flows.len() > MAX {
                self.flows.truncate(MAX);
            }
            // 表头插入会令旧选中下标后移;越界则收敛到首行。
            if let Some(i) = self.selected {
                let shifted = i + n_added;
                self.selected = if shifted < self.flows.len() {
                    Some(shifted)
                } else {
                    (!self.flows.is_empty()).then_some(0)
                };
            }
        }

        // WebSocket 消息增量(独立通道,不去重;最新在前)。
        let mut ws_in = Vec::new();
        if let Some(rx) = &self.ws_rx {
            while let Ok(m) = rx.try_recv() {
                ws_in.push(m);
            }
        }
        if !ws_in.is_empty() {
            for m in ws_in {
                self.ws_msgs.insert(0, m);
            }
            const WS_MAX: usize = 5000;
            if self.ws_msgs.len() > WS_MAX {
                self.ws_msgs.truncate(WS_MAX);
            }
        }
    }

    /// Clear:**真清空** —— 清库 + 清界面 + 排空推流积压 + 复位过滤。
    pub fn clear_flows(&mut self, cx: &mut Context<Self>) {
        if let Some(store) = &self.store {
            if let Ok(s) = store.lock() {
                let _ = s.clear();
            }
        } else if let Ok(s) = Store::open_default() {
            let _ = s.clear();
        }
        // 排空通道积压,避免清完又被旧 backlog 灌回。
        if let Some(rx) = &self.flow_rx {
            while rx.try_recv().is_ok() {}
        }
        if let Some(rx) = &self.ws_rx {
            while rx.try_recv().is_ok() {}
        }
        self.flows.clear();
        self.ws_msgs.clear();
        self.ws_selected = None;
        self.marks.clear();
        self.selected = None;
        self.demo = false;
        self.proto = Proto::All;
        self.search.update(cx, |s, cx| s.clear(cx));
        self.push_log(LogLevel::Info, "capture", "已清空历史与数据库");
        cx.notify();
    }
}

/// 代理监听配置存盘:`~/.scry/proxy.json`(监听端口 + 是否允许局域网设备)。
fn net_cfg_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home).join(".scry").join("proxy.json")
}

#[derive(serde::Serialize, serde::Deserialize)]
struct NetCfg {
    /// 代理监听端口(默认 8888)。
    port: u16,
    /// 是否绑 0.0.0.0 允许局域网设备(手机)连。
    lan: bool,
}

/// 读监听配置(文件不存在 / 损坏 → 默认 8888 + 仅本机)。供 `ScryApp::new` 启动恢复。
pub fn load_net_cfg() -> (u16, bool) {
    match std::fs::read_to_string(net_cfg_path()) {
        Ok(s) => match serde_json::from_str::<NetCfg>(&s) {
            Ok(c) => (if c.port == 0 { 8888 } else { c.port }, c.lan),
            Err(_) => (8888, false),
        },
        Err(_) => (8888, false),
    }
}

/// 保存监听配置;best-effort,失败静默。
pub fn save_net_cfg(port: u16, lan: bool) {
    let path = net_cfg_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(s) = serde_json::to_string_pretty(&NetCfg { port, lan }) {
        let _ = std::fs::write(&path, s);
    }
}

/// 本机局域网出口 IP(UDP `connect` 到公网地址仅为查路由出口,不实际发包)。供手机配置代理时显示。
pub fn lan_ip() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    sock.local_addr().ok().map(|a| a.ip().to_string())
}

/// 生成 pcapng 落盘路径:`~/.scry/capture-<unixsecs>.pcapng`(确保目录存在)。
fn pcapng_out_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    let mut dir = std::path::PathBuf::from(home);
    dir.push(".scry");
    let _ = std::fs::create_dir_all(&dir);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    dir.push(format!("capture-{ts}.pcapng"));
    Some(dir)
}
