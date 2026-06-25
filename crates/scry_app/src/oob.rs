//! OOB(带外 / out-of-band)盲注扫描 runner —— Scry 的「盲漏洞确认」杀手锏。
//!
//! 盲 SSRF / 盲 RCE / 盲 SQLi / 盲 XXE / 盲打 XSS 在响应里看不到任何回显,本 runner 用 interactsh
//! 带外服务器确认:① 生成会话(`scry_oob`)并注册;② 对当前目标的流注入带外 payload
//! (`scry_scan::oob`,每条 payload 一个唯一带外域名);③ 把探测发出去;④ 轮询带外服务器,
//! 任何「目标主动回连某带外域名」= 对应盲漏洞被确认 → 关联回探测点出 Finding。
//!
//! async 桥接同 Scanner / SQLi:后台 current-thread runtime 串行驱动 `replay::send`,经 `mpsc`
//! 流式回传状态 / 发现,前台 200ms 轮询并入;支持随时停止。带外服务器在境外,墙内需配上游代理。

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use mage_ui::prelude::*;
use scry_core::HttpFlow;
use scry_oob::{correlate, OobSession};
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};
use scry_proxy::upstream::UpstreamProxy;
use scry_scan::{Finding, OobProbeKind};

use crate::logger::LogLevel;
use crate::state::{OobMsg, ScryApp};

/// 单轮带外扫描最多发送的盲注探测数(防对目标狂轰)。
const OOB_PROBE_CAP: usize = 240;
/// 发完探测后轮询带外服务器的次数与间隔(默认 12 × 5s = 60s 等回连窗口)。
const OOB_POLLS: usize = 12;
const OOB_POLL_INTERVAL_SECS: u64 = 5;

impl ScryApp {
    /// 发起 OOB 带外盲注扫描(对当前 Scanner 目标的流)。
    pub fn run_oob_scan(&mut self, cx: &mut Context<Self>) {
        if self.oob_busy || self.scan_busy {
            return;
        }
        let scoped = self.scoped_flows();
        let has_injectable = scoped
            .iter()
            .any(|f| f.path.contains('?') || !f.req_body.is_empty());
        if scoped.is_empty() || !has_injectable {
            self.push_log(
                LogLevel::Warning,
                "oob",
                "带外扫描跳过:当前目标无可注入的请求(需带 ?参数 或请求体)",
            );
            self.oob_status = Some(
                if self.lang.is_zh() {
                    "无可注入请求(先抓带参数 / 带 body 的流量)"
                } else {
                    "No injectable requests (need query params or a body)"
                }
                .to_string(),
            );
            cx.notify();
            return;
        }

        let server = scry_oob::PUBLIC_SERVERS
            .get(self.oob_server_idx)
            .copied()
            .unwrap_or_else(scry_oob::default_server)
            .to_string();
        let up = self.upstream_proxy(cx);
        let is_zh = self.lang.is_zh();

        self.oob_busy = true;
        self.oob_status = Some(
            if is_zh {
                "生成带外会话(RSA)…"
            } else {
                "Creating OOB session (RSA)…"
            }
            .to_string(),
        );
        let ctrl = Arc::new(AtomicBool::new(false));
        self.oob_ctrl = Some(ctrl.clone());
        let (tx, rx) = mpsc::channel::<OobMsg>();
        self.oob_rx = Some(rx);
        self.push_log(
            LogLevel::Info,
            "oob",
            format!("带外扫描开始 · 服务器 {server} · {} 条目标流", scoped.len()),
        );
        cx.notify();

        // 后台:注册 → 注入并发送探测 → 轮询回连。
        cx.background_executor()
            .spawn(async move {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => return,
                };
                rt.block_on(oob_worker(server, scoped, up, ctrl, tx, is_zh));
            })
            .detach();

        // 前台:把状态 / 发现并入,直到后台收尾。
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(200))
                    .await;
                let keep = this.update(cx, |this, cx| {
                    this.drain_oob_results();
                    cx.notify();
                    this.oob_busy
                });
                match keep {
                    Ok(true) => continue,
                    _ => break,
                }
            }
        })
        .detach();
    }

    /// 停止带外扫描(置停止位 + 丢弃接收端)。
    pub fn stop_oob_scan(&mut self, cx: &mut Context<Self>) {
        if !self.oob_busy {
            return;
        }
        if let Some(ctrl) = &self.oob_ctrl {
            ctrl.store(true, Ordering::Relaxed);
        }
        self.oob_busy = false;
        self.oob_rx = None;
        self.oob_ctrl = None;
        self.push_log(LogLevel::Warning, "oob", "带外扫描已停止");
        cx.notify();
    }

    /// 把通道里已到的状态 / 发现并入;后台收尾则结束。
    fn drain_oob_results(&mut self) {
        let Some(rx) = &self.oob_rx else {
            return;
        };
        let mut new_findings: Vec<Finding> = Vec::new();
        let mut finished = false;
        let mut last_status: Option<String> = None;
        while let Ok(msg) = rx.try_recv() {
            if let Some(s) = msg.status {
                last_status = Some(s);
            }
            if let Some(f) = msg.finding {
                new_findings.push(f);
            }
            if msg.done {
                finished = true;
            }
        }
        if let Some(s) = last_status {
            self.oob_status = Some(s);
        }
        if !new_findings.is_empty() {
            for f in &new_findings {
                self.push_log(
                    LogLevel::Success,
                    "oob",
                    format!("带外回连确认:{} · {}", self.lang.t(f.title), f.url),
                );
            }
            self.scan_findings.extend(new_findings);
            crate::scanner::merge_sort_findings(&mut self.scan_findings);
            self.scan_ran = true;
        }
        if finished {
            self.oob_busy = false;
            self.oob_rx = None;
            self.oob_ctrl = None;
        }
    }
}

/// 后台带外扫描主流程(注册 → 发探测 → 轮询)。
async fn oob_worker(
    server: String,
    scoped: Vec<HttpFlow>,
    up: Option<UpstreamProxy>,
    ctrl: Arc<AtomicBool>,
    tx: mpsc::Sender<OobMsg>,
    is_zh: bool,
) {
    macro_rules! status {
        ($s:expr) => {{
            let _ = tx.send(OobMsg {
                status: Some($s),
                finding: None,
                done: false,
            });
        }};
    }
    macro_rules! end {
        ($s:expr) => {{
            let _ = tx.send(OobMsg {
                status: $s,
                finding: None,
                done: true,
            });
            return;
        }};
    }

    // 1) 生成会话(RSA-2048 keygen)。
    let session = match OobSession::generate(&server) {
        Ok(s) => s,
        Err(e) => end!(Some(format!(
            "{}: {e}",
            if is_zh { "会话生成失败" } else { "session failed" }
        ))),
    };
    let cfg = ReplayConfig {
        upstream: up,
        ..Default::default()
    };

    // 2) 注册(上报公钥 + secret + 关联 id)。
    let reg_body = session.register_body().into_bytes();
    let reg_headers = vec![
        ("Host".to_string(), server.clone()),
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Content-Length".to_string(), reg_body.len().to_string()),
        ("User-Agent".to_string(), "scry-oob".to_string()),
    ];
    let Some(reg) = ReplayRequest::from_url("POST", &session.register_url(), reg_headers, reg_body)
    else {
        end!(Some("bad register url".to_string()))
    };
    match replay::send(&reg, &cfg).await {
        Ok(resp) if resp.status == 200 || resp.status == 201 => {}
        Ok(resp) => end!(Some(format!(
            "{} (HTTP {})",
            if is_zh {
                "带外注册被拒"
            } else {
                "OOB register rejected"
            },
            resp.status
        ))),
        Err(e) => end!(Some(format!(
            "{}: {e}",
            if is_zh {
                "带外服务器连不上(墙内需在设置里配上游代理)"
            } else {
                "OOB server unreachable (set an upstream proxy)"
            }
        ))),
    }
    status!(format!(
        "{} {}.{}",
        if is_zh { "会话就绪 ·" } else { "session ·" },
        session.correlation_id(),
        server
    ));

    // 3) 生成带外探测 + 记录关联表(带外 id → 漏洞类型 / URL / 参数)。
    let mut map: HashMap<String, (OobProbeKind, String, String)> = HashMap::new();
    let mut probes = Vec::new();
    'gen: for f in &scoped {
        let alloc = || {
            let p = session.new_payload();
            (p.host, p.id)
        };
        for probe in scry_scan::generate_oob_probes(f, alloc) {
            map.insert(
                probe.oob_id.clone(),
                (probe.kind, probe.flow.url(), probe.param.clone()),
            );
            probes.push(probe);
            if probes.len() >= OOB_PROBE_CAP {
                break 'gen;
            }
        }
    }
    let total = probes.len();

    // 4) 发送探测(忽略响应,确认全靠带外回连)。
    for (i, probe) in probes.iter().enumerate() {
        if ctrl.load(Ordering::Relaxed) {
            end!(None);
        }
        let req = ReplayRequest::from_flow(&probe.flow);
        let _ = replay::send(&req, &cfg).await;
        if (i + 1) % 10 == 0 || i + 1 == total {
            status!(format!(
                "{} {}/{}",
                if is_zh { "发送探测" } else { "sending" },
                i + 1,
                total
            ));
        }
    }

    // 5) 轮询带外服务器看回连(逐秒可停)。
    let mut seen: HashSet<String> = HashSet::new();
    let mut hits = 0usize;
    for k in 0..OOB_POLLS {
        for _ in 0..OOB_POLL_INTERVAL_SECS {
            if ctrl.load(Ordering::Relaxed) {
                end!(None);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let poll_headers = vec![
            ("Host".to_string(), server.clone()),
            ("User-Agent".to_string(), "scry-oob".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        let Some(poll) = ReplayRequest::from_url("GET", &session.poll_url(), poll_headers, vec![])
        else {
            continue;
        };
        if let Ok(resp) = replay::send(&poll, &cfg).await {
            let body = String::from_utf8_lossy(&resp.resp_body);
            if let Ok(interactions) = session.parse_poll(&body) {
                for (it, info) in correlate(&interactions, &map) {
                    let key = format!("{}|{}|{}", it.unique_id, it.protocol, it.remote_address);
                    if !seen.insert(key) {
                        continue;
                    }
                    hits += 1;
                    let (kind, url, param) = info;
                    let detail = if is_zh {
                        format!(
                            "目标对带外域名发起了 {} 回连(参数 '{}',来自 {});盲漏洞已确认",
                            it.protocol.to_uppercase(),
                            param,
                            it.remote_address
                        )
                    } else {
                        format!(
                            "Target made a {} callback to our OOB domain (param '{}', from {}); blind vuln confirmed",
                            it.protocol.to_uppercase(),
                            param,
                            it.remote_address
                        )
                    };
                    let _ = tx.send(OobMsg {
                        status: None,
                        finding: Some(Finding::new(
                            kind.rule_id(),
                            kind.title(),
                            kind.severity(),
                            url.clone(),
                            detail,
                        )),
                        done: false,
                    });
                }
            }
        }
        status!(format!(
            "{} {}/{} · {} {}",
            if is_zh { "轮询" } else { "polling" },
            k + 1,
            OOB_POLLS,
            hits,
            if is_zh { "命中" } else { "hits" }
        ));
    }

    // 6) 注销(best-effort)+ 收尾。
    let dreg_body = session.deregister_body().into_bytes();
    let dreg_headers = vec![
        ("Host".to_string(), server.clone()),
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Content-Length".to_string(), dreg_body.len().to_string()),
        ("User-Agent".to_string(), "scry-oob".to_string()),
    ];
    if let Some(dreg) =
        ReplayRequest::from_url("POST", &session.deregister_url(), dreg_headers, dreg_body)
    {
        let _ = replay::send(&dreg, &cfg).await;
    }
    end!(Some(format!(
        "{} · {} {}",
        if is_zh {
            "带外扫描完成"
        } else {
            "OOB scan done"
        },
        hits,
        if is_zh { "命中" } else { "hits" }
    )));
}
