//! 扩展系统(Extender)—— 宿主侧实现。
//!
//! - [`ExtRegistry`]:加载 / 启停扩展,实现 [`scry_ext_api::ExtensionHost`],按加载顺序 fan-out 到各扩展;
//!   把扩展产生的日志 / findings 收进线程安全缓冲(供 UI 读)。`Arc<ExtRegistry>` 注入 `ProxyConfig.hooks`。
//! - P0 内置两个演示扩展:被动密钥扫描(只读,默认开)/ 请求标记(改包演示,默认关)。
//! - native dylib / WASM / 外部进程(Python)Runner 见 `docs/设计-扩展系统.md`(P1/P2/P3)。

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use mage_ui::gpui::Div;
use mage_ui::prelude::*;

use scry_core::HttpFlow;
use scry_ext_api::{
    ExtKind, ExtManifest, Extension, ExtensionHost, Finding, HookAction, HostServices,
    LogLevel as ExtLevel, Permission, Severity, SynthResponse,
};

use crate::rules::{
    should_intercept, CompiledMap, CompiledReplace, CompiledScope, MapResult, MapRule, ReplaceRule,
    ScopeRule,
};
use crate::state::ScryApp;
use crate::widgets::section_label;

// ───────────────────────── 注册表(= ExtensionHost) ─────────────────────────

/// 一条扩展产生的事件(日志 / 发现),由宿主汇聚后供 UI 展示。
#[derive(Clone)]
pub struct ExtEvent {
    pub ext_name: String,
    pub level: ExtLevel,
    pub text: String,
    pub finding: bool,
}

// ───────────────────────── 交互式拦截(Intercept 断点队列) ─────────────────────────

/// 拦截方向:请求(转发前)/ 响应(回传前)。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InterceptDir {
    Request,
    Response,
}

/// 用户对一条被拦截报文的决策(经 [`InterceptItem::reply`] 回传给阻塞中的代理线程)。
pub enum InterceptDecision {
    /// 放行:携带(可能已被用户编辑过的)flow。
    Forward(Box<HttpFlow>),
    /// 丢弃:不转发,直接断连。
    Drop,
}

/// 一条被拦截、正等用户处理的报文。
///
/// 代理线程在 `on_request` / `on_response` 里把它发给 UI 后**阻塞**等 `reply`;
/// UI 展示 + 编辑后,通过 `reply` 回传 [`InterceptDecision`] 解除阻塞。
pub struct InterceptItem {
    pub id: u64,
    pub dir: InterceptDir,
    /// 被拦截报文的快照(供 UI 展示 / 编辑)。
    pub flow: HttpFlow,
    /// 决策回传端(放行改后的 flow / 丢弃)。
    pub reply: std::sync::mpsc::Sender<InterceptDecision>,
}

/// UI 用的一行扩展概览(从 manifest + 运行态拍平,避免 UI 直接借 trait 对象)。
#[derive(Clone)]
pub struct ExtRow {
    pub name: String,
    pub version: String,
    pub description: String,
    pub kind: ExtKind,
    pub enabled: bool,
    pub hits: u64,
    pub permissions: Vec<String>,
    pub hooks: Vec<String>,
}

/// 已加载的一个扩展 + 运行态(启停 / 命中计数,内部可变,供 proxy 线程并发访问)。
struct LoadedExt {
    ext: Box<dyn Extension>,
    enabled: AtomicBool,
    hits: AtomicU64,
}

impl LoadedExt {
    fn new(ext: Box<dyn Extension>, enabled: bool) -> Self {
        Self {
            ext,
            enabled: AtomicBool::new(enabled),
            hits: AtomicU64::new(0),
        }
    }
}

/// 扩展注册表:`scry_proxy` 只认它实现的 [`ExtensionHost`];UI 经 `Arc` 共享读取运行态。
pub struct ExtRegistry {
    exts: Vec<LoadedExt>,
    events: Mutex<VecDeque<ExtEvent>>,
    /// 扩展私有设置:键为 `"{ext_id}.{field_key}"`。P0 仅装载 manifest 默认值。
    settings: Mutex<HashMap<String, String>>,
    /// 抓包当前的上游代理(供扩展 `send_request` 与抓包同源出网;抓包启动时由 `set_upstream` 注入)。
    upstream: Mutex<Option<scry_proxy::upstream::UpstreamProxy>>,
    /// 交互式拦截:是否拦请求 / 拦响应(UI 开关,proxy 线程每次钩子读取)。
    intercept_req: AtomicBool,
    intercept_resp: AtomicBool,
    /// 拦截总开关:抓包期间为 true;停止抓包置 false 以**唤醒所有阻塞中的钩子**放行收尾。
    intercept_active: AtomicBool,
    /// 把被拦报文发给 UI 的通道(抓包启动时由 `arm_intercept` 装上;UI 持 Receiver)。
    intercept_tx: Mutex<Option<std::sync::mpsc::Sender<InterceptItem>>>,
    /// 拦截项自增 id(给 UI 区分队列项)。
    intercept_seq: AtomicU64,
    /// 自定义拦截范围(编译快照;UI 改规则 / 抓包启动时推入,引擎逐请求只读)。
    scope_rules: Mutex<Vec<CompiledScope>>,
    /// Match & Replace 自动改包规则(编译快照)。
    replace_rules: Mutex<Vec<CompiledReplace>>,
    /// Map Local / Map Remote / Mock 规则(编译快照)。
    map_rules: Mutex<Vec<CompiledMap>>,
}

impl ExtRegistry {
    /// 装载内置扩展(P0)+ 发现并拉起 `~/.scry/extensions` 下的进程扩展(P1)。
    pub fn with_builtins() -> Self {
        let mut exts = vec![
            LoadedExt::new(Box::new(PassiveSecretScan::new()), true),
            LoadedExt::new(Box::new(RequestTagger::new()), false),
        ];
        // 发现并加载外部进程扩展(Python 等);默认目录不存在则跳过(零额外进程)。
        let mut boot: VecDeque<ExtEvent> = VecDeque::new();
        if let Some(dir) = scry_ext_host::default_ext_dir() {
            for d in scry_ext_host::discover(&dir) {
                match d.result {
                    Ok(ext) => {
                        boot.push_front(ExtEvent {
                            ext_name: "扩展加载".to_string(),
                            level: ExtLevel::Success,
                            text: format!("已加载进程扩展 {}", d.dir_name),
                            finding: false,
                        });
                        exts.push(LoadedExt::new(ext, true));
                    }
                    Err(e) => {
                        boot.push_front(ExtEvent {
                            ext_name: "扩展加载".to_string(),
                            level: ExtLevel::Error,
                            text: format!("加载 {} 失败:{e}", d.dir_name),
                            finding: false,
                        });
                    }
                }
            }
        }
        let mut map = HashMap::new();
        for le in &exts {
            let m = le.ext.manifest();
            for f in &m.settings_schema {
                map.insert(format!("{}.{}", m.id, f.key), f.default.clone());
            }
        }
        Self {
            exts,
            events: Mutex::new(boot),
            settings: Mutex::new(map),
            upstream: Mutex::new(None),
            intercept_req: AtomicBool::new(false),
            intercept_resp: AtomicBool::new(false),
            intercept_active: AtomicBool::new(false),
            intercept_tx: Mutex::new(None),
            intercept_seq: AtomicU64::new(0),
            scope_rules: Mutex::new(Vec::new()),
            replace_rules: Mutex::new(Vec::new()),
            map_rules: Mutex::new(Vec::new()),
        }
    }

    // ── 拦截规则(自定义范围 + Match & Replace) ──

    /// 更新自定义拦截范围规则(UI 增删 / 启停或抓包启动时调用):传入纯规则,内部编译为快照。
    pub fn set_scope_rules(&self, rules: &[ScopeRule]) {
        let compiled: Vec<CompiledScope> = rules.iter().map(|r| r.compile()).collect();
        if let Ok(mut g) = self.scope_rules.lock() {
            *g = compiled;
        }
    }

    /// 更新 Match & Replace 规则(同上)。
    pub fn set_replace_rules(&self, rules: &[ReplaceRule]) {
        let compiled: Vec<CompiledReplace> = rules.iter().map(|r| r.compile()).collect();
        if let Ok(mut g) = self.replace_rules.lock() {
            *g = compiled;
        }
    }

    /// 在钩子里应用 Match & Replace(`is_request` 决定请求向 / 响应向规则)。
    fn apply_replace(&self, flow: &mut HttpFlow, is_request: bool) {
        if let Ok(rules) = self.replace_rules.lock() {
            for r in rules.iter() {
                if r.enabled && r.target.is_request() == is_request {
                    r.apply(flow);
                }
            }
        }
    }

    /// 是否存在启用的「响应向」Match & Replace 规则(用于门控 `wants_response_hook`)。
    fn has_response_replace(&self) -> bool {
        self.replace_rules
            .lock()
            .map(|rules| rules.iter().any(|r| r.enabled && !r.target.is_request()))
            .unwrap_or(false)
    }

    /// 更新 Map Local / Map Remote / Mock 规则(同 scope/replace)。
    pub fn set_map_rules(&self, rules: &[MapRule]) {
        let compiled: Vec<CompiledMap> = rules.iter().map(|r| r.compile()).collect();
        if let Ok(mut g) = self.map_rules.lock() {
            *g = compiled;
        }
    }

    /// 在 `on_request` 里求值 Map Local / Mock:命中则返回短路响应(`Respond`),否则 `None`。
    /// Map Remote 不在此处(它在连上游前经 [`ExtensionHost::remap_target`] 改目标)。
    fn map_respond(&self, flow: &HttpFlow) -> Option<HookAction> {
        let rules = self.map_rules.lock().ok()?;
        for r in rules.iter() {
            match r.eval_respond(flow) {
                MapResult::NoMatch => continue,
                MapResult::Mock {
                    status,
                    headers,
                    body,
                } => {
                    return Some(HookAction::Respond(SynthResponse {
                        status,
                        headers,
                        body,
                    }))
                }
                MapResult::LocalFile { path, content_type } => match std::fs::read(&path) {
                    Ok(body) => {
                        return Some(HookAction::Respond(SynthResponse {
                            status: 200,
                            headers: vec![("Content-Type".to_string(), content_type)],
                            body,
                        }))
                    }
                    // 文件读不到 → 跳过该规则(不短路,继续走真实请求)。
                    Err(_) => continue,
                },
            }
        }
        None
    }

    // ── 交互式拦截(Intercept) ──

    /// 设置拦截开关(UI 调用):是否拦请求 / 拦响应。
    pub fn set_intercept(&self, req: bool, resp: bool) {
        self.intercept_req.store(req, Ordering::Relaxed);
        self.intercept_resp.store(resp, Ordering::Relaxed);
    }

    /// 当前拦截开关 `(请求, 响应)`。
    pub fn intercept_flags(&self) -> (bool, bool) {
        (
            self.intercept_req.load(Ordering::Relaxed),
            self.intercept_resp.load(Ordering::Relaxed),
        )
    }

    /// 抓包启动:装上拦截回传通道并激活(UI 持配对的 Receiver)。
    pub fn arm_intercept(&self, tx: std::sync::mpsc::Sender<InterceptItem>) {
        if let Ok(mut g) = self.intercept_tx.lock() {
            *g = Some(tx);
        }
        self.intercept_active.store(true, Ordering::Relaxed);
    }

    /// 抓包停止:停激活(令所有阻塞中的钩子在 ≤150ms 内放行收尾)+ 摘掉通道。
    pub fn disarm_intercept(&self) {
        self.intercept_active.store(false, Ordering::Relaxed);
        if let Ok(mut g) = self.intercept_tx.lock() {
            *g = None;
        }
    }

    /// 在钩子里按方向决定是否拦截:命中则把报文发 UI 并**阻塞**等用户决策。
    ///
    /// 关键(线程模型):本方法在代理的 tokio worker 线程同步调用,阻塞期间只占用该 worker;
    /// 多线程 runtime 仍可处理其它连接。停止抓包(`disarm_intercept`)会令循环退出放行,避免析构卡死。
    fn maybe_intercept(&self, flow: &mut HttpFlow, dir: InterceptDir) -> HookAction {
        let want = match dir {
            InterceptDir::Request => self.intercept_req.load(Ordering::Relaxed),
            InterceptDir::Response => self.intercept_resp.load(Ordering::Relaxed),
        };
        if !want || !self.intercept_active.load(Ordering::Relaxed) {
            return HookAction::Continue;
        }
        // 自定义拦截范围:有规则时只暂停匹配的流(无规则 = 拦该方向全部,保持旧行为)。
        let in_scope = self
            .scope_rules
            .lock()
            .map(|rules| should_intercept(flow, dir, &rules, true))
            .unwrap_or(true);
        if !in_scope {
            return HookAction::Continue;
        }
        let tx = match self.intercept_tx.lock() {
            Ok(g) => g.clone(),
            Err(_) => None,
        };
        let Some(tx) = tx else {
            return HookAction::Continue;
        };
        let (rtx, rrx) = std::sync::mpsc::channel();
        let id = self.intercept_seq.fetch_add(1, Ordering::Relaxed);
        if tx
            .send(InterceptItem {
                id,
                dir,
                flow: flow.clone(),
                reply: rtx,
            })
            .is_err()
        {
            return HookAction::Continue; // UI 端已不在,放行
        }
        loop {
            // 抓包停止 → 放行收尾(不能让 worker 永久阻塞,否则 runtime 析构卡死)。
            if !self.intercept_active.load(Ordering::Relaxed) {
                return HookAction::Continue;
            }
            match rrx.recv_timeout(std::time::Duration::from_millis(150)) {
                Ok(InterceptDecision::Forward(f)) => {
                    *flow = *f;
                    return HookAction::Continue;
                }
                Ok(InterceptDecision::Drop) => return HookAction::Drop,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return HookAction::Continue; // UI 丢弃了该项 → 放行
                }
            }
        }
    }

    /// 抓包启动时注入当前上游代理(供扩展 `send_request` 与抓包同源出网,墙内才出得去)。
    pub fn set_upstream(&self, up: Option<scry_proxy::upstream::UpstreamProxy>) {
        if let Ok(mut g) = self.upstream.lock() {
            *g = up;
        }
    }

    fn push_event(&self, ev: ExtEvent) {
        if let Ok(mut q) = self.events.lock() {
            q.push_front(ev);
            while q.len() > 200 {
                q.pop_back();
            }
        }
    }

    // ── UI 只读访问 ──

    pub fn rows(&self) -> Vec<ExtRow> {
        self.exts
            .iter()
            .map(|le| {
                let m = le.ext.manifest();
                ExtRow {
                    name: m.name.clone(),
                    version: m.version.clone(),
                    description: m.description.clone(),
                    kind: m.kind,
                    enabled: le.enabled.load(Ordering::Relaxed),
                    hits: le.hits.load(Ordering::Relaxed),
                    permissions: m.permissions.iter().map(perm_label).collect(),
                    hooks: m.hooks.clone(),
                }
            })
            .collect()
    }

    /// 切换第 `idx` 个扩展的启停(原子,供 UI 线程调用)。
    pub fn toggle(&self, idx: usize) {
        if let Some(le) = self.exts.get(idx) {
            let cur = le.enabled.load(Ordering::Relaxed);
            le.enabled.store(!cur, Ordering::Relaxed);
        }
    }

    pub fn recent_events(&self, n: usize) -> Vec<ExtEvent> {
        self.events
            .lock()
            .map(|q| q.iter().take(n).cloned().collect())
            .unwrap_or_default()
    }

    pub fn enabled_count(&self) -> usize {
        self.exts
            .iter()
            .filter(|le| le.enabled.load(Ordering::Relaxed))
            .count()
    }
}

/// 给某个扩展在一次钩子调用期间使用的 [`HostServices`]:把副作用收进注册表缓冲(线程安全)。
struct Collector<'a> {
    reg: &'a ExtRegistry,
    ext_id: String,
    ext_name: String,
}

impl HostServices for Collector<'_> {
    fn log(&mut self, level: ExtLevel, msg: &str) {
        self.reg.push_event(ExtEvent {
            ext_name: self.ext_name.clone(),
            level,
            text: msg.to_string(),
            finding: false,
        });
    }

    fn emit_finding(&mut self, finding: Finding) {
        self.reg.push_event(ExtEvent {
            ext_name: self.ext_name.clone(),
            level: severity_level(finding.severity),
            text: format!("{} — {} [{}]", finding.title, finding.detail, finding.url),
            finding: true,
        });
    }

    fn get_setting(&self, key: &str) -> Option<String> {
        self.reg
            .settings
            .lock()
            .ok()?
            .get(&format!("{}.{}", self.ext_id, key))
            .cloned()
    }

    fn set_kv(&mut self, key: &str, val: &str) {
        if let Ok(mut s) = self.reg.settings.lock() {
            s.insert(format!("{}.{}", self.ext_id, key), val.to_string());
        }
    }

    /// 扩展主动发包:解析 URL → 复用 `scry_proxy::replay`(与抓包同上游),在抓包 runtime 上跑。
    ///
    /// 钩子是同步调用、但身处抓包的多线程 tokio runtime 内:把 async `replay::send` `spawn` 到该 runtime,
    /// 用 std 通道 `recv_timeout` 同步等结果(另一 worker 执行,不死锁)。
    fn send_request(&mut self, req: scry_ext_api::ExtRequest) -> scry_ext_api::ExtResponse {
        use scry_ext_api::ExtResponse;
        let rr = match scry_proxy::replay::ReplayRequest::from_url(
            &req.method,
            &req.url,
            req.headers,
            req.body,
        ) {
            Some(r) => r,
            None => return ExtResponse::error(format!("无法解析 URL:{}", req.url)),
        };
        let upstream = self.reg.upstream.lock().ok().and_then(|g| g.clone());
        let cfg = scry_proxy::replay::ReplayConfig {
            upstream,
            ..Default::default()
        };
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(h) => h,
            Err(_) => return ExtResponse::error("send_request 需在抓包运行时内调用"),
        };
        let (tx, rx) = std::sync::mpsc::channel();
        handle.spawn(async move {
            let _ = tx.send(scry_proxy::replay::send(&rr, &cfg).await);
        });
        match rx.recv_timeout(std::time::Duration::from_secs(35)) {
            Ok(Ok(flow)) => ExtResponse {
                status: flow.status,
                headers: flow.resp_headers,
                body: flow.resp_body,
                error: None,
            },
            Ok(Err(e)) => ExtResponse::error(format!("{e:#}")),
            Err(_) => ExtResponse::error("send_request 超时/无响应"),
        }
    }
}

impl ExtRegistry {
    fn collector(&self, le: &LoadedExt) -> Collector<'_> {
        let m = le.ext.manifest();
        Collector {
            reg: self,
            ext_id: m.id.clone(),
            ext_name: m.name.clone(),
        }
    }
}

impl ExtensionHost for ExtRegistry {
    fn on_request(&self, flow: &mut HttpFlow) -> HookAction {
        for le in &self.exts {
            if !le.enabled.load(Ordering::Relaxed) {
                continue;
            }
            let mut col = self.collector(le);
            match le.ext.on_request(flow, &mut col) {
                HookAction::Continue => {}
                other => return other, // 第一个决定性动作(Drop/Respond/Pause)生效
            }
        }
        // Map Local / Mock:命中则用本地文件 / 内联响应短路返回(在 Match & Replace 之前)。
        if let Some(action) = self.map_respond(flow) {
            return action;
        }
        // 自动改包(Match & Replace,请求向规则)在扩展之后、交互式拦截之前应用,
        // 这样用户在「拦截」页看到的就是替换后的报文。
        self.apply_replace(flow, true);
        // 扩展放行后,再走交互式拦截(开了拦请求才暂停等用户改包)。
        self.maybe_intercept(flow, InterceptDir::Request)
    }

    fn on_response(&self, flow: &mut HttpFlow) -> HookAction {
        for le in &self.exts {
            if !le.enabled.load(Ordering::Relaxed) {
                continue;
            }
            let mut col = self.collector(le);
            match le.ext.on_response(flow, &mut col) {
                HookAction::Continue => {}
                other => return other,
            }
        }
        // 自动改包(Match & Replace,响应向规则)。
        self.apply_replace(flow, false);
        self.maybe_intercept(flow, InterceptDir::Response)
    }

    fn on_flow_complete(&self, flow: &HttpFlow) {
        for le in &self.exts {
            if !le.enabled.load(Ordering::Relaxed) {
                continue;
            }
            le.hits.fetch_add(1, Ordering::Relaxed);
            let mut col = self.collector(le);
            le.ext.on_flow_complete(flow, &mut col);
        }
    }

    fn wants_response_hook(&self) -> bool {
        // 开了「拦截响应」、存在响应向 Match & Replace 规则、或任一扩展声明了 on_response,
        // 都需要代理重建响应字节(否则改后内容不生效)。
        self.intercept_resp.load(Ordering::Relaxed)
            || self.has_response_replace()
            || self.exts.iter().any(|le| {
                le.enabled.load(Ordering::Relaxed)
                    && le.ext.manifest().hooks.iter().any(|h| h == "on_response")
            })
    }

    fn remap_target(&self, host: &str, port: u16) -> Option<(String, u16)> {
        let rules = self.map_rules.lock().ok()?;
        // 用「仅含 host/port」的探针流匹配 Remote 规则的条件(典型按 Host / URL 前缀)。
        let probe = HttpFlow::request("GET", "https", host, port, "/", vec![], vec![]);
        for r in rules.iter() {
            if let Some(target) = r.remote_target(&probe) {
                return Some(target);
            }
        }
        None
    }
}

// ───────────────────────── 内置扩展(P0 演示) ─────────────────────────

/// 被动密钥扫描:只读扫描请求里的疑似凭据,命中即上报 finding。默认开启(零风险)。
struct PassiveSecretScan {
    m: ExtManifest,
}

impl PassiveSecretScan {
    fn new() -> Self {
        Self {
            m: ExtManifest::builtin(
                "passive-secret-scan",
                "被动密钥扫描",
                "0.1.0",
                "被动扫描请求中的疑似凭据(Authorization / Cookie / token / password / api_key)",
            )
            .with_permissions(vec![Permission::TrafficRead])
            .with_hooks(&["on_flow_complete"]),
        }
    }
}

impl Extension for PassiveSecretScan {
    fn manifest(&self) -> &ExtManifest {
        &self.m
    }

    fn on_flow_complete(&self, flow: &HttpFlow, host: &mut dyn HostServices) {
        let mut hits: Vec<String> = Vec::new();
        for (k, _v) in flow.req_headers.iter() {
            let lk = k.to_ascii_lowercase();
            if lk == "authorization" || lk == "cookie" || lk == "x-api-key" {
                hits.push(format!("header:{lk}"));
            }
        }
        let url_l = flow.url().to_ascii_lowercase();
        let body_l = String::from_utf8_lossy(&flow.req_body).to_ascii_lowercase();
        for kw in ["token", "password", "passwd", "secret", "api_key", "apikey", "access_token"] {
            if url_l.contains(kw) {
                hits.push(format!("url:{kw}"));
            }
            if body_l.contains(kw) {
                hits.push(format!("body:{kw}"));
            }
        }
        if !hits.is_empty() {
            hits.sort();
            hits.dedup();
            host.emit_finding(Finding {
                severity: Severity::Low,
                title: "疑似敏感信息".to_string(),
                detail: hits.join(", "),
                url: flow.url(),
            });
        }
    }
}

/// 请求标记:给每个请求加 `X-Scry-Ext` 头,演示扩展可改写**实时流量**。默认关闭(改包需用户主动启用)。
struct RequestTagger {
    m: ExtManifest,
}

impl RequestTagger {
    fn new() -> Self {
        Self {
            m: ExtManifest::builtin(
                "request-tagger",
                "请求标记(改包演示)",
                "0.1.0",
                "给每个请求加一个 X-Scry-Ext 头,演示扩展可改写实时流量(默认关闭)",
            )
            .with_permissions(vec![Permission::TrafficModify])
            .with_hooks(&["on_request"]),
        }
    }
}

impl Extension for RequestTagger {
    fn manifest(&self) -> &ExtManifest {
        &self.m
    }

    fn on_request(&self, flow: &mut HttpFlow, host: &mut dyn HostServices) -> HookAction {
        flow.req_headers
            .push(("X-Scry-Ext".to_string(), "request-tagger".to_string()));
        host.log(ExtLevel::Debug, &format!("已标记请求 {}", flow.url()));
        HookAction::Continue
    }
}

// ───────────────────────── 标签 / 颜色辅助 ─────────────────────────

fn perm_label(p: &Permission) -> String {
    match p {
        Permission::TrafficRead => "读流量".to_string(),
        Permission::TrafficModify => "改流量".to_string(),
        Permission::NetOutbound => "外联".to_string(),
        Permission::Storage => "存储".to_string(),
        Permission::FsRead(path) => format!("读:{path}"),
        Permission::FsWrite(path) => format!("写:{path}"),
    }
}

fn kind_label(k: ExtKind) -> &'static str {
    match k {
        ExtKind::Builtin => "内置",
        ExtKind::Native => "Native",
        ExtKind::Wasm => "WASM",
        ExtKind::Process => "进程",
    }
}

fn severity_level(s: Severity) -> ExtLevel {
    match s {
        Severity::Critical | Severity::High => ExtLevel::Error,
        Severity::Medium => ExtLevel::Warning,
        Severity::Low => ExtLevel::Info,
        Severity::Info => ExtLevel::Debug,
    }
}

fn level_color(level: ExtLevel, c: ThemeColors) -> Hsla {
    match level {
        ExtLevel::Error => c.danger,
        ExtLevel::Warning => c.warning,
        ExtLevel::Success => c.success,
        ExtLevel::Info => c.text_muted,
        ExtLevel::Debug => c.text_subtle,
    }
}

/// 一张卡(实色面板 + 描边 + 圆角)。
fn card(c: ThemeColors, t: Tokens) -> Div {
    div()
        .flex()
        .flex_col()
        .gap(t.space.md)
        .p(t.space.lg)
        .rounded(t.radius.xl)
        .bg(c.surface)
        .border_1()
        .border_color(c.border)
}

/// 一个彩色小标签(权限 / 钩子 / 类型)。
fn chip(text: impl Into<SharedString>, color: Hsla, t: Tokens) -> Div {
    div()
        .flex_shrink_0()
        .px(t.space.sm)
        .py(px(1.0))
        .rounded(t.radius.full)
        .bg(color.opacity(0.14))
        .border_1()
        .border_color(color.opacity(0.30))
        .text_size(t.font_size.xs)
        .text_color(color)
        .child(text.into())
}

// ───────────────────────── Extender 页(UI) ─────────────────────────

impl ScryApp {
    /// Extender 页:扩展列表(启停 / 权限 / 命中)+ 近期活动 + 运行时路线图。
    pub fn extender_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let rows = self.ext.rows();

        // 头部卡:标题 + 概览。
        let header = card(c, t)
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap(t.space.sm)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(t.space.sm)
                            .child(Icon::new(IconName::Package).size(px(18.0)).color(c.text))
                            .child(
                                div()
                                    .text_size(t.font_size.lg)
                                    .text_color(c.text)
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child("扩展 / Extender"),
                            ),
                    )
                    .child(
                        div()
                            .text_size(t.font_size.sm)
                            .text_color(c.text_subtle)
                            .child(format!(
                                "已启用 {} · 共 {}",
                                self.ext.enabled_count(),
                                rows.len()
                            )),
                    ),
            )
            .child(
                div()
                    .text_size(t.font_size.sm)
                    .text_color(c.text_muted)
                    .child(
                        "扩展在抓包内核的三个接缝(on_request / on_response / on_flow_complete)运行。\
                         三种运行时:内置(随包)/ WASM 沙箱 / 外部进程(Python 等)—— 见 docs/设计-扩展系统.md。",
                    ),
            );

        // 扩展列表。
        let mut ext_cards: Vec<Div> = Vec::new();
        for (idx, r) in rows.iter().enumerate() {
            let kind_color = if r.kind == ExtKind::Builtin {
                c.success
            } else {
                c.text_subtle
            };
            let mut chips: Vec<Div> = vec![chip(kind_label(r.kind), kind_color, t)];
            for p in &r.permissions {
                let pc = if p == "改流量" || p.starts_with("写:") {
                    c.warning
                } else {
                    c.text_subtle
                };
                chips.push(chip(p.clone(), pc, t));
            }
            for h in &r.hooks {
                chips.push(chip(h.clone(), c.text_subtle, t));
            }

            let toggle_id = SharedString::from(format!("ext-toggle-{idx}"));
            let enabled = r.enabled;
            let head = div()
                .flex()
                .items_center()
                .justify_between()
                .gap(t.space.sm)
                .child(
                    div()
                        .flex()
                        .items_baseline()
                        .gap(t.space.sm)
                        .min_w(px(0.0))
                        .child(
                            div()
                                .text_size(t.font_size.md)
                                .text_color(c.text)
                                .font_weight(FontWeight::SEMIBOLD)
                                .child(r.name.clone()),
                        )
                        .child(
                            div()
                                .text_size(t.font_size.xs)
                                .text_color(c.text_subtle)
                                .child(format!("v{}", r.version)),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(t.space.sm)
                        .child(
                            div()
                                .text_size(t.font_size.xs)
                                .text_color(c.text_subtle)
                                .child(format!("命中 {}", r.hits)),
                        )
                        .child(Switch::new(toggle_id, enabled).on_toggle(cx.listener(
                            move |this, _e, _w, cx| {
                                this.ext.toggle(idx);
                                cx.notify();
                            },
                        ))),
                );

            let card_el = card(c, t)
                .child(head)
                .child(
                    div()
                        .text_size(t.font_size.sm)
                        .text_color(c.text_muted)
                        .child(r.description.clone()),
                )
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .gap(t.space.sm)
                        .children(chips),
                );
            ext_cards.push(card_el);
        }

        // 近期活动 / findings。
        let events = self.ext.recent_events(60);
        let mut events_card = card(c, t).child(section_label("近期活动 / 发现", c, t));
        if events.is_empty() {
            events_card = events_card.child(
                div()
                    .text_size(t.font_size.sm)
                    .text_color(c.text_subtle)
                    .child("启用扩展并开始抓包后,扩展产生的发现 / 日志会出现在这里。"),
            );
        } else {
            let mut lines: Vec<Div> = Vec::new();
            for ev in &events {
                let col = level_color(ev.level, c);
                lines.push(
                    div()
                        .flex()
                        .items_baseline()
                        .gap(t.space.sm)
                        .child(StatusDot::new(col).size(px(7.0)))
                        .child(
                            div()
                                .flex_shrink_0()
                                .text_size(t.font_size.xs)
                                .text_color(c.text_subtle)
                                .child(ev.ext_name.clone()),
                        )
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(0.0))
                                .text_size(t.font_size.xs)
                                .text_color(if ev.finding { col } else { c.text_muted })
                                .child(ev.text.clone()),
                        ),
                );
            }
            events_card = events_card.child(div().flex().flex_col().gap(px(4.0)).children(lines));
        }

        // 运行时路线图。
        let roadmap = card(c, t)
            .child(section_label("运行时路线图", c, t))
            .child(roadmap_line("内置(Builtin)", "已支持 · 第一方,随包", c.success, t))
            .child(roadmap_line(
                "外部进程(Python 等)",
                "已支持 · stdio JSON-RPC,崩溃隔离",
                c.success,
                t,
            ))
            .child(roadmap_line(
                "WASM 沙箱",
                "已支持 · wasmtime,fuel/内存上限·强隔离",
                c.success,
                t,
            ))
            .child(roadmap_line(
                "Native dylib",
                "P3 · libloading,最快·仅可信",
                c.text_subtle,
                t,
            ));

        div()
            .id("extender-scroll")
            .flex_1()
            .min_h(px(0.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .items_center()
            .p(t.space.xl)
            .child(
                div()
                    .w(px(760.0))
                    .max_w(px(760.0))
                    .flex()
                    .flex_col()
                    .gap(t.space.lg)
                    .child(header)
                    .children(ext_cards)
                    .child(events_card)
                    .child(roadmap),
            )
    }
}

/// 路线图一行:阶段名 + 状态 + 状态点。
fn roadmap_line(
    name: impl Into<SharedString>,
    status: impl Into<SharedString>,
    color: Hsla,
    t: Tokens,
) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .gap(t.space.sm)
        .child(StatusDot::new(color).size(px(7.0)))
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .text_size(t.font_size.sm)
                .text_color(color)
                .child(name.into()),
        )
        .child(
            div()
                .text_size(t.font_size.xs)
                .text_color(color)
                .child(status.into()),
        )
}
