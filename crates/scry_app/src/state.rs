//! 应用状态与导航枚举。UI 各面板(无状态)从这里读状态、通过 `cx.listener` 回写。

use std::time::{Duration, Instant};

use mage_ui::gpui::ClipboardItem;
use mage_ui::prelude::*;
use scry_core::{HttpFlow, WsMessage};
use scry_proxy::SharedStore;
use tokio::sync::oneshot;

use crate::i18n::Lang;
use crate::logger::{initial_logs, LogEntry, LogLevel};
use crate::model::{self, Session};

/// 根证书的系统信任状态。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    Unknown,
    Checking,
    Trusted,
    Untrusted,
}

/// 抓包方式。
///
/// 架构定论:**[`Proxy`](CaptureMode::Proxy) 是唯一抓包内核**(TLS 终止式 MITM,能解密 + 改包,
/// 对标 Burp/mitmproxy);[`Kernel`](CaptureMode::Kernel) 被动嗅探仅作**辅助降级**(看不到明文、
/// 只有元数据 + SNI,对应仪表盘「抓整机」卡)。T1 内置浏览器 / T2 托管启动都汇聚到 `Proxy` 内核。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    /// 内核被动嗅探(libpcap/BPF,类 Wireshark)——**辅助**:抓任意软件但 HTTPS 仅记 SNI(被动不解密),
    /// 可另存 pcapng。用于「解不开 / 不愿引流」的兜底观测。
    Kernel,
    /// **MITM 代理内核**(127.0.0.1:8888)——抓包核心,**解密 HTTPS + 改包**;
    /// 流量来自 scry 自启的内置浏览器 / 托管程序、手动设代理的客户端,或 sing-box/QX 上游链式。
    Proxy,
}

impl CaptureMode {
    pub const ALL: [CaptureMode; 2] = [CaptureMode::Kernel, CaptureMode::Proxy];
    pub fn label(self) -> &'static str {
        match self {
            CaptureMode::Kernel => "Kernel sniff",
            CaptureMode::Proxy => "MITM proxy",
        }
    }
}

/// 顶部工具页签(对标 Burp 顶栏)。全部页签均已落地实现。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Proxy,
    Scanner,
    Sqli,
    Xss,
    Authz,
    Spider,
    Repeater,
    Intruder,
    Sequencer,
    Decoder,
    Comparer,
    Logger,
    Extender,
    Settings,
}

impl Tab {
    pub const ALL: [Tab; 15] = [
        Tab::Dashboard,
        Tab::Proxy,
        Tab::Scanner,
        Tab::Sqli,
        Tab::Xss,
        Tab::Authz,
        Tab::Spider,
        Tab::Repeater,
        Tab::Intruder,
        Tab::Sequencer,
        Tab::Decoder,
        Tab::Comparer,
        Tab::Logger,
        Tab::Extender,
        Tab::Settings,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Proxy => "Proxy",
            Tab::Scanner => "Scanner",
            Tab::Sqli => "SQLi",
            Tab::Xss => "XSS",
            Tab::Authz => "Authz",
            Tab::Spider => "Spider",
            Tab::Repeater => "Repeater",
            Tab::Intruder => "Intruder",
            Tab::Sequencer => "Sequencer",
            Tab::Decoder => "Decoder",
            Tab::Comparer => "Comparer",
            Tab::Logger => "Logger",
            Tab::Extender => "Extender",
            Tab::Settings => "Settings",
        }
    }

    pub fn icon(self) -> IconName {
        match self {
            Tab::Dashboard => IconName::Box,
            Tab::Proxy => IconName::Globe,
            Tab::Scanner => IconName::Search,
            Tab::Sqli => IconName::Layers,
            Tab::Xss => IconName::Tag,
            Tab::Authz => IconName::Shield,
            Tab::Spider => IconName::GitBranch,
            Tab::Repeater => IconName::Refresh,
            Tab::Intruder => IconName::Zap,
            Tab::Sequencer => IconName::Sort,
            Tab::Decoder => IconName::Hash,
            Tab::Comparer => IconName::Copy,
            Tab::Logger => IconName::Clock,
            Tab::Extender => IconName::Package,
            Tab::Settings => IconName::Settings,
        }
    }

    /// 该页是否独占中栏宽度(不显示右侧 Inspector / 图标栏)。
    pub fn is_wide(self) -> bool {
        !matches!(self, Tab::Proxy)
    }
}

/// 历史列表协议过滤(工具栏右侧的 chip)。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    All,
    Http,
    Https,
    Ws,
}

impl Proto {
    pub const ALL: [Proto; 4] = [Proto::All, Proto::Http, Proto::Https, Proto::Ws];
    pub fn label(self) -> &'static str {
        match self {
            Proto::All => "All",
            Proto::Http => "HTTP",
            Proto::Https => "HTTPS",
            Proto::Ws => "WebSocket",
        }
    }
    /// 是否放行该流。
    pub fn matches(self, f: &HttpFlow) -> bool {
        match self {
            Proto::All => true,
            Proto::Http => f.scheme == "http",
            Proto::Https => f.scheme == "https",
            Proto::Ws => f.scheme == "ws" || f.scheme == "wss",
        }
    }
}

/// 报文视图模式(请求 / 响应面板各自一个)。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MsgView {
    Pretty,
    Raw,
    Hex,
    Render,
}

impl MsgView {
    /// 全部视图(响应面板用)。
    pub const ALL: [MsgView; 4] = [MsgView::Pretty, MsgView::Raw, MsgView::Hex, MsgView::Render];
    /// 请求面板可用视图:只「美化 / 原始」(十六进制 / 渲染对请求无意义)。
    pub const REQUEST: [MsgView; 2] = [MsgView::Pretty, MsgView::Raw];

    /// 某面板(请求 / 响应)可用的视图列表:请求只 美化/原始,响应全部四个。
    pub fn for_panel(is_req: bool) -> &'static [MsgView] {
        if is_req {
            &Self::REQUEST
        } else {
            &Self::ALL
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            MsgView::Pretty => "Pretty",
            MsgView::Raw => "Raw",
            MsgView::Hex => "Hex",
            MsgView::Render => "Render",
        }
    }
}

/// 中栏工具条页签(History / WebSocket / Intercept / Options)。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HistTab {
    History,
    WebSocket,
    Intercept,
    Options,
}

impl HistTab {
    pub const ALL: [HistTab; 4] =
        [HistTab::History, HistTab::WebSocket, HistTab::Intercept, HistTab::Options];
    pub fn label(self) -> &'static str {
        match self {
            HistTab::History => "HTTP History",
            HistTab::WebSocket => "WebSocket",
            HistTab::Intercept => "Intercept",
            HistTab::Options => "Options",
        }
    }
}

/// 右侧 Inspector 顶部页签。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InspTab {
    Inspector,
    Notes,
}

impl InspTab {
    pub const ALL: [InspTab; 2] = [InspTab::Inspector, InspTab::Notes];
    pub fn label(self) -> &'static str {
        match self {
            InspTab::Inspector => "Inspector",
            InspTab::Notes => "Notes",
        }
    }
}

/// 代理 history 行**右键上下文菜单**的状态:目标流下标 + 弹出位置(窗口坐标)+ 级联子菜单展开态。
pub struct CtxMenu {
    pub flow: usize,
    pub x: Pixels,
    pub y: Pixels,
    /// 当前展开的二级子菜单(`None`=未展开;0=发送到 / 1=复制为 / 2=标记 / 3=范围)。
    pub sub: Option<u8>,
    /// 当前展开的三级子菜单(目前仅「发送到 → 比较器」用,值 0)。
    pub subsub: Option<u8>,
}

/// 爆破攻击模式(对标 Burp Intruder)。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AttackMode {
    /// 狙击手:逐个注入点轮流注入,其余位保持原值。
    Sniper,
    /// 攻城锤:同一载荷灌进所有注入点。
    BatteringRam,
    /// 集束炸弹:各注入点载荷的笛卡尔积。
    ClusterBomb,
}

impl AttackMode {
    pub const ALL: [AttackMode; 3] = [
        AttackMode::Sniper,
        AttackMode::BatteringRam,
        AttackMode::ClusterBomb,
    ];
    pub fn label(self) -> &'static str {
        match self {
            AttackMode::Sniper => "Sniper",
            AttackMode::BatteringRam => "Battering ram",
            AttackMode::ClusterBomb => "Cluster bomb",
        }
    }
}

/// 载荷来源(对标 Burp 的 payload type)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    /// 简单列表:每行一个载荷。
    List,
    /// 数字区间:`from-to[:step]`(如 `1-9999`、`0-100:5`)。
    Numbers,
    /// 字符集暴破:给定字符集与长度区间,枚举全部组合(`a-z`、`0-9` 试密码 / PIN)。
    Brute,
}

impl PayloadKind {
    pub const ALL: [PayloadKind; 3] = [PayloadKind::List, PayloadKind::Numbers, PayloadKind::Brute];
    pub fn label(self) -> &'static str {
        match self {
            PayloadKind::List => "List",
            PayloadKind::Numbers => "Numbers",
            PayloadKind::Brute => "Brute force",
        }
    }
}

/// 载荷处理器(逐条载荷按固定顺序施加:大小写 → 哈希 → Base64 → URL 编码;对标 Burp payload processing)。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProcOp {
    Upper,
    Lower,
    UrlEncode,
    Base64,
    Md5,
    Sha1,
}

impl ProcOp {
    pub const ALL: [ProcOp; 6] = [
        ProcOp::Upper,
        ProcOp::Lower,
        ProcOp::UrlEncode,
        ProcOp::Base64,
        ProcOp::Md5,
        ProcOp::Sha1,
    ];
    pub fn label(self) -> &'static str {
        match self {
            ProcOp::Upper => "UPPER",
            ProcOp::Lower => "lower",
            ProcOp::UrlEncode => "URL",
            ProcOp::Base64 => "Base64",
            ProcOp::Md5 => "MD5",
            ProcOp::Sha1 => "SHA-1",
        }
    }
    /// 在处理器位掩码中的比特位。
    pub fn bit(self) -> u16 {
        match self {
            ProcOp::Upper => 1 << 0,
            ProcOp::Lower => 1 << 1,
            ProcOp::UrlEncode => 1 << 2,
            ProcOp::Base64 => 1 << 3,
            ProcOp::Md5 => 1 << 4,
            ProcOp::Sha1 => 1 << 5,
        }
    }
}

/// 爆破结果表排序键。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    /// 发出顺序(默认)。
    Order,
    Status,
    Length,
    Time,
}

impl SortBy {
    pub const ALL: [SortBy; 4] = [SortBy::Order, SortBy::Status, SortBy::Length, SortBy::Time];
    pub fn label(self) -> &'static str {
        match self {
            SortBy::Order => "#",
            SortBy::Status => "Status",
            SortBy::Length => "Length",
            SortBy::Time => "Time(ms)",
        }
    }
}

/// 一条爆破请求的结果行(发出顺序 `idx`、展示用载荷、命中位置、响应或错误)。
pub struct AttackResult {
    /// 在本轮作业中的发出序号(0 基)。
    pub idx: usize,
    /// 展示用载荷标签(集束炸弹为各位置值逗号拼接)。
    pub payload: String,
    /// 狙击手模式下命中的注入点下标(其余模式为 `None`)。
    pub position: Option<usize>,
    /// 成功时的响应流;失败为 `None`。
    pub flow: Option<HttpFlow>,
    /// 发包出错信息(成功为 `None`)。
    pub error: Option<String>,
}

impl AttackResult {
    /// 响应状态码(无响应 = 0)。
    pub fn status(&self) -> u16 {
        self.flow.as_ref().map(|f| f.status).unwrap_or(0)
    }
    /// 响应体长度(无响应 = 0)。
    pub fn resp_len(&self) -> usize {
        self.flow.as_ref().map(|f| f.resp_len()).unwrap_or(0)
    }
    /// 往返耗时毫秒(无响应 = 0)。
    pub fn ms(&self) -> u64 {
        self.flow.as_ref().map(|f| f.duration_ms).unwrap_or(0)
    }
}

/// 代理详情文本框(所有视图)的同步签名:`(选中行, 视图, body 长度, 状态码)`。
/// 任一变化即重灌「文本 + 高亮区间」;无选中流时签名记为 `None`。
pub type MsgSig = Option<(usize, MsgView, usize, u16)>;

/// 主动扫描后台 → 前台的流式消息(每完成一个探测发一条:累计完成数 + 可选发现)。
pub struct ScanMsg {
    /// 已完成的探测序号(1 基,= 进度分子)。
    pub done: usize,
    /// 该探测命中的发现(无命中为 `None`)。
    pub finding: Option<scry_scan::Finding>,
}

/// SQLi 测试日志行级别(决定颜色:命中绿 / 信息默认 / 提醒黄 / 失败红)。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SqliLevel {
    Info,
    Good,
    Warn,
    Bad,
}

/// 一条 SQLi 测试日志(级别 + 文本)。
#[derive(Clone)]
pub struct SqliLine {
    pub level: SqliLevel,
    pub text: String,
}

/// SQLi 测试结论(随测试推进逐步填充)。
#[derive(Clone, Default)]
pub struct SqliReport {
    /// 命中的注入点(None = 未发现)。
    pub point: Option<scry_sqli::InjectionPoint>,
    /// 是否确认可注入。
    pub injectable: bool,
    /// 成立的注入技术(去重)。
    pub techniques: Vec<scry_sqli::Technique>,
    /// 指纹出的数据库类型(盲注无回显时可能为 None)。
    pub dbms: Option<scry_sqli::Dbms>,
    /// 成立的闭合边界。
    pub boundary: Option<scry_sqli::Boundary>,
    /// 取到的数据库版本 / 当前用户 / 当前库。
    pub version: Option<String>,
    pub user: Option<String>,
    pub database: Option<String>,
}

/// SQLi 后台 runner → 前台的流式消息。
pub struct SqliMsg {
    /// 追加的日志行(无则 `None`)。
    pub line: Option<SqliLine>,
    /// 报告快照(有变化时整体替换;无则 `None`)。
    pub report: Option<SqliReport>,
    /// 进度文案(无则 `None`)。
    pub progress: Option<String>,
    /// 是否结束(收尾)。
    pub done: bool,
}

/// 一条 XSS 发现(某注入点的检测结论)。
#[derive(Clone)]
pub struct XssFinding {
    /// 注入点标签(如 `query: q`)。
    pub point: String,
    /// 是否**确认可利用**(合成载荷的执行片段未被编码地回显)。
    pub confirmed: bool,
    /// 反射所处的 HTML 上下文(英文 key,界面翻译)。
    pub context: &'static str,
    /// 可利用时合成的载荷(注入值);否则 `None`。
    pub payload: Option<String>,
    /// 载荷类型(html-tag / attr-event / js-string-breakout …)。
    pub kind: Option<&'static str>,
}

/// XSS 后台 runner → 前台的流式消息。
pub struct XssMsg {
    /// 追加日志行(复用 [`SqliLine`])。
    pub line: Option<SqliLine>,
    /// 追加一条发现。
    pub finding: Option<XssFinding>,
    /// DOM sink 提示(整体替换一次)。
    pub sinks: Option<Vec<String>>,
    /// 进度文案。
    pub progress: Option<String>,
    /// 是否结束。
    pub done: bool,
}

/// 越权测试里一条「身份重放结果」(用于结论卡逐行展示)。
#[derive(Clone)]
pub struct AuthzRow {
    /// 身份名(`high` / `low` / `anonymous`;界面按它翻译)。
    pub identity: String,
    /// 判定:0=拦截到位(Enforced)· 1=疑似越权(Bypass)· 2=无法判定(Inconclusive)· 3=高权限基准。
    pub verdict: u8,
    /// 该身份重放的响应状态码。
    pub status: u16,
    /// 响应体字节数。
    pub len: usize,
}

/// 越权(Authz)后台 runner → 前台的流式消息。
pub struct AuthzMsg {
    /// 追加日志行(复用 [`SqliLine`])。
    pub line: Option<SqliLine>,
    /// 追加一条身份重放结果(进结论卡)。
    pub row: Option<AuthzRow>,
    /// 追加一条发现(越权 / 未授权访问)。
    pub finding: Option<scry_scan::Finding>,
    /// 进度文案。
    pub progress: Option<String>,
    /// 是否结束。
    pub done: bool,
}

/// 「本次发现列表」一行:爬虫访问过的页 URL + 是否成功(浏览器导航 + 拿到 HTML)。
#[derive(Clone)]
pub struct CrawlVisited {
    pub url: String,
    pub ok: bool,
}

/// 站点爬虫(Spider)后台 → 前台的流式消息(每抓完一页发一条)。
///
/// **浏览器驱动模式**:页面由 drission(CDP)真实 Chrome 访问,流量经 scry MITM(8888)
/// 自动解密落历史,故这里**不回传 flow**;只回传进度 + 本次访问的 URL(填「本次发现列表」)+ 提示。
pub struct CrawlMsg {
    /// 已抓取的页数(进度分子)。
    pub fetched: usize,
    /// 累计发现并接纳的 URL 数(队列 + 已抓;进度规模)。
    pub discovered: usize,
    /// 本次访问的页 URL(填「本次发现列表」;纯进度 / 结束帧为 `None`)。
    pub url: Option<String>,
    /// 该页是否抓取成功(导航成功且拿到 HTML)。
    pub ok: bool,
    /// 出错 / 提示信息(写进事件日志;无则 `None`)。
    pub note: Option<String>,
    /// 是否已结束(队列抽干 或 达页数上限 或 被停止 或 启动失败)。
    pub done: bool,
}

/// 整个应用的状态。
pub struct ScryApp {
    // 导航
    pub tab: Tab,
    // 左栏
    pub sessions: Vec<Session>,
    pub active_session: usize,
    /// 正在重命名的会话下标(None = 无);非 None 时该会话行渲染输入框。
    pub rename_idx: Option<usize>,
    /// 会话重命名输入框。
    pub rename_input: Entity<InputState>,
    // Proxy / history
    pub flows: Vec<HttpFlow>,
    pub selected: Option<usize>,
    /// 抓包列表排序:`true` = 最新在前(默认),`false` = 最早在前。
    pub sort_newest: bool,
    /// 行标记着色:flow 指纹 → 颜色序号(1..=5),分析时给行加自定义底色。
    pub marks: std::collections::HashMap<String, usize>,
    pub search: Entity<InputState>,
    pub proto: Proto,
    pub hist_tab: HistTab,
    /// WebSocket 消息(升级连接的双向帧;与 `flows` 分开存,不去重)。
    pub ws_msgs: Vec<WsMessage>,
    /// WebSocket 列表选中下标(看完整 payload)。
    pub ws_selected: Option<usize>,
    /// WebSocket 消息实时推流通道(抓包时 Store 推,UI `drain_new_flows` 取)。
    pub ws_rx: Option<std::sync::mpsc::Receiver<WsMessage>>,
    /// WebSocket 列表虚拟滚动句柄(跨帧保持滚动位置)。
    pub ws_scroll: UniformListScrollHandle,
    pub req_view: MsgView,
    pub resp_view: MsgView,
    /// 代理页请求 / 响应详情的**只读可选中**文本框(所有视图统一承载:美化带语法高亮,亦含原始 / 十六进制 / 渲染)。
    /// 文本按当前选中流 + 视图同步;`*_sig` 记录上次同步签名以避免每帧重置选区。
    pub msg_req: Entity<InputState>,
    pub msg_resp: Entity<InputState>,
    pub msg_req_sig: MsgSig,
    pub msg_resp_sig: MsgSig,
    // 交互式拦截(Intercept 断点队列)
    /// 被拦报文的回传通道(抓包启动时与 `ext` 配对;UI 每拍排空)。
    pub intercept_rx: Option<std::sync::mpsc::Receiver<crate::ext::InterceptItem>>,
    /// 待处理拦截队列(队首 = 当前展示 / 编辑对象)。
    pub intercept_queue: std::collections::VecDeque<crate::ext::InterceptItem>,
    /// 拦截编辑器:队首报文的**可编辑**原文;放行时按它重建 flow。
    pub intercept_edit: Entity<InputState>,
    /// 已灌进编辑器的队首 id(变化才重灌,避免每拍清掉用户编辑)。
    pub intercept_edit_id: Option<u64>,
    // 拦截规则(Proxy → Options,对标 Burp):自定义拦截范围 + Match & Replace 自动改包。
    /// 自定义拦截范围规则(UI 可编辑;每次变化即编译推给引擎 `ext`)。
    pub scope_rules: Vec<crate::rules::ScopeRule>,
    /// Match & Replace 自动改包规则。
    pub replace_rules: Vec<crate::rules::ReplaceRule>,
    /// 新增范围规则的表单:方向 / 字段 / 算子 / 值 / 取反 / 拦截或排除。
    pub sr_dir: crate::ext::InterceptDir,
    pub sr_field: crate::rules::Field,
    pub sr_op: crate::rules::Op,
    pub sr_field_open: bool,
    pub sr_op_open: bool,
    pub sr_value: Entity<InputState>,
    pub sr_negate: bool,
    pub sr_intercept: bool,
    /// 新增 Match & Replace 规则的表单:目标 / 查找 / 替换 / 是否正则。
    pub mr_target: crate::rules::Target,
    pub mr_target_open: bool,
    pub mr_find: Entity<InputState>,
    pub mr_replace: Entity<InputState>,
    pub mr_regex: bool,
    // Inspector
    pub insp_tab: InspTab,
    /// 4 个折叠分组的展开态:Req Headers / Req Cookies / Resp Headers / Resp Cookies。
    pub insp_open: [bool; 4],
    /// 右侧图标栏当前项(Inspector / Breakpoints / Payloads / SSL Info)。
    pub rail: usize,
    // Repeater
    pub rp_target: Entity<InputState>,
    pub rp_req: Entity<InputState>,
    pub rp_resp: Option<HttpFlow>,
    pub rp_err: Option<String>,
    pub rp_sending: bool,
    /// Repeater 响应区视图模式(Pretty 高亮 / Raw / Hex)。
    pub rp_resp_view: MsgView,
    /// Repeater 请求区视图:Pretty(只读语法高亮)/ Raw(可编辑输入框)。
    pub rp_req_view: MsgView,
    /// Repeater 响应的**只读可选中高亮**查看器(选中 + Cmd/Ctrl+C + 右键复制);文本/高亮由 `sync_repeater_views` 灌入。
    pub rp_resp_input: Entity<InputState>,
    /// 上次同步 `rp_resp_input` 的签名(状态/长度/视图/主题变化才重灌,免每帧重置选区)。
    pub rp_resp_sig: u64,
    // 扫描器
    /// 最近一次扫描的发现(被动 + 主动汇总,严重度降序)。
    pub scan_findings: Vec<scry_scan::Finding>,
    /// 是否已运行过扫描(区分「未扫描」与「扫描后无发现」)。
    pub scan_ran: bool,
    /// 主动扫描进行中(后台 replay 发包时禁用按钮)。
    pub scan_busy: bool,
    /// 主动扫描进度文案(如 `12 / 30`)。
    pub scan_progress: Option<String>,
    /// 严重度过滤(None = 全部)。
    pub scan_filter: Option<scry_scan::Severity>,
    /// 扫描目标:限定到某个 host(None = 全部抓到的流量)。被动 / 主动扫描都按它过滤。
    pub scan_target: Option<String>,
    /// 目标 host 下拉是否展开。
    pub scan_target_open: bool,
    /// 本轮主动扫描的探测总数(进度分母)。
    pub scan_total: usize,
    /// 已完成的探测数(进度分子)。
    pub scan_done: usize,
    /// 主动扫描是否已暂停(暂停时后台线程挂起、不再发包)。
    pub scan_paused: bool,
    /// 主动扫描结果流式回传通道(后台 → 前台);停止即丢弃。
    pub scan_rx: Option<std::sync::mpsc::Receiver<ScanMsg>>,
    /// 主动扫描控制位(Running / Paused / Stopped;见 scanner.rs 常量),后台逐探测查询。
    pub scan_ctrl: Option<std::sync::Arc<std::sync::atomic::AtomicU8>>,
    // SQLi 注入测试(sqlmap 式:选请求 + 注入点 → 报错 / 布尔 / 时间 / 联合 探测 + 取数)
    /// 目标 `scheme://host[:port]`。
    pub sqli_target: Entity<InputState>,
    /// 可编辑的原始请求(注入点从它解析)。
    pub sqli_req: Entity<InputState>,
    /// 注入点选择:0 = 全部参数(自动逐个试),其余对应当前解析出的注入点。
    pub sqli_point_sel: usize,
    /// 注入点下拉是否展开。
    pub sqli_point_open: bool,
    /// 时间盲注睡眠秒数。
    pub sqli_secs: u32,
    /// 睡眠秒数下拉是否展开。
    pub sqli_secs_open: bool,
    /// 测试进行中(后台 replay 发包时显示「停止」)。
    pub sqli_busy: bool,
    /// 进度文案。
    pub sqli_progress: Option<String>,
    /// 测试日志(带颜色;最新在末尾)。
    pub sqli_log: Vec<SqliLine>,
    /// 当前结论(逐步填充)。
    pub sqli_report: SqliReport,
    /// 结果流式回传通道(后台 → 前台);停止即丢弃。
    pub sqli_rx: Option<std::sync::mpsc::Receiver<SqliMsg>>,
    /// 停止标志(置位即让后台 runner 收尾退出)。
    pub sqli_ctrl: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    // XSS 注入测试(dalfox 式:反射定位 + 上下文识别 + 可用字符探测 + 载荷合成 + 反射验证)
    /// 目标 `scheme://host[:port]`。
    pub xss_target: Entity<InputState>,
    /// 可编辑的原始请求(注入点从它解析)。
    pub xss_req: Entity<InputState>,
    /// 注入点选择:0 = 全部参数(自动),其余对应解析出的注入点。
    pub xss_point_sel: usize,
    /// 注入点下拉是否展开。
    pub xss_point_open: bool,
    /// 测试进行中。
    pub xss_busy: bool,
    /// 进度文案。
    pub xss_progress: Option<String>,
    /// 测试日志(复用 SqliLine;最新在末尾)。
    pub xss_log: Vec<SqliLine>,
    /// 各注入点的发现。
    pub xss_findings: Vec<XssFinding>,
    /// DOM sink 提示(从响应静态扫出)。
    pub xss_sinks: Vec<String>,
    /// 结果流式回传通道(后台 → 前台);停止即丢弃。
    pub xss_rx: Option<std::sync::mpsc::Receiver<XssMsg>>,
    /// 停止标志。
    pub xss_ctrl: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// 验证模式:`false` = 静态反射检测(replay);`true` = 浏览器真执行确认(drission 无头 Chrome 弹 alert)。
    pub xss_dom: bool,
    /// 浏览器验证用的无头 Chrome 子进程(scry 自启,停止 / 完成 / 关软件时 kill)。
    pub xss_child: Option<std::process::Child>,
    // 越权 / 访问控制测试(Authz,Autorize 式:同一请求用 高权限 / 低权限 / 匿名 多身份重放比对)
    /// 目标 `scheme://host[:port]`。
    pub authz_target: Entity<InputState>,
    /// 可编辑的原始请求(高权限基准 = 它本身或套用下面的高权限身份)。
    pub authz_req: Entity<InputState>,
    /// 高权限身份头(`Header: value` 每行一条;留空 = 直接用上面的请求当基准)。
    pub authz_high: Entity<InputState>,
    /// 低权限身份头(可选;留空则只测匿名)。
    pub authz_low: Entity<InputState>,
    /// 测试进行中。
    pub authz_busy: bool,
    /// 进度文案。
    pub authz_progress: Option<String>,
    /// 测试日志(复用 [`SqliLine`];最新在末尾)。
    pub authz_log: Vec<SqliLine>,
    /// 各身份重放结果(结论卡逐行展示;第一行通常是高权限基准)。
    pub authz_rows: Vec<AuthzRow>,
    /// 命中的越权 / 未授权访问发现。
    pub authz_findings: Vec<scry_scan::Finding>,
    /// 是否已运行过测试(区分「未测试」与「测试后无发现」)。
    pub authz_ran: bool,
    /// 结果流式回传通道(后台 → 前台);停止即丢弃。
    pub authz_rx: Option<std::sync::mpsc::Receiver<AuthzMsg>>,
    /// 停止标志(置位即让后台 runner 收尾退出)。
    pub authz_ctrl: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    // 站点爬虫(Spider)—— 独立「爬虫」页发起:drission(CDP)真实浏览器从种子 BFS 抓站,
    // 流量经 MITM 自动落历史(代理页可见)、可被扫描。
    /// 种子 URL 输入(空白 / 换行分隔多个;省略 scheme 默认补 https)。
    pub crawl_seed: Entity<InputState>,
    /// BFS 最大深度。
    pub crawl_depth: usize,
    /// 最多抓取的页数。
    pub crawl_pages: usize,
    /// 深度下拉是否展开。
    pub crawl_depth_open: bool,
    /// 页数下拉是否展开。
    pub crawl_pages_open: bool,
    /// 爬虫进行中(后台 BFS 抓取时显示「停止」)。
    pub crawl_busy: bool,
    /// 进度文案(如 `抓取 12 · 发现 30`)。
    pub crawl_progress: Option<String>,
    /// 爬虫结果流式回传通道(后台 → 前台);停止即丢弃。
    pub crawl_rx: Option<std::sync::mpsc::Receiver<CrawlMsg>>,
    /// 爬虫控制位(Running / Stopped;见 crawler.rs 常量),后台逐页查询。
    pub crawl_ctrl: Option<std::sync::Arc<std::sync::atomic::AtomicU8>>,
    /// 「本次发现列表」:本轮爬虫访问过的页(最新在前),独立于代理历史。
    pub crawl_visited: Vec<CrawlVisited>,
    /// 爬虫专用的无头 Chrome 子进程(scry 自启 + drission connect 接管):进程归 scry 管,
    /// 停止 / 爬完 / 关软件时统一 kill,杜绝孤儿浏览器。
    pub crawl_child: Option<std::process::Child>,
    // 爆破(Intruder)
    /// 目标 `scheme://host[:port]`。
    pub it_target: Entity<InputState>,
    /// 带 `§…§` 注入点标记的请求模板(可编辑)。
    pub it_req: Entity<InputState>,
    /// 载荷表(每行一个,可编辑)。
    pub it_payloads: Entity<InputState>,
    /// grep 关键字(命中的结果行高亮;空 = 不过滤)。
    pub it_match: Entity<InputState>,
    /// 攻击模式。
    pub it_mode: AttackMode,
    /// 结果行(按发出顺序流式追加)。
    pub it_results: Vec<AttackResult>,
    /// 当前选中的结果行下标。
    pub it_selected: Option<usize>,
    /// 爆破进行中(发包时禁用「开始」、显示「停止」)。
    pub it_busy: bool,
    /// 进度 / 提示文案(如 `12 / 100`)。
    pub it_progress: Option<String>,
    /// 本轮预定发出的请求总数(进度分母)。
    pub it_total: usize,
    /// 结果流式回传通道接收端(后台发包线程 → 主线程);停止即丢弃。
    pub it_rx: Option<std::sync::mpsc::Receiver<AttackResult>>,
    /// 选中结果响应区视图(Pretty / Raw / Hex)。
    pub it_resp_view: MsgView,
    /// 请求模板视图:Pretty(只读语法高亮)/ Raw(可编辑,放注入点)。
    pub it_req_view: MsgView,
    /// Intruder 选中结果响应的**只读可选中高亮**查看器(选中 + 复制);由 `sync_intruder_views` 灌入。
    pub it_resp_input: Entity<InputState>,
    /// 上次同步 `it_resp_input` 的签名。
    pub it_resp_sig: u64,
    /// 载荷来源(列表 / 数字区间 / 字符集暴破)。
    pub it_src: PayloadKind,
    /// 数字区间载荷的配置串(`from-to[:step]`)。
    pub it_num: Entity<InputState>,
    /// 字符集暴破的字符集。
    pub it_charset: Entity<InputState>,
    /// 字符集暴破的长度区间(`min-max`)。
    pub it_len: Entity<InputState>,
    /// 载荷处理器:前缀(施加在处理后载荷之前)。
    pub it_prefix: Entity<InputState>,
    /// 载荷处理器:后缀。
    pub it_suffix: Entity<InputState>,
    /// 已启用的载荷处理器位掩码(见 [`ProcOp::bit`])。
    pub it_proc_mask: u16,
    /// Grep-Extract:正则(首个捕获组,无组则整体匹配),从响应抽值成「提取」列。
    pub it_extract: Entity<InputState>,
    /// 结果排序键。
    pub it_sort: SortBy,
    /// 结果排序是否降序。
    pub it_sort_desc: bool,
    /// 并发发包数(1 = 串行)。
    pub it_concurrency: usize,
    /// 每请求前的限速延迟(毫秒;0 = 不限速)。
    pub it_throttle: Entity<InputState>,
    // 序列器(Sequencer)
    /// 令牌样本输入(每行一个;粘贴 / 加载演示)。
    pub seq_input: Entity<InputState>,
    /// 最近一次随机性分析报告(None = 未分析)。
    pub seq_report: Option<scry_seq::SequencerReport>,
    // 解码器(Decoder)
    /// 待变换的源文本。
    pub dec_input: Entity<InputState>,
    /// 变换结果(可继续「转输入」链式;纯数据容器,展示走 `dec_view`)。
    pub dec_output: Entity<InputState>,
    /// 解码输出的**只读可选中高亮**查看器(JSON 美化 + 多色 + 选中复制);由 `sync_decoder_view` 灌入。
    pub dec_view: Entity<InputState>,
    /// 上次同步 `dec_view` 的签名。
    pub dec_view_sig: u64,
    /// 对称加解密密钥(XOR / RC4 / AES / HMAC;按 UTF-8 字节解释)。
    pub dec_key: Entity<InputState>,
    /// 对称加解密 IV(仅 AES-CBC;16 字节)。
    pub dec_iv: Entity<InputState>,
    /// 上次变换的状态提示(变换名 / 错误原因);None = 未操作。
    pub dec_note: Option<String>,
    /// 上次变换是否失败(提示着色)。
    pub dec_err: bool,
    // 比较器(Comparer)
    /// 待比较的两段文本。
    pub cmp_a: Entity<InputState>,
    pub cmp_b: Entity<InputState>,
    /// 比较粒度(行 / 词 / 字符)。
    pub cmp_gran: scry_diff::Granularity,
    /// 最近一次 diff 结果(None = 未比较)。
    pub cmp_report: Option<scry_diff::DiffReport>,
    // 上游代理(链式出网):抓包 / 重放解密后经它出网(sing-box / QX);未启用 = 直连。
    pub upstream_input: Entity<InputState>,
    pub upstream_enabled: bool,
    // 抓包
    pub capture_mode: CaptureMode,
    pub capturing: bool,
    /// 抓包时与代理 / 嗅探线程共享的存储句柄。
    pub store: Option<SharedStore>,
    /// 代理模式停止信号:发送即让代理线程的 tokio select 结束、释放端口。
    pub capture_stop: Option<oneshot::Sender<()>>,
    /// 内核抓包停止标志:置位即让嗅探循环退出。
    pub sniff_stop: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// 实时推流接收端:抓包时 `Store` 每条新流量 clone 推来,UI `try_recv` 增量追加(替代全量轮询)。
    pub flow_rx: Option<std::sync::mpsc::Receiver<HttpFlow>>,
    /// T2 托管启动:要拉起的程序 / 命令(如 `curl https://example.com`)。
    pub prog_input: Entity<InputState>,
    /// 被 scry 拉起的子进程(内置浏览器 / 托管程序);停止抓包 / 退出时统一收掉,周期回收退出者。
    pub launched: Vec<crate::launcher::Launched>,
    /// 历史表虚拟列表滚动句柄(跨帧记住滚动位置;虚拟化只渲可见行,大数据不卡)。
    pub hist_scroll: UniformListScrollHandle,
    /// 网站分类过滤:仅显示该「网站」(eTLD+1,见 `model::site_of`)的流量;None = 全部。
    pub host_filter: Option<String>,
    /// 左栏「网站分类」是否展开。
    pub host_cat_open: bool,
    // 网卡(内核抓包):可选列表 + 当前选中 + 下拉展开态。
    pub ifaces: Vec<String>,
    pub iface_sel: usize,
    pub iface_open: bool,
    /// 内核抓包时是否同时把原始帧落 pcapng(Wireshark 可开)。
    pub pcapng_enabled: bool,
    /// TLS 指纹伪装 profile 下标(`scry_proxy::tls_profile::TlsProfile::ALL`)。
    pub tls_profile_sel: usize,
    /// TLS 指纹下拉是否展开。
    pub tls_profile_open: bool,
    /// 当前 history 是否为内置演示数据(界面标注用)。
    pub demo: bool,
    // 证书
    pub cert_status: CertStatus,
    /// 上次证书 / 抓包操作的结果提示。
    pub cert_msg: Option<String>,
    /// 正在执行外部命令(安装 / 检查),按钮禁用。
    pub cert_busy: bool,
    // 事件日志(Logger 页)
    /// 运行时事件流(抓包 / 扫描 / 证书 / 上游 / 流量),最新在表头。
    pub logs: Vec<LogEntry>,
    /// 级别过滤(None = 全部)。
    pub log_filter: Option<LogLevel>,
    /// 日志全文搜索框。
    pub log_search: Entity<InputState>,
    // 交互浮层
    /// 代理 history 行右键菜单(None = 未弹出)。
    pub ctx_menu: Option<CtxMenu>,
    /// 短暂提示(如「已复制为 curl」),自动消失。
    pub toast: Option<String>,
    // 杂项
    pub lang: Lang,
    pub started: Instant,
    /// 扩展注册表(Extender 页展示 + 注入抓包钩子);`Arc` 与 proxy 线程共享。
    pub ext: std::sync::Arc<crate::ext::ExtRegistry>,
}

impl ScryApp {
    /// 构造:建输入框、挂搜索观察、启动每秒计时(状态栏运行时长),装载流量。
    /// 把当前会话的工作集(`self.flows`)存回其存档槽。
    fn stash_active_flows(&mut self) {
        let cur = std::mem::take(&mut self.flows);
        if let Some(s) = self.sessions.get_mut(self.active_session) {
            s.flows = cur;
        }
    }

    /// 切到第 `i` 个会话:存回旧会话工作集,载入目标会话数据(实现会话级数据隔离)。
    pub fn switch_session(&mut self, i: usize, cx: &mut Context<Self>) {
        if i >= self.sessions.len() || i == self.active_session {
            return;
        }
        self.stash_active_flows();
        self.flows = self
            .sessions
            .get_mut(i)
            .map(|s| std::mem::take(&mut s.flows))
            .unwrap_or_default();
        self.active_session = i;
        self.selected = None;
        self.host_filter = None;
        cx.notify();
    }

    /// 新建一个空会话并切过去(新会话不带任何数据)。
    pub fn add_session(&mut self, cx: &mut Context<Self>) {
        self.stash_active_flows();
        let n = self.sessions.len() + 1;
        let tone = self.sessions.len() % 5;
        let name = format!("会话 {n}");
        self.sessions.push(model::new_session(name.clone(), tone));
        self.active_session = self.sessions.len() - 1;
        self.flows = Vec::new();
        self.selected = None;
        self.host_filter = None;
        self.host_cat_open = false;
        self.push_log(LogLevel::Info, "session", format!("新建会话「{name}」"));
        cx.notify();
    }

    /// 删除第 `i` 个会话(至少保留一个)。删当前会话则切到相邻会话。
    pub fn delete_session(&mut self, i: usize, cx: &mut Context<Self>) {
        if self.sessions.len() <= 1 || i >= self.sessions.len() {
            return;
        }
        if self.rename_idx == Some(i) {
            self.rename_idx = None;
        }
        let removed = self.sessions.remove(i);
        match self.active_session.cmp(&i) {
            std::cmp::Ordering::Equal => {
                // 删的是当前会话:其数据在 self.flows(随删丢弃),切到相邻会话并载入它的数据。
                let new_active = i.min(self.sessions.len() - 1);
                self.flows = self
                    .sessions
                    .get_mut(new_active)
                    .map(|s| std::mem::take(&mut s.flows))
                    .unwrap_or_default();
                self.active_session = new_active;
                self.selected = None;
                self.host_filter = None;
            }
            std::cmp::Ordering::Greater => self.active_session -= 1,
            std::cmp::Ordering::Less => {}
        }
        self.push_log(
            LogLevel::Info,
            "session",
            format!("删除会话「{}」", removed.name),
        );
        cx.notify();
    }

    /// 进入重命名:把当前名字灌进输入框。
    pub fn start_rename(&mut self, i: usize, cx: &mut Context<Self>) {
        if let Some(s) = self.sessions.get(i) {
            let name = s.name.to_string();
            self.rename_idx = Some(i);
            self.rename_input
                .update(cx, |inp, cx| inp.set_text(name, cx));
            cx.notify();
        }
    }

    /// 提交重命名(空名忽略)。
    pub fn commit_rename(&mut self, cx: &mut Context<Self>) {
        if let Some(i) = self.rename_idx.take() {
            let name = self.rename_input.read(cx).text().trim().to_string();
            if !name.is_empty() {
                if let Some(s) = self.sessions.get_mut(i) {
                    s.name = name.into();
                }
            }
            cx.notify();
        }
    }

    pub fn new(cx: &mut Context<Self>) -> Self {
        // 默认中文界面。
        let lang = Lang::Zh;
        let search = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder(lang.t("Filter: host / path / header / body…"))
                .clearable(true)
        });
        cx.observe(&search, |_this, _src, cx| cx.notify()).detach();

        let (flows, demo) = model::load_flows();
        let ifaces = scry_sniff::list_devices().unwrap_or_default();
        // 用一条样例流预填 Repeater 编辑区(打开即有内容,免空面板)。
        let sample = flows.get(1).or_else(|| flows.first());
        let (rp_target_text, rp_req_text) = match sample {
            Some(f) => (
                crate::repeater::target_string(f),
                crate::repeater::render_raw_request(f),
            ),
            None => (String::new(), String::new()),
        };
        let rp_target = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder(lang.t("https://host[:port]"))
                .clearable(true)
                .with_text(rp_target_text)
        });
        let rp_req = cx.new(|cx| {
            InputState::multi_line(cx)
                .placeholder("GET /path HTTP/1.1\nHost: example.com\n\n<body>")
                .min_rows(14)
                .with_text(rp_req_text)
        });

        // 爆破页:优先用带查询串的流当模板(自动标记参数,打开即可跑),否则回退样例。
        let it_sample = flows
            .iter()
            .find(|f| f.path.contains('?'))
            .or_else(|| flows.get(1))
            .or_else(|| flows.first());
        let (it_target_text, it_req_text) = match it_sample {
            Some(f) => (
                crate::repeater::target_string(f),
                crate::intruder::auto_mark(&crate::repeater::render_raw_request(f)),
            ),
            None => (String::new(), String::new()),
        };
        let it_target = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder(lang.t("https://host[:port]"))
                .clearable(true)
                .with_text(it_target_text)
        });
        let it_req = cx.new(|cx| {
            InputState::multi_line(cx)
                .placeholder("GET /path?id=§1§ HTTP/1.1\nHost: example.com\n\n<body>")
                .min_rows(10)
                .with_text(it_req_text)
        });
        let it_payloads = cx.new(|cx| {
            InputState::multi_line(cx)
                .placeholder("payload-1\npayload-2\n…")
                .min_rows(6)
                .with_text("1\n2\n3\nadmin\ntest")
        });
        let it_match = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder(lang.t("Grep match (optional)"))
                .clearable(true)
        });
        // 数字区间 / 字符集暴破 / 处理器前后缀(载荷生成器配置)。
        let it_num = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder("1-9999  ·  0-100:5")
                .clearable(true)
                .with_text("1-100")
        });
        let it_charset = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder("abcdefghijklmnopqrstuvwxyz0123456789")
                .clearable(true)
                .with_text("0123456789")
        });
        let it_len = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder("1-4")
                .clearable(true)
                .with_text("1-3")
        });
        let it_prefix = cx.new(|cx| InputState::single_line(cx).clearable(true));
        let it_suffix = cx.new(|cx| InputState::single_line(cx).clearable(true));
        // Grep-Extract 正则 + 限速延迟。
        let it_extract = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder("regex, e.g. token=([0-9a-f]+)")
                .clearable(true)
        });
        let it_throttle = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder("0")
                .clearable(true)
                .with_text("0")
        });

        // 模板 / 载荷 / grep / 生成器配置改动即刷新注入点计数、载荷数、预览与命中高亮。
        cx.observe(&it_req, |_this, _src, cx| cx.notify()).detach();
        cx.observe(&it_payloads, |_this, _src, cx| cx.notify()).detach();
        cx.observe(&it_match, |_this, _src, cx| cx.notify()).detach();
        cx.observe(&it_num, |_this, _src, cx| cx.notify()).detach();
        cx.observe(&it_charset, |_this, _src, cx| cx.notify()).detach();
        cx.observe(&it_len, |_this, _src, cx| cx.notify()).detach();
        cx.observe(&it_prefix, |_this, _src, cx| cx.notify()).detach();
        cx.observe(&it_suffix, |_this, _src, cx| cx.notify()).detach();
        cx.observe(&it_extract, |_this, _src, cx| cx.notify()).detach();

        // SQLi 注入测试:预填一条带查询参数的样例请求(打开即可演示注入点选择)。
        let sqli_sample = flows
            .iter()
            .find(|f| f.path.contains('?'))
            .or_else(|| flows.get(1))
            .or_else(|| flows.first());
        let (sqli_target_text, sqli_req_text) = match sqli_sample {
            Some(f) => (
                crate::repeater::target_string(f),
                crate::repeater::render_raw_request(f),
            ),
            None => (String::new(), String::new()),
        };
        let sqli_target = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder(lang.t("https://host[:port]"))
                .clearable(true)
                .with_text(sqli_target_text)
        });
        let sqli_req = cx.new(|cx| {
            InputState::multi_line(cx)
                .placeholder("GET /path?id=1 HTTP/1.1\nHost: example.com\n\n<body>")
                .min_rows(12)
                .with_text(sqli_req_text)
        });
        cx.observe(&sqli_req, |_this, _src, cx| cx.notify()).detach();

        // XSS 注入测试:同样预填带查询参数的样例请求。
        let (xss_target_text, xss_req_text) = match sqli_sample {
            Some(f) => (
                crate::repeater::target_string(f),
                crate::repeater::render_raw_request(f),
            ),
            None => (String::new(), String::new()),
        };
        let xss_target = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder(lang.t("https://host[:port]"))
                .clearable(true)
                .with_text(xss_target_text)
        });
        let xss_req = cx.new(|cx| {
            InputState::multi_line(cx)
                .placeholder("GET /path?q=1 HTTP/1.1\nHost: example.com\n\n<body>")
                .min_rows(12)
                .with_text(xss_req_text)
        });
        cx.observe(&xss_req, |_this, _src, cx| cx.notify()).detach();

        // 越权测试:同样预填一条样例请求当高权限基准;身份头留空,提示用户填低权限身份。
        let (authz_target_text, authz_req_text) = match sample {
            Some(f) => (
                crate::repeater::target_string(f),
                crate::repeater::render_raw_request(f),
            ),
            None => (String::new(), String::new()),
        };
        let authz_target = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder(lang.t("https://host[:port]"))
                .clearable(true)
                .with_text(authz_target_text)
        });
        let authz_req = cx.new(|cx| {
            InputState::multi_line(cx)
                .placeholder("GET /api/order/1001 HTTP/1.1\nHost: example.com\nAuthorization: Bearer <admin>\n\n")
                .min_rows(10)
                .with_text(authz_req_text)
        });
        let authz_high = cx.new(|cx| {
            InputState::multi_line(cx)
                .placeholder(lang.t("Header: value per line (empty = use the request as-is)"))
                .min_rows(3)
        });
        let authz_low = cx.new(|cx| {
            InputState::multi_line(cx)
                .placeholder(lang.t("Header: value per line (optional)"))
                .min_rows(3)
        });
        cx.observe(&authz_req, |_this, _src, cx| cx.notify()).detach();

        // 序列器:令牌样本输入(每行一个;空开局,点「加载样例」或「从流量」填充);改动即刷新计数。
        let seq_input = cx.new(|cx| {
            InputState::multi_line(cx)
                .placeholder("token-1\ntoken-2\n…")
                .min_rows(14)
        });
        cx.observe(&seq_input, |_this, _src, cx| cx.notify()).detach();

        // 解码器:输入预填一段含特殊字符的示例(打开即可演示编解码);改动即刷新字符计数。
        let dec_input = cx.new(|cx| {
            InputState::multi_line(cx)
                .placeholder(lang.t("Paste text to encode / decode…"))
                .min_rows(12)
                .with_text("Hello, 世界! <b>&\"'")
        });
        let dec_output = cx.new(|cx| {
            InputState::multi_line(cx)
                .placeholder(lang.t("Result appears here"))
                .min_rows(12)
        });
        // 加解密密钥 / IV(预填一个 16 字节示例,打开即可演示 AES)。
        let dec_key = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder(lang.t("Key (UTF-8) · AES needs 16/24/32 bytes"))
                .clearable(true)
                .with_text("0123456789abcdef")
        });
        let dec_iv = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder(lang.t("IV (16 bytes) · AES-CBC only"))
                .clearable(true)
                .with_text("abcdef9876543210")
        });
        cx.observe(&dec_input, |_this, _src, cx| cx.notify()).detach();
        cx.observe(&dec_output, |_this, _src, cx| cx.notify()).detach();

        // 代理详情(原始 / 十六进制 / 渲染视图):只读可选中文本框,支持选中 + Cmd/Ctrl+C 复制。
        // 字体对齐右侧检查器(等宽 Menlo + xs 字号),让报文区与检查器观感一致;美化视图另走只读高亮
        // CodeView(见 proxy::message_panel),不在此承载。
        let msg_font_size = cx.theme().tokens.font_size.xs;
        let msg_req = cx.new(|cx| {
            InputState::multi_line(cx)
                .read_only(true)
                .seamless(true)
                .font_family(model::MONO)
                .font_size(msg_font_size)
                .placeholder(lang.t("Select a row above to view the message"))
                .min_rows(8)
        });
        let msg_resp = cx.new(|cx| {
            InputState::multi_line(cx)
                .read_only(true)
                .seamless(true)
                .font_family(model::MONO)
                .font_size(msg_font_size)
                .placeholder(lang.t("Select a row above to view the message"))
                .min_rows(8)
        });

        // 拦截编辑器:被拦报文在此**可编辑**,放行时按它重建请求 / 响应。
        let intercept_edit = cx.new(|cx| {
            InputState::multi_line(cx)
                .placeholder(lang.t("Intercepted traffic will appear here to edit"))
                .min_rows(12)
        });

        // 拦截规则表单的输入框(Options 页:范围规则的值 + Match & Replace 的查找/替换)。
        let sr_value = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder(lang.t("value, e.g. api.example.com"))
                .clearable(true)
        });
        let mr_find = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder(lang.t("Find (empty = append a header)"))
                .clearable(true)
        });
        let mr_replace = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder(lang.t("Replace with…"))
                .clearable(true)
        });

        // Repeater / Intruder 响应 + 解码输出的只读可选中高亮查看器(与 msg_* 同款;文本由各 sync_* 灌入)。
        let rp_resp_input = cx.new(|cx| {
            InputState::multi_line(cx)
                .read_only(true)
                .placeholder(lang.t("Edit the request on the left, then Send"))
                .min_rows(10)
        });
        let it_resp_input = cx.new(|cx| {
            InputState::multi_line(cx)
                .read_only(true)
                .placeholder(lang.t("Select a result to view the response"))
                .min_rows(8)
        });
        let dec_view = cx.new(|cx| {
            InputState::multi_line(cx)
                .read_only(true)
                .placeholder(lang.t("Result appears here"))
                .min_rows(12)
        });

        // 比较器:两段文本预填略有差异的示例(打开即可演示 diff)。
        let cmp_a = cx.new(|cx| {
            InputState::multi_line(cx)
                .placeholder(lang.t("Paste the first item…"))
                .min_rows(12)
                .with_text("the quick brown fox\njumps over the lazy dog\n")
        });
        let cmp_b = cx.new(|cx| {
            InputState::multi_line(cx)
                .placeholder(lang.t("Paste the second item…"))
                .min_rows(12)
                .with_text("the slow brown fox\njumps over the lazy dog!\n")
        });

        // 半秒一拍:刷新状态栏运行时长;抓包时从推流通道**增量**取新流量(不再全量轮询 DB)。
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(500))
                    .await;
                if this
                    .update(cx, |this, cx| {
                        if this.capturing {
                            this.drain_new_flows();
                            this.drain_intercepts(cx);
                        }
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();

        // 启动只建一个「默认会话」,其数据 = 启动载入的 flows(放在 self.flows 工作集)。
        let sessions = vec![model::new_session("默认会话", 0)];
        let rename_input = cx.new(InputState::single_line);

        // T2 托管启动:命令输入(预填一个能演示解密的示例)。
        let prog_input = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder(lang.t("e.g. curl https://example.com"))
                .clearable(true)
                .with_text("curl https://example.com")
        });

        // 上游代理输入(预填探测到的 sing-box 本地入口;默认关,在设置页开关启用)。
        let upstream_input = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder("http://127.0.0.1:20122  ·  socks5://127.0.0.1:1080")
                .clearable(true)
                .with_text("http://127.0.0.1:20122")
        });

        // 事件日志搜索框 + 初始一条「启动」日志。
        let log_search = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder(lang.t("Filter logs…"))
                .clearable(true)
        });
        cx.observe(&log_search, |_this, _src, cx| cx.notify()).detach();
        let logs = initial_logs(demo);

        // 站点爬虫种子输入(预填首个抓到的 host,打开扫描器即可一键爬)。
        let crawl_seed_text = flows
            .first()
            .map(|f| format!("{}://{}/", f.scheme, f.host))
            .unwrap_or_default();
        let crawl_seed = cx.new(|cx| {
            InputState::single_line(cx)
                .placeholder(lang.t("Seed URL(s), e.g. https://example.com/"))
                .clearable(true)
                .with_text(crawl_seed_text)
        });
        cx.observe(&crawl_seed, |_this, _src, cx| cx.notify()).detach();

        Self {
            // 默认落在仪表盘:先点选抓包源(默认代理),再开始抓包(Wireshark 式)。
            tab: Tab::Dashboard,
            sessions,
            active_session: 0,
            rename_idx: None,
            rename_input,
            flows,
            selected: Some(1),
            sort_newest: true,
            marks: std::collections::HashMap::new(),
            search,
            proto: Proto::All,
            hist_tab: HistTab::History,
            ws_msgs: Vec::new(),
            ws_selected: None,
            ws_rx: None,
            ws_scroll: UniformListScrollHandle::new(),
            req_view: MsgView::Pretty,
            resp_view: MsgView::Pretty,
            msg_req,
            msg_resp,
            msg_req_sig: None,
            msg_resp_sig: None,
            intercept_rx: None,
            intercept_queue: std::collections::VecDeque::new(),
            intercept_edit,
            intercept_edit_id: None,
            // 启动即从磁盘加载已保存的拦截 / 改包规则(抓包时 sync_rules_to_engine 推给引擎自动生效)。
            scope_rules: crate::rules::load_rules().0,
            replace_rules: crate::rules::load_rules().1,
            sr_dir: crate::ext::InterceptDir::Request,
            sr_field: crate::rules::Field::Host,
            sr_op: crate::rules::Op::Contains,
            sr_field_open: false,
            sr_op_open: false,
            sr_value,
            sr_negate: false,
            sr_intercept: true,
            mr_target: crate::rules::Target::ReqHeaders,
            mr_target_open: false,
            mr_find,
            mr_replace,
            mr_regex: false,
            insp_tab: InspTab::Inspector,
            insp_open: [true, true, false, false],
            rail: 0,
            rp_target,
            rp_req,
            rp_resp: None,
            rp_err: None,
            rp_sending: false,
            rp_resp_view: MsgView::Pretty,
            rp_req_view: MsgView::Pretty,
            rp_resp_input,
            rp_resp_sig: u64::MAX,
            scan_findings: Vec::new(),
            scan_ran: false,
            scan_busy: false,
            scan_progress: None,
            scan_filter: None,
            scan_target: None,
            scan_target_open: false,
            scan_total: 0,
            scan_done: 0,
            scan_paused: false,
            scan_rx: None,
            scan_ctrl: None,
            sqli_target,
            sqli_req,
            sqli_point_sel: 0,
            sqli_point_open: false,
            sqli_secs: 3,
            sqli_secs_open: false,
            sqli_busy: false,
            sqli_progress: None,
            sqli_log: Vec::new(),
            sqli_report: SqliReport::default(),
            sqli_rx: None,
            sqli_ctrl: None,
            xss_target,
            xss_req,
            xss_point_sel: 0,
            xss_point_open: false,
            xss_busy: false,
            xss_progress: None,
            xss_log: Vec::new(),
            xss_findings: Vec::new(),
            xss_sinks: Vec::new(),
            xss_rx: None,
            xss_ctrl: None,
            xss_dom: false,
            xss_child: None,
            authz_target,
            authz_req,
            authz_high,
            authz_low,
            authz_busy: false,
            authz_progress: None,
            authz_log: Vec::new(),
            authz_rows: Vec::new(),
            authz_findings: Vec::new(),
            authz_ran: false,
            authz_rx: None,
            authz_ctrl: None,
            crawl_seed,
            crawl_depth: 2,
            crawl_pages: 60,
            crawl_depth_open: false,
            crawl_pages_open: false,
            crawl_busy: false,
            crawl_progress: None,
            crawl_rx: None,
            crawl_ctrl: None,
            crawl_visited: Vec::new(),
            crawl_child: None,
            it_target,
            it_req,
            it_payloads,
            it_match,
            it_mode: AttackMode::Sniper,
            it_results: Vec::new(),
            it_selected: None,
            it_busy: false,
            it_progress: None,
            it_total: 0,
            it_rx: None,
            it_resp_view: MsgView::Pretty,
            it_req_view: MsgView::Raw,
            it_resp_input,
            it_resp_sig: u64::MAX,
            it_src: PayloadKind::List,
            it_num,
            it_charset,
            it_len,
            it_prefix,
            it_suffix,
            it_proc_mask: 0,
            it_extract,
            it_sort: SortBy::Order,
            it_sort_desc: false,
            it_concurrency: 1,
            it_throttle,
            seq_input,
            seq_report: None,
            dec_input,
            dec_output,
            dec_view,
            dec_view_sig: u64::MAX,
            dec_key,
            dec_iv,
            dec_note: None,
            dec_err: false,
            cmp_a,
            cmp_b,
            cmp_gran: scry_diff::Granularity::Line,
            cmp_report: None,
            upstream_input,
            upstream_enabled: false,
            capture_mode: CaptureMode::Proxy, // 默认代理(MITM):可解密 HTTPS,配合 Proxifier / 在 QX 后面按进程喂流量
            capturing: false,
            store: None,
            capture_stop: None,
            sniff_stop: None,
            flow_rx: None,
            prog_input,
            launched: Vec::new(),
            hist_scroll: UniformListScrollHandle::new(),
            host_filter: None,
            host_cat_open: false,
            ifaces,
            iface_sel: 0,
            iface_open: false,
            pcapng_enabled: false,
            tls_profile_sel: 0,
            tls_profile_open: false,
            demo,
            cert_status: CertStatus::Unknown,
            cert_msg: None,
            cert_busy: false,
            logs,
            log_filter: None,
            log_search,
            ctx_menu: None,
            toast: None,
            lang,
            started: Instant::now(),
            ext: std::sync::Arc::new(crate::ext::ExtRegistry::with_builtins()),
        }
    }

    /// 弹一条短暂提示(~1.8s 后自动消失)。
    pub fn show_toast(&mut self, msg: impl Into<String>, cx: &mut Context<Self>) {
        self.toast = Some(msg.into());
        cx.notify();
        cx.spawn(async move |this, cx| {
            cx.background_executor()
                .timer(Duration::from_millis(1800))
                .await;
            let _ = this.update(cx, |this, cx| {
                this.toast = None;
                cx.notify();
            });
        })
        .detach();
    }

    /// 切换界面语言(并同步更新各输入框占位符)。
    pub fn toggle_lang(&mut self, cx: &mut Context<Self>) {
        self.lang = self.lang.toggle();
        let l = self.lang;
        self.search.update(cx, |s, cx| {
            s.set_placeholder(l.t("Filter: host / path / header / body…"), cx)
        });
        self.rp_target
            .update(cx, |s, cx| s.set_placeholder(l.t("https://host[:port]"), cx));
        self.it_target
            .update(cx, |s, cx| s.set_placeholder(l.t("https://host[:port]"), cx));
        self.sqli_target
            .update(cx, |s, cx| s.set_placeholder(l.t("https://host[:port]"), cx));
        self.xss_target
            .update(cx, |s, cx| s.set_placeholder(l.t("https://host[:port]"), cx));
        self.authz_target
            .update(cx, |s, cx| s.set_placeholder(l.t("https://host[:port]"), cx));
        self.authz_high.update(cx, |s, cx| {
            s.set_placeholder(l.t("Header: value per line (empty = use the request as-is)"), cx)
        });
        self.authz_low.update(cx, |s, cx| {
            s.set_placeholder(l.t("Header: value per line (optional)"), cx)
        });
        self.it_match
            .update(cx, |s, cx| s.set_placeholder(l.t("Grep match (optional)"), cx));
        self.crawl_seed.update(cx, |s, cx| {
            s.set_placeholder(l.t("Seed URL(s), e.g. https://example.com/"), cx)
        });
        self.dec_input
            .update(cx, |s, cx| s.set_placeholder(l.t("Paste text to encode / decode…"), cx));
        self.dec_output
            .update(cx, |s, cx| s.set_placeholder(l.t("Result appears here"), cx));
        self.dec_key.update(cx, |s, cx| {
            s.set_placeholder(l.t("Key (UTF-8) · AES needs 16/24/32 bytes"), cx)
        });
        self.dec_iv
            .update(cx, |s, cx| s.set_placeholder(l.t("IV (16 bytes) · AES-CBC only"), cx));
        self.cmp_a
            .update(cx, |s, cx| s.set_placeholder(l.t("Paste the first item…"), cx));
        self.cmp_b
            .update(cx, |s, cx| s.set_placeholder(l.t("Paste the second item…"), cx));
        cx.notify();
    }

    /// 当前选中的流。
    pub fn current_flow(&self) -> Option<&HttpFlow> {
        self.selected.and_then(|i| self.flows.get(i))
    }

    /// 状态栏运行时长。
    pub fn uptime(&self) -> String {
        model::dur_hms(self.started.elapsed().as_secs())
    }

    /// 从只读查看器复制:有选区复制选区,否则复制整段;空则不动。各页报文 / 输出查看器共用。
    pub fn copy_from_input(&mut self, input: Entity<InputState>, cx: &mut Context<Self>) {
        let text = {
            let st = input.read(cx);
            let sel = st.selected_text();
            if sel.is_empty() {
                st.text().to_string()
            } else {
                sel.to_string()
            }
        };
        if text.is_empty() {
            return;
        }
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        let msg = self.lang.t("Copied to clipboard").to_string();
        self.show_toast(msg, cx);
    }

    /// 当前生效的上游代理(启用且地址可解析时);否则 `None`(直连)。
    /// 抓包 / 重放 / 扫描共用:解密后的流量交给它出网(sing-box / QX 链式)。
    pub fn upstream_proxy(&self, cx: &Context<Self>) -> Option<scry_proxy::upstream::UpstreamProxy> {
        if !self.upstream_enabled {
            return None;
        }
        let text = self.upstream_input.read(cx).text().to_string();
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        scry_proxy::upstream::UpstreamProxy::parse(text).ok()
    }
}
