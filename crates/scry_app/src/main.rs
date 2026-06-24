//! Scry 界面入口 —— 复用 [`mage_ui`](../../../mage-ui)(gpui)拼出 Burp 式安全渗透工作台。
//!
//! 模块分层(组件化):
//! - [`model`]:展示数据与格式化辅助(流量取色 / Type / IP / 时间 + 演示数据)。
//! - [`widgets`]:无状态小构件(分割线 / 分组标题 / 计数药丸 / TLS 单元格 …)。
//! - [`state`]:应用状态 [`state::ScryApp`] + 导航枚举。
//! - [`chrome`]:外壳(顶栏 / 左栏 / Inspector / 图标栏 / 状态栏)+ [`gpui::Render`]。
//! - [`proxy`]:Proxy 页(拦截 / 历史表 / 报文视图)。
//! - [`repeater`]:Repeater 页(改包重发)+ 报文解析单测。
//! - [`launcher`]:流量源启动器(T1 内置浏览器 / T2 托管启动程序 —— scry 自管流量源)。
//! - [`intruder`]:Intruder 爆破页(§标记§ + 载荷 + 批量发包)+ 引擎单测。
//! - [`sqli`]:SQLi 页(sqlmap 式 SQL 注入检测与利用)—— UI 接 `scry_sqli` 内核。
//! - [`xss`]:XSS 页(dalfox 式上下文感知反射型 XSS)—— UI 接 `scry_xss` 内核。
//! - [`authz`]:Authz 页(Autorize 式越权 / 访问控制测试)—— UI 接 `scry_scan::authz` 内核。
//! - [`sequencer`]:Sequencer 页(令牌随机性 / 熵分析)—— UI 接 `scry_seq` 内核。
//! - [`decoder`]:Decoder 页(URL/HTML/Base64/Hex 编解码 + 哈希)—— UI 接 `scry_codec` 内核。
//! - [`comparer`]:Comparer 页(两段文本 diff)—— UI 接 `scry_diff` 内核。
//! - [`crawler`]:站点爬虫(Spider)异步 runner —— UI 接 `scry_crawl` 内核(种子 → BFS 抓取 → 发现页落库)。
//! - [`logger`]:Logger 页(实时事件日志:抓包 / 扫描 / 证书 / 上游 等)。

mod authz;
mod capture;
mod cert;
mod chrome;
mod comparer;
mod crawler;
mod dashboard;
mod decoder;
mod ext;
mod har;
mod highlight;
mod i18n;
mod intercept;
mod intruder;
mod launcher;
mod logger;
mod model;
mod proxy;
mod repeater;
mod rules;
mod scanner;
mod sequencer;
mod settings;
mod spider;
mod sqli;
mod state;
mod widgets;
mod xss;

use mage_ui::prelude::*;
use mage_ui::theme;

use crate::state::ScryApp;

fn main() {
    // drission(reqwest)带入了 rustls 的 aws-lc-rs 后端,与 scry 的 ring 并存 → rustls 0.23 没有
    // 单一默认 CryptoProvider,任何走默认路径的 TLS 调用(reqwest HTTPS / drission 下载 Chrome)会
    // panic。进程启动最早处显式把 ring 装为默认,统一到 ring(scry MITM 本就用 ring)。
    let _ = rustls::crypto::ring::default_provider().install_default();

    application().run(|cx: &mut App| {
        theme::init(cx, ThemeMode::Dark);
        // 文本输入(搜索框 / Repeater 编辑区)需要的全局快捷键。
        bind_input_keys(cx);

        let bounds = Bounds::centered(None, size(px(1520.0), px(940.0)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_background: WindowBackgroundAppearance::Blurred,
                ..Default::default()
            },
            |_window, cx| cx.new(ScryApp::new),
        )
        .unwrap();
        cx.activate(true);
    });
}
