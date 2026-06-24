//! 仪表盘(Dashboard)—— 以「**抓什么**」组织,scry 自管流量源(对标 Burp,不抢系统代理)。
//!
//! 抓包内核唯一:**MITM 代理**(TLS 终止式,解密 + 改包)。仪表盘按「抓包目标」给四张卡:
//! - **T1 抓网站(内置浏览器)** ⭐ 默认零配置:scry 拉起 Chromium,喂代理 + CA SPKI + 独立 profile。
//! - **T2 抓程序 / 命令**:托管启动任意程序,注入代理 + CA env。
//! - **T4 对接代理客户端**(sing-box / QX / Proxifier):抓「已运行的任意软件」,进阶。
//! - **抓整机(被动嗅探)**:任意软件但仅元数据 + SNI(辅助降级,不解密),可另存 pcapng。
//!
//! 前三者都汇聚到同一个 MITM 内核(`capture_mode = Proxy`);嗅探走 `Kernel`(辅助)。

use mage_ui::prelude::*;

use crate::i18n::Lang;
use crate::model::MONO;
use crate::state::{CaptureMode, ScryApp, Tab};
use crate::widgets::section_label;

impl ScryApp {
    /// 循环切换内核抓包(嗅探)的网卡。抓包中禁止切换。
    pub fn cycle_iface(&mut self, cx: &mut Context<Self>) {
        if self.capturing || self.ifaces.is_empty() {
            return;
        }
        self.iface_sel = (self.iface_sel + 1) % self.ifaces.len();
        cx.notify();
    }

    /// 开始**被动嗅探**(辅助路径,`Kernel` 模式)。已在抓包则提示先停止。
    pub fn start_sniff(&mut self, cx: &mut Context<Self>) {
        if self.capturing {
            self.cert_msg = Some(if self.lang.is_zh() {
                "请先停止当前抓包,再切到被动嗅探".to_string()
            } else {
                "Stop the current capture before switching to passive sniff".to_string()
            });
            cx.notify();
            return;
        }
        self.capture_mode = CaptureMode::Kernel;
        self.start_capture(cx);
    }

    /// 当前网卡名(嗅探卡展示)。
    fn current_iface_name(&self) -> SharedString {
        self.ifaces
            .get(self.iface_sel)
            .cloned()
            .map(SharedString::from)
            .unwrap_or_else(|| SharedString::from(if self.lang.is_zh() { "(无可用网卡)" } else { "(no NIC)" }))
    }

    /// 仪表盘页主体。
    pub fn dashboard_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let l = self.lang;
        let cap = self.capturing;
        let proxy_running = cap && self.capture_mode == CaptureMode::Proxy;
        let sniff_running = cap && self.capture_mode == CaptureMode::Kernel;

        // ── 顶部:标题 + 内核状态 + 大「停止抓包」按钮(抓包时) ──
        let core_text: SharedString = if proxy_running {
            SharedString::from("127.0.0.1:8888")
        } else if sniff_running {
            self.current_iface_name()
        } else {
            l.t("Idle")
        };
        let core_color = if cap { c.success } else { c.text_subtle };

        let mut header = div().flex().items_center().justify_between().gap(t.space.lg).child(
            div()
                .flex()
                .flex_col()
                .gap(px(3.0))
                .child(
                    div()
                        .text_size(t.font_size.xl)
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(c.text)
                        .child(l.t("What do you want to capture?")),
                )
                .child(
                    div()
                        .text_size(t.font_size.sm)
                        .text_color(c.text_subtle)
                        .child(l.t("Scry launches the traffic source itself — no system proxy, no Chrome tweaks")),
                ),
        );
        let mut status_pill = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .child(StatusDot::new(core_color))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .items_end()
                    .child(
                        div()
                            .text_size(t.font_size.xs)
                            .text_color(c.text_subtle)
                            .child(l.t("MITM core")),
                    )
                    .child(
                        div()
                            .font_family(MONO)
                            .text_size(t.font_size.sm)
                            .text_color(core_color)
                            .child(core_text),
                    ),
            );
        if cap {
            status_pill = status_pill.child(
                Button::new("dash-stop", l.t("Stop capture"))
                    .variant(ButtonVariant::Danger)
                    .icon(IconName::Zap)
                    .on_click(cx.listener(|this, _e, _w, cx| this.toggle_capture(cx))),
            );
        }
        // 顶部快捷入口:离线导入 HAR / XHR(详细说明见底部「离线导入」卡)。
        let import_btn = Button::new("dash-import-top", l.t("Import HAR / XHR file"))
            .ghost()
            .size(ButtonSize::Sm)
            .icon(IconName::Download)
            .on_click(cx.listener(|this, _e, _w, cx| this.import_har_dialog(cx)));
        header = header.child(
            div()
                .flex()
                .items_center()
                .gap(t.space.md)
                .child(import_btn)
                .child(status_pill),
        );

        // ── 概览指标 ──
        let https = self.flows.iter().filter(|f| f.scheme == "https").count();
        let http = self.flows.iter().filter(|f| f.scheme == "http").count();
        let metrics = div()
            .flex()
            .gap(t.space.md)
            .child(Metric::new(IconName::Layers, l.t("Total flows"), self.flows.len().to_string()).color(c.primary))
            .child(Metric::new(IconName::Tag, "HTTPS", https.to_string()).color(c.success))
            .child(Metric::new(IconName::Globe, "HTTP", http.to_string()).color(c.accent))
            .child(Metric::new(IconName::Clock, l.t("Duration"), self.uptime()).color(c.warning));

        // ── 当前操作结果提示 ──
        let msg_el = self.cert_msg.as_ref().map(|msg| {
            let ok = !msg.contains("失败")
                && !msg.contains("取消")
                && !msg.contains("占用")
                && !msg.contains("先停止")
                && !msg.contains("请先")
                && !msg.contains("未找到")
                && !msg.contains("before")
                && !msg.contains("first");
            div()
                .p(t.space.md)
                .rounded(t.radius.lg)
                .bg(c.glass)
                .border_1()
                .border_color(if ok { c.success.opacity(0.4) } else { c.warning.opacity(0.4) })
                .text_size(t.font_size.sm)
                .text_color(if ok { c.success } else { c.warning })
                .child(msg.clone())
        });

        div()
            .id("dashboard-scroll")
            .flex_1()
            .min_h(px(0.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .items_center()
            .p(t.space.xl)
            .child(
                div()
                    .w(px(820.0))
                    .max_w(px(820.0))
                    .flex()
                    .flex_col()
                    .gap(t.space.lg)
                    .child(header)
                    .child(metrics)
                    .child(section_label(l.t("Decrypting capture (MITM core)"), c, t))
                    .child(self.card_browser(proxy_running, cx))
                    .child(self.card_program(proxy_running, cx))
                    .child(self.card_client(proxy_running, cx))
                    .child(section_label(l.t("Passive (auxiliary · metadata only)"), c, t))
                    .child(self.card_sniff(sniff_running, cx))
                    .child(section_label(l.t("Import / offline"), c, t))
                    .child(self.card_import(cx))
                    .children(msg_el),
            )
    }

    /// T1 · 抓网站(内置浏览器)。
    fn card_browser(&self, running: bool, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let l = self.lang;
        target_card(running, c, t)
            .child(card_header(
                IconName::Globe,
                l.t("Capture a website (built-in browser)"),
                l.t("Scry launches Chromium pointed at it — decrypts HTTPS, bypasses pinning, no system CA"),
                vec![(l.t("Recommended"), c.primary), (l.t("Decrypt"), c.success)],
                running,
                l,
                c,
                t,
            ))
            .child(HintRow::new(IconName::Check, l.t("Isolated profile — won't touch your daily browser")))
            .child(HintRow::new(IconName::Check, l.t("Using an HTTP proxy disables QUIC, so nothing slips by")))
            .child(if self.has_browser() {
                // 已在运行:复用而非再拉一个(防多开堆积),并提供单独关闭。
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .child(
                        Button::new("dash-close-browser", l.t("Close browser"))
                            .variant(ButtonVariant::Danger)
                            .icon(IconName::Trash)
                            .on_click(cx.listener(|this, _e, _w, cx| this.close_browser(cx))),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(5.0))
                            .child(StatusDot::new(c.success))
                            .child(
                                div()
                                    .text_size(t.font_size.xs)
                                    .text_color(c.success)
                                    .child(l.t("Built-in browser running")),
                            ),
                    )
                    .into_any_element()
            } else {
                Button::new("dash-launch-browser", l.t("Launch browser capture"))
                    .variant(ButtonVariant::Primary)
                    .icon(IconName::Globe)
                    .on_click(cx.listener(|this, _e, _w, cx| this.launch_browser_capture(cx)))
                    .into_any_element()
            })
    }

    /// T2 · 抓程序 / 命令(托管启动)。
    fn card_program(&self, running: bool, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let l = self.lang;
        target_card(running, c, t)
            .child(card_header(
                IconName::Package,
                l.t("Capture a program / command"),
                l.t("Launches it with proxy + CA injected (curl, Electron, Java, Python, Node…)"),
                vec![(l.t("Decrypt"), c.success)],
                running,
                l,
                c,
                t,
            ))
            .child(self.prog_input.clone())
            .child(
                Button::new("dash-launch-prog", l.t("Launch & capture"))
                    .variant(ButtonVariant::Primary)
                    .icon(IconName::Zap)
                    .on_click(cx.listener(|this, _e, _w, cx| this.launch_program_capture(cx))),
            )
    }

    /// T4 · 对接代理客户端(sing-box / QX / Proxifier)。
    fn card_client(&self, running: bool, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let l = self.lang;
        target_card(running, c, t)
            .child(card_header(
                IconName::GitBranch,
                l.t("Connect a proxy client (sing-box / QX / Proxifier)"),
                l.t("Capture any already-running app by routing its traffic into Scry"),
                vec![(l.t("Decrypt"), c.success), (l.t("Advanced"), c.warning)],
                running,
                l,
                c,
                t,
            ))
            .child(HintRow::new(IconName::Globe, l.t("Point the client proxy to 127.0.0.1:8888 (sing-box: use the Scry plugin)")))
            .child(HintRow::new(IconName::GitBranch, l.t("Set upstream to socks5://127.0.0.1:8899 in Settings so traffic exits via your nodes")))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .flex_wrap()
                    .child(
                        Button::new("dash-core-only", l.t("Start MITM core only"))
                            .ghost()
                            .size(ButtonSize::Sm)
                            .icon(IconName::Zap)
                            .on_click(cx.listener(|this, _e, _w, cx| this.start_core_capture(cx))),
                    )
                    .child(
                        Button::new("dash-goto-settings", l.t("Upstream / cert settings"))
                            .ghost()
                            .size(ButtonSize::Sm)
                            .icon(IconName::Settings)
                            .on_click(cx.listener(|this, _e, _w, cx| {
                                this.tab = Tab::Settings;
                                cx.notify();
                            })),
                    ),
            )
    }

    /// 抓整机(被动嗅探,辅助)。
    fn card_sniff(&self, running: bool, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let l = self.lang;
        target_card(running, c, t)
            .child(card_header(
                IconName::Layers,
                l.t("Capture the whole machine (passive sniff)"),
                l.t("Any app, but HTTPS shows metadata + SNI only (no decryption)"),
                vec![(l.t("Metadata only"), c.warning), (l.t("Auxiliary"), c.text_subtle)],
                running,
                l,
                c,
                t,
            ))
            // 网卡选择(循环切换)。
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
                            .child(Icon::new(IconName::Globe).size(px(16.0)).color(c.text_subtle))
                            .child(div().text_size(t.font_size.sm).text_color(c.text_muted).child(l.t("Network interface")))
                            .child(div().font_family(MONO).text_size(t.font_size.sm).text_color(c.text).child(self.current_iface_name())),
                    )
                    .child(
                        Button::new("dash-iface-cycle", l.t("Switch"))
                            .ghost()
                            .size(ButtonSize::Sm)
                            .icon(IconName::Refresh)
                            .on_click(cx.listener(|this, _e, _w, cx| this.cycle_iface(cx))),
                    ),
            )
            // pcapng 开关。
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap(t.space.sm)
                    .child(div().text_size(t.font_size.sm).text_color(c.text_muted).child(l.t("Save pcapng (Wireshark)")))
                    .child(
                        Switch::new("dash-pcapng", self.pcapng_enabled)
                            .disabled(self.capturing)
                            .on_toggle(cx.listener(|this, _e, _w, cx| {
                                this.pcapng_enabled = !this.pcapng_enabled;
                                cx.notify();
                            })),
                    ),
            )
            .child(
                Button::new("dash-sniff", l.t("Authorize & sniff"))
                    .ghost()
                    .icon(IconName::Check)
                    .on_click(cx.listener(|this, _e, _w, cx| this.start_sniff(cx))),
            )
    }

    /// 离线导入 HAR / XHR —— 浏览器 DevTools「Network」导出的请求文件,落盘去重后进历史。
    fn card_import(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let l = self.lang;
        target_card(false, c, t)
            .child(card_header(
                IconName::Download,
                l.t("Import HAR / XHR file"),
                l.t("Load requests exported from browser DevTools (Network → Save all as HAR)"),
                vec![(l.t("Offline"), c.text_subtle)],
                false,
                l,
                c,
                t,
            ))
            .child(HintRow::new(
                IconName::Check,
                l.t("Imported requests go into history — ready for Repeater / Scanner"),
            ))
            .child(
                Button::new("dash-import-har", l.t("Choose .har file…"))
                    .variant(ButtonVariant::Primary)
                    .icon(IconName::Download)
                    .on_click(cx.listener(|this, _e, _w, cx| this.import_har_dialog(cx))),
            )
    }
}

/// 一张「抓包目标」卡的外框(复用 mage_ui [`GlassPanel`];运行中时主色描边高亮)。
fn target_card(active: bool, c: ThemeColors, t: Tokens) -> GlassPanel {
    let mut p = GlassPanel::new().padding(t.space.lg).gap(t.space.md);
    if active {
        p = p.border_accent(c.primary);
    }
    p
}

/// 卡头:图标方块 + 标题/副标题 + 右侧能力徽标(运行中追加「抓包中」)。
#[allow(clippy::too_many_arguments)]
fn card_header(
    icon: IconName,
    title: SharedString,
    subtitle: SharedString,
    badges: Vec<(SharedString, Hsla)>,
    active: bool,
    l: Lang,
    c: ThemeColors,
    t: Tokens,
) -> impl IntoElement {
    let mut badge_row = div().flex().items_center().gap(px(6.0)).flex_shrink_0();
    if active {
        badge_row = badge_row.child(Badge::new(l.t("Capturing"), c.success));
    }
    for (txt, col) in badges {
        badge_row = badge_row.child(Badge::new(txt, col));
    }
    div()
        .flex()
        .items_start()
        .justify_between()
        .gap(t.space.md)
        .child(
            div()
                .flex()
                .items_center()
                .gap(t.space.md)
                .min_w(px(0.0))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_center()
                        .w(px(40.0))
                        .h(px(40.0))
                        .flex_shrink_0()
                        .rounded(t.radius.md)
                        .bg(c.glass)
                        .border_1()
                        .border_color(c.glass_border)
                        .child(Icon::new(icon).size(px(19.0)).color(if active { c.primary } else { c.text_subtle })),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .min_w(px(0.0))
                        .child(
                            div()
                                .text_size(t.font_size.md)
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(c.text)
                                .child(title),
                        )
                        .child(div().text_size(t.font_size.xs).text_color(c.text_subtle).child(subtitle)),
                ),
        )
        .child(badge_row)
}

