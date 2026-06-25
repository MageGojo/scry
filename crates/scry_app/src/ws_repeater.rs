//! WS 重放(WebSocket Repeater)页:主动建立一条 WS 连接,双向收发帧 —— 对标 Reqable / Postman 的
//! WebSocket 工具。区别于 Proxy 页的 WS 抓包(被动只读),这里**主动连**目标并可反复发消息。
//!
//! async 桥接(同 SQLi / Repeater 范式):会话跑在 `background_executor` 的临时 current-thread runtime
//! 里([`scry_proxy::ws_client::run_session`]);UI → 会话经 `tokio` 无界通道发 [`WsCommand`],
//! 会话 → UI 经 `std` 通道回 [`WsEvent`],由 `cx.spawn` 起的 150ms 轮询 [`drain_ws_repeater`] 收。

use std::time::Duration;

use mage_ui::prelude::*;
use scry_core::HttpFlow;
use scry_proxy::ws_client::{WsClientConfig, WsCommand, WsEvent};

use crate::state::ScryApp;

/// WS 重放消息列表上限(超出丢最旧)。
const WS_MSG_CAP: usize = 2000;

/// 一条 WS 重放收发记录(展示用)。
#[derive(Debug, Clone)]
pub struct WsRepMsg {
    /// `true` = 本端发出,`false` = 对端发来。
    pub outgoing: bool,
    /// opcode 文本标签(Text/Binary/Ping/Pong/Close)。
    pub opcode: String,
    /// 文本预览(二进制按 lossy 显示)。
    pub text: String,
}

impl ScryApp {
    /// 由一条(WS 升级的)HTTP 流构造目标 URL 灌进 WS 重放页:`https→wss` / `http→ws`。
    pub fn fill_ws_from_flow(&mut self, flow: &HttpFlow, cx: &mut Context<Self>) {
        let scheme = if flow.scheme.eq_ignore_ascii_case("https") {
            "wss"
        } else {
            "ws"
        };
        let host = if (scheme == "wss" && flow.port == 443) || (scheme == "ws" && flow.port == 80) {
            flow.host.clone()
        } else {
            format!("{}:{}", flow.host, flow.port)
        };
        let url = format!("{scheme}://{host}{}", flow.path);
        self.ws_rep_url.update(cx, |s, cx| s.set_text(url, cx));
        self.ws_rep_status = None;
        cx.notify();
    }

    /// 连接目标 WS:建通道 → 后台跑会话 → 前台 150ms 轮询事件。
    pub fn ws_connect(&mut self, cx: &mut Context<Self>) {
        if self.ws_rep_connected || self.ws_rep_cmd_tx.is_some() {
            return; // 已连接 / 连接中
        }
        let url = self.ws_rep_url.read(cx).text().trim().to_string();
        if url.is_empty() {
            self.ws_rep_status = Some("请填写 ws:// 或 wss:// 地址".into());
            cx.notify();
            return;
        }
        let upstream = self.upstream_proxy(cx); // 与抓包 / 重放同源出网(墙内经上游)
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<WsCommand>();
        let (evt_tx, evt_rx) = std::sync::mpsc::channel::<WsEvent>();
        self.ws_rep_cmd_tx = Some(cmd_tx);
        self.ws_rep_evt_rx = Some(evt_rx);
        self.ws_rep_msgs.clear();
        self.ws_rep_status = Some("连接中…".into());
        self.push_log(
            crate::logger::LogLevel::Info,
            "ws",
            format!("WS 重放连接 {url}"),
        );

        let cfg = WsClientConfig {
            url,
            upstream,
            ..Default::default()
        };
        cx.background_executor()
            .spawn(async move {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => return,
                };
                rt.block_on(scry_proxy::ws_client::run_session(cfg, cmd_rx, evt_tx));
            })
            .detach();

        // 前台轮询:把会话事件并入状态;会话结束(evt_rx 被清)即停止。
        cx.spawn(async move |this, cx| loop {
            cx.background_executor()
                .timer(Duration::from_millis(150))
                .await;
            let keep = this.update(cx, |this, cx| {
                this.drain_ws_repeater();
                cx.notify();
                this.ws_rep_evt_rx.is_some()
            });
            match keep {
                Ok(true) => continue,
                _ => break,
            }
        })
        .detach();
        cx.notify();
    }

    /// 主动断开:发 Close 帧(会话随后回 `Closed` 事件收尾)。
    pub fn ws_disconnect(&mut self, cx: &mut Context<Self>) {
        if let Some(tx) = self.ws_rep_cmd_tx.as_ref() {
            let _ = tx.send(WsCommand::Close);
        }
        self.ws_rep_status = Some("断开中…".into());
        cx.notify();
    }

    /// 发送当前编辑框文本(作为 Text 帧);发出的消息经会话回灌显示。
    pub fn ws_send(&mut self, cx: &mut Context<Self>) {
        let text = self.ws_rep_send.read(cx).text().to_string();
        if text.is_empty() {
            return;
        }
        match self.ws_rep_cmd_tx.as_ref() {
            Some(tx) => {
                let _ = tx.send(WsCommand::Text(text));
            }
            None => {
                self.ws_rep_status = Some("未连接".into());
            }
        }
        cx.notify();
    }

    /// 排空会话事件通道:并入连接状态 / 消息;关闭 / 出错则清理通道(令轮询停止)。
    pub fn drain_ws_repeater(&mut self) {
        let Some(rx) = &self.ws_rep_evt_rx else {
            return;
        };
        let mut finished = false;
        while let Ok(evt) = rx.try_recv() {
            match evt {
                WsEvent::Connected { status } => {
                    self.ws_rep_connected = true;
                    self.ws_rep_status = Some(format!("已连接({status})"));
                }
                WsEvent::Message { outgoing, opcode, payload } => {
                    let text = String::from_utf8_lossy(&payload).into_owned();
                    self.ws_rep_msgs.push(WsRepMsg { outgoing, opcode, text });
                    if self.ws_rep_msgs.len() > WS_MSG_CAP {
                        let cut = self.ws_rep_msgs.len() - WS_MSG_CAP;
                        self.ws_rep_msgs.drain(0..cut);
                    }
                }
                WsEvent::Closed(reason) => {
                    self.ws_rep_connected = false;
                    self.ws_rep_status = Some(format!("已关闭:{reason}"));
                    finished = true;
                }
                WsEvent::Error(e) => {
                    self.ws_rep_connected = false;
                    self.ws_rep_status = Some(format!("错误:{e}"));
                    finished = true;
                }
            }
        }
        if finished {
            self.ws_rep_cmd_tx = None;
            self.ws_rep_evt_rx = None;
        }
    }

    /// WS 重放页主体。
    pub fn ws_repeater_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let zh = self.lang.is_zh();
        let connected = self.ws_rep_connected;
        let busy = self.ws_rep_cmd_tx.is_some();

        // 标题。
        let title = div()
            .flex()
            .flex_col()
            .gap(px(2.0))
            .child(
                div()
                    .text_size(t.font_size.lg)
                    .text_color(c.text)
                    .child(if zh { "WS 重放" } else { "WS Repeater" }),
            )
            .child(div().text_size(t.font_size.xs).text_color(c.text_subtle).child(if zh {
                "主动连接 WebSocket(ws:// 或 wss://)并双向收发;经设置页上游出网"
            } else {
                "Connect to a WebSocket (ws:// / wss://) and send/receive both ways; exits via upstream from Settings"
            }));

        // 连接栏:URL + 连接/断开。
        let connect_btn = if busy {
            Button::new("ws-disconnect", if zh { "断开" } else { "Disconnect" })
                .on_click(cx.listener(|this, _e, _w, cx| this.ws_disconnect(cx)))
        } else {
            Button::new("ws-connect", if zh { "连接" } else { "Connect" })
                .on_click(cx.listener(|this, _e, _w, cx| this.ws_connect(cx)))
        };
        let bar = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .child(div().flex_1().min_w(px(0.0)).child(self.ws_rep_url.clone()))
            .child(connect_btn);

        // 状态行:圆点 + 文案。
        let status_text = self
            .ws_rep_status
            .clone()
            .unwrap_or_else(|| if zh { "未连接".into() } else { "Disconnected".into() });
        let dot = if connected { c.success } else { c.text_subtle };
        let status_row = div()
            .flex()
            .items_center()
            .gap(t.space.xs)
            .child(div().w(px(8.0)).h(px(8.0)).rounded_full().bg(dot))
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_muted)
                    .child(SharedString::from(status_text)),
            );

        // 消息流。
        let mut rows: Vec<AnyElement> = Vec::with_capacity(self.ws_rep_msgs.len());
        if self.ws_rep_msgs.is_empty() {
            rows.push(
                div()
                    .p(t.space.md)
                    .text_size(t.font_size.sm)
                    .text_color(c.text_subtle)
                    .child(if zh {
                        "连接后,收发的消息会显示在这里"
                    } else {
                        "Messages will appear here once connected"
                    })
                    .into_any_element(),
            );
        } else {
            for m in &self.ws_rep_msgs {
                let (arrow, color) = if m.outgoing {
                    ("\u{25b2}", c.accent) // ▲ 出站
                } else {
                    ("\u{25bc}", c.success) // ▼ 入站
                };
                rows.push(
                    div()
                        .flex()
                        .items_start()
                        .gap(t.space.sm)
                        .px(t.space.sm)
                        .py(px(3.0))
                        .child(
                            div()
                                .flex_shrink_0()
                                .w(px(86.0))
                                .text_size(t.font_size.xs)
                                .text_color(color)
                                .child(format!("{arrow} {}", m.opcode)),
                        )
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(0.0))
                                .text_size(t.font_size.xs)
                                .text_color(c.text_muted)
                                .child(SharedString::from(m.text.clone())),
                        )
                        .into_any_element(),
                );
            }
        }
        let stream = div()
            .id("ws-stream")
            .flex_1()
            .min_h(px(0.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(px(2.0))
            .border_1()
            .border_color(c.border)
            .rounded(t.radius.md)
            .bg(c.surface)
            .p(t.space.xs)
            .children(rows);

        // 发送栏。
        let send_row = div()
            .flex()
            .items_end()
            .gap(t.space.sm)
            .child(div().flex_1().min_w(px(0.0)).child(self.ws_rep_send.clone()))
            .child(
                Button::new("ws-send", if zh { "发送" } else { "Send" })
                    .on_click(cx.listener(|this, _e, _w, cx| this.ws_send(cx))),
            );

        div()
            .flex_1()
            .flex()
            .flex_col()
            .min_h(px(0.0))
            .gap(t.space.md)
            .p(t.space.lg)
            .child(title)
            .child(bar)
            .child(status_row)
            .child(stream)
            .child(send_row)
    }
}
