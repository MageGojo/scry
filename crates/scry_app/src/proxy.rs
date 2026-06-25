//! Proxy 页:拦截开关 + 工具条(History / WebSocket / Options · 协议 chip · 清空)+ HTTP history
//! 表 + 选中流的请求 / 响应报文视图(Pretty / Raw / Hex / Render)。
//!
//! 复用 `mage_ui` 组件:[`Switch`](拦截)、[`Segmented`](History / 视图分段)、[`Chip`](协议过滤)、
//! [`InputState`](只读可选中 + 语法高亮的报文文本框)、[`Table`] / [`Badge`]。

use std::cell::RefCell;
use std::ops::Range;
use std::rc::Rc;

use mage_ui::gpui::{img, ClipboardItem, MouseButton, MouseDownEvent};
use mage_ui::prelude::*;
use scry_core::HttpFlow;
use scry_decode::body_text;

use crate::i18n::Lang;
use crate::model::{
    clock_hms, human_len, method_color, pseudo_ip, site_of, status_color, status_reason,
    type_label, MONO,
};
use crate::state::{CtxMenu, HistTab, MsgView, Proto, ScryApp, Tab};
use crate::widgets::{divider, tls_cell};

/// 代理详情文本框单次最多展示的字符数(超长 body 截断,避免巨型只读框卡顿;右键仍可复制可见内容)。
const MSG_TEXT_CAP: usize = 200_000;

/// 美化(Pretty)视图单次最多渲染的 body 行数(逐行建彩色元素,超出补「共 N 字节」尾注;
/// 要看 / 复制完整内容切「原始」视图)。
const MSG_MAX_LINES: usize = 5000;

impl ScryApp {
    /// Proxy 页主体。
    pub fn proxy_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let raw_query = self.search.read(cx).text().trim().to_string();
        let query = raw_query.to_ascii_lowercase();
        let proto = self.proto;
        let host_filter = self.host_filter.clone();
        let total = self.flows.len();
        // 搜索升级为 **HTTPQL**(对标 Caido):写成 `req.method.eq:"GET" AND resp.status.gt:400`
        // 这类带字段子句的查询 → 结构化逐字段匹配;纯文本 / 解析失败 → 回退快路径子串搜索。
        let httpql = if raw_query.is_empty() {
            None
        } else {
            scry_httpql::parse(&raw_query)
                .ok()
                .filter(|q| q.has_clauses())
        };
        // 可见行下标映射(过滤后)：虚拟化表只渲可见区间,这里只算一次 O(n) 下标表。
        // 性能关键:全文 / 子串走**按 body 指针缓存的可搜索文本**([`flow_search_text`]),
        // 解码(gzip/charset)只在每条流首次入索引时做一次 —— 不再「输入即卡死」。
        let mut visible: Vec<usize> = self
            .flows
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                if !proto.matches(f) {
                    return false;
                }
                if let Some(h) = host_filter.as_ref() {
                    if site_of(&f.host) != *h {
                        return false;
                    }
                }
                if raw_query.is_empty() {
                    return true;
                }
                match &httpql {
                    Some(q) => {
                        // 结构化字段(method/host/status… 廉价取自 flow);body 子句/全文走缓存 searchable。
                        let url = f.url();
                        let ext = path_ext(&f.path);
                        let req_h = join_headers(&f.req_headers);
                        let resp_h = join_headers(&f.resp_headers);
                        let search = flow_search_text(f);
                        let ff = scry_httpql::FlowFields {
                            method: &f.method,
                            host: &f.host,
                            path: &f.path,
                            url: &url,
                            ext,
                            port: f.port,
                            status: f.status,
                            req_len: f.req_body.len(),
                            resp_len: f.resp_body.len(),
                            mime: f.content_type().unwrap_or(""),
                            req_headers: &req_h,
                            resp_headers: &resp_h,
                            searchable: search.as_str(),
                        };
                        q.matches(&ff)
                    }
                    None => flow_search_text(f).contains(&query),
                }
            })
            .map(|(i, _)| i)
            .collect();
        // 按时间排序:最新在前(默认)或最早在前。
        if self.sort_newest {
            visible.sort_by(|&a, &b| self.flows[b].ts.cmp(&self.flows[a].ts));
        } else {
            visible.sort_by(|&a, &b| self.flows[a].ts.cmp(&self.flows[b].ts));
        }
        let shown = visible.len();

        // ── 工具条 ──
        let hist_idx = HistTab::ALL.iter().position(|h| *h == self.hist_tab).unwrap_or(0);
        let view = cx.entity();
        let hist_seg = Segmented::new("hist-seg")
            .items(HistTab::ALL.map(|h| self.lang.t(h.label())))
            .selected(hist_idx)
            .on_select(move |i, _e, _w, app| {
                view.update(app, |this, cx| {
                    this.hist_tab = HistTab::ALL[i];
                    cx.notify();
                });
            });

        let mut chips = Vec::new();
        for p in Proto::ALL {
            chips.push(
                Chip::new(SharedString::from(format!("proto-{}", p.label())), self.lang.t(p.label()))
                    .active(self.proto == p)
                    .on_click(cx.listener(move |this, _e, _w, cx| {
                        this.proto = p;
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }

        let toolbar = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.md)
            .flex_shrink_0()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.md)
                    .child(self.capture_button(cx))
                    .child(hist_seg),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .child(div().flex().items_center().gap(px(4.0)).children(chips))
                    .child(
                        Button::new(
                            "proxy-sort",
                            if self.sort_newest {
                                if self.lang.is_zh() { "最新" } else { "Newest" }
                            } else if self.lang.is_zh() {
                                "最早"
                            } else {
                                "Oldest"
                            },
                        )
                        .ghost()
                        .size(ButtonSize::Sm)
                        .icon(IconName::Sort)
                        .on_click(cx.listener(|this, _e, _w, cx| {
                            this.sort_newest = !this.sort_newest;
                            cx.notify();
                        })),
                    )
                    .child(
                        IconButton::new("proxy-refresh", IconName::Refresh)
                            .ghost()
                            .on_click(cx.listener(|this, _e, _w, cx| {
                                this.reload_flows();
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("proxy-clear", self.lang.t("Clear"))
                            .ghost()
                            .size(ButtonSize::Sm)
                            .icon(IconName::Trash)
                            .on_click(cx.listener(|this, _e, _w, cx| this.clear_flows(cx))),
                    ),
            );

        // ── 过滤行:搜索框 + 命中计数 ──
        let filter_row = div()
            .flex()
            .items_center()
            .gap(t.space.md)
            .flex_shrink_0()
            .child(Icon::new(IconName::Filter).size(px(15.0)).color(c.text_subtle))
            .child(div().flex_1().min_w(px(0.0)).child(self.search.clone()))
            .when(host_filter.is_some(), |row| {
                let site = SharedString::from(host_filter.clone().unwrap_or_default());
                row.child(
                    div()
                        .id("site-filter-pill")
                        .flex_shrink_0()
                        .flex()
                        .items_center()
                        .gap(px(4.0))
                        .px(px(8.0))
                        .py(px(2.0))
                        .rounded(t.radius.full)
                        .bg(c.glass)
                        .border_1()
                        .border_color(c.primary)
                        .cursor_pointer()
                        .hover(move |s| s.bg(c.surface_hover))
                        .child(Icon::new(IconName::Globe).size(px(11.0)).color(c.primary))
                        .child(div().text_size(t.font_size.xs).text_color(c.primary).child(site))
                        .child(Icon::new(IconName::Trash).size(px(11.0)).color(c.text_subtle))
                        .on_click(cx.listener(|this, _e, _w, cx| {
                            this.host_filter = None;
                            cx.notify();
                        })),
                )
            })
            .when(self.demo, |row| {
                // 演示数据角标:提示当前是内置样例,点「开始抓包」后会被真实流量替换。
                row.child(
                    div()
                        .flex_shrink_0()
                        .px(px(8.0))
                        .py(px(2.0))
                        .rounded(t.radius.full)
                        .bg(c.glass)
                        .border_1()
                        .border_color(c.warning)
                        .text_size(t.font_size.xs)
                        .text_color(c.warning)
                        .child(if self.lang.is_zh() {
                            "演示数据"
                        } else {
                            "DEMO"
                        }),
                )
            })
            .child(
                div()
                    .flex_shrink_0()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(if query.is_empty() {
                        if self.lang.is_zh() {
                            format!("{total} 条请求")
                        } else {
                            format!("{total} requests")
                        }
                    } else if self.lang.is_zh() {
                        format!("命中 {shown} / {total}")
                    } else {
                        format!("{shown} / {total} matched")
                    }),
            );

        // ── 历史表 ──
        let columns = vec![
            Column::fixed("#", px(46.0)).end(),
            Column::fixed(self.lang.t("Method"), px(74.0)),
            Column::flex(self.lang.t("URL"), 1.0),
            Column::fixed(self.lang.t("Status"), px(68.0)).center(),
            Column::fixed(self.lang.t("Size"), px(84.0)).end(),
            Column::fixed(self.lang.t("Time"), px(78.0)),
            Column::fixed(self.lang.t("IP"), px(116.0)),
            Column::fixed(self.lang.t("TLS"), px(58.0)),
            Column::fixed(self.lang.t("Type"), px(60.0)),
        ];
        let selected = self.selected;
        let count = visible.len();
        // 虚拟化历史表:`uniform_list` 只为视口内 ~20 行调用 build,1 万行滚动开销恒定。
        // `visible` 下标表 move 进 build 闭包;行元素经 `cx.processor` 惰性构建(读 `this.flows` + 挂行点击)。
        let table = Table::virtualized(
            columns,
            count,
            cx.processor(move |this, range: Range<usize>, _w, cx| -> Vec<Row> {
                let c = cx.theme().colors;
                let t = cx.theme().tokens;
                range
                    .map(|list_ix| {
                        let i = visible[list_ix];
                        let f = &this.flows[i];
                        let status = if f.status == 0 {
                            "—".to_string()
                        } else {
                            f.status.to_string()
                        };
                        // 行标记底色(分析用):按该流指纹查 marks → 主题色淡底。
                        let mark_bg = this
                            .marks
                            .get(&f.fingerprint())
                            .map(|m| mark_color(*m, c).opacity(0.20));
                        let mut row = Row::new().selected(this.selected == Some(i));
                        if let Some(b) = mark_bg {
                            row = row.bg(b);
                        }
                        row.on_select(cx.listener(move |this, _e, _w, cx| {
                                this.selected = Some(i);
                                cx.notify();
                            }))
                            .on_secondary(cx.listener(move |this, e: &MouseDownEvent, _w, cx| {
                                // 右键:选中该行并在光标处弹上下文菜单(发送到重放 / 复制为各语言)。
                                this.selected = Some(i);
                                this.ctx_menu = Some(CtxMenu {
                                    flow: i,
                                    x: e.position.x,
                                    y: e.position.y,
                                    sub: None,
                                    subsub: None,
                                });
                                cx.notify();
                            }))
                            .text(format!("{}", i + 1))
                            .cell(Badge::new(f.method.clone(), method_color(&f.method, c)))
                            .text(f.url())
                            .cell(Badge::new(status, status_color(f.status, c)))
                            .text(human_len(f.resp_len()))
                            .text(clock_hms(f.ts))
                            .muted(pseudo_ip(&f.host))
                            .cell(tls_cell(f.scheme == "https", c, t))
                            .muted(type_label(f))
                    })
                    .collect()
            }),
        )
        .selection(SelectionMode::Single)
        .row_height(px(34.0))
        .fill()
        .scroll_handle(self.hist_scroll.clone())
        .footer_note(match selected {
            Some(i) if self.lang.is_zh() => format!("已选 #{} · 显示 {}/{}", i + 1, shown, total),
            Some(i) => format!("Selected #{} · showing {} of {}", i + 1, shown, total),
            None if self.lang.is_zh() => format!("显示 {shown}/{total} · 点击一行查看"),
            None => format!("Showing {shown} of {total} · click a row to inspect"),
        });

        // ── 报文区(请求 / 响应)──
        let messages = div()
            .flex()
            .gap(t.space.md)
            .h(px(250.0))
            .flex_shrink_0()
            .child(self.message_panel(true, cx))
            .child(self.message_panel(false, cx));

        // 抓包状态 / 错误条:把 start_capture / BPF 授权的结果直接显在 Proxy 页(不必翻到设置页)。
        let cap_msg = self.cert_msg.clone();

        let mut root = div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .gap(t.space.md)
            .p(t.space.lg)
            .child(toolbar)
            .child(filter_row);
        // 拦截状态提示条:开启拦截时显示「正在拦截哪些链接」+ 待处理 + 一键关闭
        //(解决「右键拦截后不知道拦的是哪个」)。
        if let Some(banner) = self.intercept_banner(cx) {
            root = root.child(banner);
        }
        if let Some(msg) = cap_msg {
            let ok = !(msg.contains("失败")
                || msg.contains("取消")
                || msg.contains("打不开")
                || msg.contains("占用")
                || msg.contains("需要"));
            root = root.child(
                div()
                    .flex_shrink_0()
                    .px(t.space.md)
                    .py(t.space.sm)
                    .rounded(t.radius.md)
                    .bg(c.glass)
                    .border_1()
                    .border_color(if ok { c.success } else { c.warning })
                    .text_size(t.font_size.xs)
                    .text_color(if ok { c.success } else { c.warning })
                    .child(msg),
            );
        }
        match self.hist_tab {
            HistTab::WebSocket => root.child(self.ws_panel(cx)),
            HistTab::SiteMap => root.child(self.sitemap_panel(cx)),
            HistTab::Intercept => root.child(self.intercept_panel(cx)),
            HistTab::Options => root.child(self.options_panel(cx)),
            HistTab::History => root.child(table).child(messages),
        }
    }

    /// 拦截状态提示条:仅在「拦截请求 / 响应」任一开关开启时显示。
    ///
    /// 对标 Burp 顶部的 Intercept 状态——把「正在拦哪些链接」直接显在代理页:
    /// - 方向徽标(请求 / 响应);
    /// - 范围摘要(`仅拦截 host1, host2 (+N)` 或 `全部流量`,读 [`Self::intercept_scope_summary`]);
    /// - 待处理计数(点击跳到「拦截」队列页);
    /// - 「关闭拦截」按钮(一键关掉,见 [`Self::intercept_off`])。
    fn intercept_banner(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let (req_on, resp_on) = self.ext.intercept_flags();
        if !req_on && !resp_on {
            return None;
        }
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let zh = self.lang.is_zh();
        let (includes, has_exclude) = self.intercept_scope_summary();
        let pending = self.intercept_queue.len();

        let dir_txt = if req_on && resp_on {
            if zh { "请求 + 响应" } else { "Requests + Responses" }
        } else if req_on {
            if zh { "请求" } else { "Requests" }
        } else if zh {
            "响应"
        } else {
            "Responses"
        };

        // 范围摘要文本:列出最多 3 个被拦主机,多余折叠为 +N;无 include = 拦全部。
        let mut scope_txt = if includes.is_empty() {
            if zh { "全部流量".to_string() } else { "All traffic".to_string() }
        } else {
            let shown: Vec<String> = includes.iter().take(3).cloned().collect();
            let extra = includes.len() - shown.len();
            let base = if zh {
                format!("仅拦截 {}", shown.join(", "))
            } else {
                format!("Intercepting only {}", shown.join(", "))
            };
            if extra > 0 {
                format!("{base} +{extra}")
            } else {
                base
            }
        };
        if has_exclude {
            scope_txt.push_str(if zh { " · 含排除规则" } else { " · with excludes" });
        }

        let left = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .min_w(px(0.0))
            .child(StatusDot::new(c.warning).size(px(7.0)))
            .child(
                div()
                    .flex_shrink_0()
                    .text_size(t.font_size.sm)
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(c.warning)
                    .child(if zh { "拦截已开启" } else { "Intercept on" }),
            )
            .child(Badge::new(dir_txt, c.text_muted))
            .child(
                div()
                    .min_w(px(0.0))
                    .truncate()
                    .font_family(MONO)
                    .text_size(t.font_size.xs)
                    .text_color(c.text_muted)
                    .child(scope_txt),
            );

        let mut right = div().flex().items_center().gap(t.space.sm).flex_shrink_0();
        if pending > 0 {
            let pending_txt =
                if zh { format!("{pending} 待处理") } else { format!("{pending} pending") };
            right = right.child(
                div()
                    .id("ic-banner-pending")
                    .flex()
                    .items_center()
                    .gap(px(4.0))
                    .px(px(8.0))
                    .py(px(2.0))
                    .rounded(t.radius.full)
                    .bg(c.glass)
                    .border_1()
                    .border_color(c.warning)
                    .text_size(t.font_size.xs)
                    .text_color(c.warning)
                    .cursor_pointer()
                    .hover(move |s| s.bg(c.surface_hover))
                    .child(pending_txt)
                    .on_click(cx.listener(|this, _e, _w, cx| {
                        this.hist_tab = HistTab::Intercept; // 跳到队列查看 / 编辑
                        cx.notify();
                    })),
            );
        }
        right = right.child(
            Button::new("ic-banner-off", self.lang.t("Turn off intercept"))
                .ghost()
                .size(ButtonSize::Sm)
                .icon(IconName::Power)
                .on_click(cx.listener(|this, _e, _w, cx| this.intercept_off(cx))),
        );

        Some(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap(t.space.md)
                .flex_shrink_0()
                .px(t.space.md)
                .py(t.space.sm)
                .rounded(t.radius.md)
                .bg(c.glass)
                .border_1()
                .border_color(c.warning)
                .child(left)
                .child(right)
                .into_any_element(),
        )
    }

    /// 抓包开关按钮(启动 / 停止代理)。
    fn capture_button(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let cap = self.capturing;
        Button::new(
            "proxy-capture",
            self.lang.t(if cap { "Stop capture" } else { "Start capture" }),
        )
        .variant(if cap {
            ButtonVariant::Danger
        } else {
            ButtonVariant::Primary
        })
        .size(ButtonSize::Sm)
        .icon(IconName::Zap)
        .on_click(cx.listener(|this, _e, _w, cx| this.toggle_capture(cx)))
    }

    /// WebSocket tab:升级连接的双向帧消息列表(▲ 客户端发 / ▼ 服务端发)+ 选中消息的完整 payload。
    fn ws_panel(&self, cx: &mut Context<Self>) -> AnyElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let zh = self.lang.is_zh();
        let total = self.ws_msgs.len();

        if total == 0 {
            return div()
                .flex_1()
                .min_h(px(0.0))
                .flex()
                .items_center()
                .justify_center()
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .items_center()
                        .gap(t.space.sm)
                        .child(Icon::new(IconName::Globe).size(px(28.0)).color(c.text_subtle))
                        .child(
                            div()
                                .max_w(px(420.0))
                                .text_size(t.font_size.sm)
                                .text_color(c.text_subtle)
                                .child(if zh {
                                    "暂无 WebSocket 消息 · 用内置浏览器抓一个 wss 站点(在线聊天 / 行情推送等)即可在此看到双向帧"
                                } else {
                                    "No WebSocket messages yet · capture a wss site to see live frames here"
                                }),
                        ),
                )
                .into_any_element();
        }

        let columns = vec![
            Column::fixed("#", px(46.0)).end(),
            Column::fixed(if zh { "方向" } else { "Dir" }, px(56.0)).center(),
            Column::fixed(if zh { "类型" } else { "Opcode" }, px(96.0)),
            Column::flex("URL", 1.0),
            Column::fixed(if zh { "大小" } else { "Size" }, px(80.0)).end(),
            Column::fixed(if zh { "时间" } else { "Time" }, px(78.0)),
            Column::flex(if zh { "内容预览" } else { "Preview" }, 1.6),
        ];
        let count = total;
        let table = Table::virtualized(
            columns,
            count,
            cx.processor(move |this, range: Range<usize>, _w, cx| -> Vec<Row> {
                let c = cx.theme().colors;
                range
                    .map(|i| {
                        let m = &this.ws_msgs[i];
                        let (arrow, color) = match m.direction {
                            scry_core::WsDirection::ClientToServer => ("\u{25b2}", c.primary),
                            scry_core::WsDirection::ServerToClient => ("\u{25bc}", c.success),
                        };
                        Row::new()
                            .selected(this.ws_selected == Some(i))
                            .on_select(cx.listener(move |this, _e, _w, cx| {
                                this.ws_selected = Some(i);
                                cx.notify();
                            }))
                            .text(format!("{}", i + 1))
                            .cell(Badge::new(arrow, color))
                            .text(m.opcode.clone())
                            .text(format!("{}{}", m.host, m.path))
                            .text(human_len(m.payload.len()))
                            .text(clock_hms(m.ts))
                            .muted(ws_preview(&m.payload))
                    })
                    .collect()
            }),
        )
        .selection(SelectionMode::Single)
        .row_height(px(34.0))
        .fill()
        .scroll_handle(self.ws_scroll.clone())
        .footer_note(if zh {
            format!("{total} 条消息 · 点击查看完整内容")
        } else {
            format!("{total} messages · click a row to view payload")
        });

        // 选中消息的完整 payload(UTF-8 lossy 文本;超长截断展示,原始完整字节已落盘)。
        let detail = self.ws_selected.and_then(|i| self.ws_msgs.get(i)).map(|m| {
            let text = String::from_utf8_lossy(&m.payload);
            let shown: String = text.chars().take(20000).collect();
            div()
                .h(px(200.0))
                .flex_shrink_0()
                .flex()
                .flex_col()
                .gap(t.space.sm)
                .child(
                    div()
                        .flex_shrink_0()
                        .text_size(t.font_size.xs)
                        .text_color(c.text_muted)
                        .child(format!(
                            "{}  ·  {} {}",
                            m.opcode,
                            if zh { "字节" } else { "bytes" },
                            m.payload.len()
                        )),
                )
                .child(
                    div()
                        .flex_1()
                        .min_h(px(0.0))
                        .overflow_hidden()
                        .p(t.space.sm)
                        .rounded(t.radius.md)
                        .bg(c.glass)
                        .text_size(t.font_size.xs)
                        .text_color(c.text_muted)
                        .child(shown),
                )
        });

        div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .gap(t.space.md)
            .child(table)
            .children(detail)
            .into_any_element()
    }

    /// 单个报文面板(请求 / 响应),含 Pretty/Raw/Hex/Render 视图切换。
    fn message_panel(&self, is_req: bool, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let view_mode = if is_req { self.req_view } else { self.resp_view };
        let title = if is_req { "Request" } else { "Response" };
        let dot = if is_req { c.accent } else { c.primary };

        // 视图分段:请求面板只「美化 / 原始」,响应面板「美化 / 原始 / 十六进制 / 渲染」。
        let views = MsgView::for_panel(is_req);
        let mv_idx = views.iter().position(|m| *m == view_mode).unwrap_or(0);
        let view = cx.entity();
        let seg = Segmented::new(if is_req { "req-view" } else { "resp-view" })
            .items(views.iter().map(|m| self.lang.t(m.label())).collect::<Vec<_>>())
            .selected(mv_idx)
            .on_select(move |i, _e, _w, app| {
                view.update(app, |this, cx| {
                    let v = MsgView::for_panel(is_req)[i];
                    if is_req {
                        this.req_view = v;
                    } else {
                        this.resp_view = v;
                    }
                    cx.notify();
                });
            });

        let header_title = div()
            .flex()
            .items_center()
            .gap(px(7.0))
            .child(StatusDot::new(dot).size(px(7.0)))
            .child(
                div()
                    .text_size(t.font_size.sm)
                    .text_color(c.text)
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(self.lang.t(title)),
            );

        let mut controls = div().flex().items_center().gap(t.space.sm).child(seg);
        if is_req {
            controls = controls.child(
                Button::new("send-to-repeater", self.lang.t("Send"))
                    .ghost()
                    .size(ButtonSize::Sm)
                    .icon(IconName::Refresh)
                    .on_click(cx.listener(|this, _e, _w, cx| {
                        if let Some(flow) = this.current_flow().cloned() {
                            this.fill_repeater_from_flow(&flow, cx);
                            this.tab = Tab::Repeater;
                            cx.notify();
                        }
                    })),
            );
        }
        // 「复制」按钮:仅在可选中的视图(原始 / 十六进制 / 渲染)显示。
        // 美化视图是纯展示(只读高亮、不可选),不提供复制——要复制就切到「原始」。
        if view_mode != MsgView::Pretty {
            controls = controls.child(
                Button::new(
                    if is_req { "copy-req-msg" } else { "copy-resp-msg" },
                    self.lang.t("Copy"),
                )
                .ghost()
                .size(ButtonSize::Sm)
                .icon(IconName::Copy)
                .on_click(cx.listener(move |this, _e, _w, cx| this.copy_message(is_req, cx))),
            );
        }

        let header = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.sm)
            .flex_shrink_0()
            .child(header_title)
            .child(controls);

        // 详情正文:**美化 / 原始严格分开**(对标 Burp,职责不混):
        // - 美化(Pretty)= 只读彩色 [`CodeView`](等宽 Menlo + xs,对齐右侧检查器):JSON / 表单分词上色、
        //   首行方法/状态着色、头部键名分色——纯展示、不可选(不支持复制)。
        // - 原始 / 十六进制 / 渲染 = 只读可选中 [`InputState`](同样 Menlo + xs):选中 + Cmd/Ctrl+C /
        //   右键 / 顶部「复制」按钮在此可用。
        let body = if self.current_flow().is_none() {
            self.message_placeholder(self.lang.t("Select a row above to view the message"), cx)
        } else if view_mode == MsgView::Pretty {
            self.pretty_message_view(is_req, cx)
        } else if view_mode == MsgView::Render {
            self.render_preview(is_req, cx)
        } else {
            let input = if is_req { self.msg_req.clone() } else { self.msg_resp.clone() };
            div()
                .id(if is_req { "req-msg-scroll" } else { "resp-msg-scroll" })
                .flex_1()
                .min_h(px(0.0))
                .overflow_y_scroll()
                .on_mouse_down(
                    MouseButton::Right,
                    cx.listener(move |this, _e, _w, cx| this.copy_message(is_req, cx)),
                )
                .child(input)
                .into_any_element()
        };

        div()
            .flex_1()
            .min_w(px(0.0))
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .p(t.space.sm)
            .rounded(t.radius.lg)
            .bg(c.surface)
            .border_1()
            .border_color(c.border)
            .child(header)
            .child(divider(c))
            .child(body)
    }

    /// 美化(Pretty)视图主体:把请求 / 响应渲染成**只读彩色报文**(等宽 Menlo + xs,对齐右侧检查器)。
    ///
    /// 首行(方法 / 状态着色)+ 头部(键名按请求 `accent` / 响应 `primary`、值 `text_muted` 弱化)+ 空行 +
    /// body(按 content-type 走 JSON / 表单分词上色,见 [`crate::highlight::body_lines`])。
    /// 纯展示、**不可选中**——要选中 / 复制请切到「原始」视图。
    fn pretty_message_view(&self, is_req: bool, cx: &mut Context<Self>) -> AnyElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let lang = self.lang;
        let f = match self.current_flow() {
            Some(f) => f,
            None => {
                return self
                    .message_placeholder(self.lang.t("Select a row above to view the message"), cx)
            }
        };
        // 响应未到:与文本视图一致显示「等待响应…」。
        if !is_req && f.status == 0 {
            return self.message_placeholder(self.lang.t("Awaiting response…"), cx);
        }

        let headers = if is_req { &f.req_headers } else { &f.resp_headers };
        let body = if is_req { &f.req_body } else { &f.resp_body };
        let key_color = if is_req { c.accent } else { c.primary };

        // CodeView 默认即等宽 Menlo + xs 字号(与检查器一致),填满剩余高度;关掉行号 gutter
        // 以贴合右侧检查器那种「无行号」的干净观感(美化 vs 原始的区别靠 body 解码 + 是否可选中,而非行号)。
        let mut view = CodeView::new(if is_req { "req-pretty" } else { "resp-pretty" })
            .font_size(t.font_size.xs)
            .gutter(false)
            .fill();
        view = view.line(pretty_first_line(is_req, f, c));
        for (k, v) in headers {
            view = view.line(pretty_header_line(k, v, key_color, c));
        }
        view = view.line(div().child(" ")); // 头部与 body 间的空行
        if body.is_empty() {
            view = view.line(div().text_color(c.text_subtle).child(lang.t("(empty body)")));
        } else {
            view = view.lines(crate::highlight::body_lines(headers, body, MSG_MAX_LINES, lang, c));
        }
        view.into_any_element()
    }

    /// 渲染(Render)视图:对**响应**做可视化预览(请求面板无 Render,仅占位提示)。
    fn render_preview(&self, is_req: bool, cx: &mut Context<Self>) -> AnyElement {
        if is_req {
            return self
                .message_placeholder(self.lang.t("Render view applies to responses only."), cx);
        }
        self.response_preview(self.current_flow(), cx)
    }

    /// 响应「渲染」预览:位图 `image/*` 解码 + 落临时文件 + `img()` 直显;HTML/SVG/其它给说明。
    /// **Proxy / Repeater / Intruder 响应面板共用**(各传自己的响应流)。
    pub(crate) fn response_preview(
        &self,
        flow: Option<&HttpFlow>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let lang = self.lang;
        let f = match flow {
            Some(f) => f,
            None => {
                return self
                    .message_placeholder(lang.t("Select a row above to view the message"), cx)
            }
        };
        if f.status == 0 {
            return self.message_placeholder(lang.t("Awaiting response…"), cx);
        }
        let ct = f.content_type().unwrap_or("").to_ascii_lowercase();

        // 图片(位图)→ 解码 + 落临时文件 + img() 预览。SVG 是文本,走源码视图(Pretty/Raw)更合适。
        if ct.starts_with("image/") && !ct.contains("svg") {
            let raw = scry_decode::decode_body(&f.resp_headers, &f.resp_body);
            if raw.is_empty() {
                return self.message_placeholder(lang.t("(empty body)"), cx);
            }
            let dims = format!("{} · {} bytes", ct, raw.len());
            match write_preview_file(&raw, &ct) {
                Some(path) => {
                    return div()
                        .id("render-preview")
                        .flex_1()
                        .min_h(px(0.0))
                        .overflow_y_scroll()
                        .flex()
                        .flex_col()
                        .items_center()
                        .justify_center()
                        .gap(t.space.sm)
                        .p(t.space.md)
                        .child(img(path).max_w(px(760.0)).max_h(px(560.0)).rounded(t.radius.md))
                        .child(
                            div()
                                .text_size(t.font_size.xs)
                                .text_color(c.text_subtle)
                                .child(dims),
                        )
                        .into_any_element();
                }
                None => return self.message_placeholder(lang.t("Preview failed"), cx),
            }
        }

        let note = if ct.contains("html") {
            lang.t("HTML preview: switch to Pretty / Raw to read the source (full rendering needs a browser).")
        } else if ct.contains("svg") {
            lang.t("SVG is text — view it under Pretty / Raw.")
        } else {
            lang.t("No visual preview for this content type. Use Pretty / Raw / Hex.")
        };
        self.message_placeholder(note, cx)
    }

    /// 报文正文占位(无选中流 / 响应未到时居中显示)。
    fn message_placeholder(
        &self,
        text: impl Into<SharedString>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .items_center()
            .justify_center()
            .child(div().text_size(t.font_size.sm).text_color(c.text_subtle).child(text.into()))
            .into_any_element()
    }

    /// 把请求 / 响应**原始文本**(原始 / 十六进制 / 渲染视图)灌进只读可选中文本框;
    /// **美化视图另走 [`ScryApp::pretty_message_view`](彩色 CodeView),此处置空文本框**(不渲染、免做无用功)。
    /// 签名不变则跳过(免每帧重置选区)。由 `render`(代理页可见时)调用。
    pub fn sync_message_inputs(&mut self, cx: &mut Context<Self>) {
        let sel = self.selected.unwrap_or(usize::MAX);
        let req_view = self.req_view;
        let resp_view = self.resp_view;
        let c = cx.theme().colors;
        // 文本框只承载可选中视图(原始 / 十六进制 / 渲染):签名 = 选中行 + 视图 + body 长度 + 状态码;
        // 仅签名变化才重灌「文本 + 高亮区间」(免每帧重置选区)。
        let (req_sig, resp_sig) = match self.current_flow() {
            Some(f) => (
                Some((sel, req_view, f.req_body.len(), 0u16)),
                Some((sel, resp_view, f.resp_body.len(), f.status)),
            ),
            None => (None, None),
        };
        if req_sig != self.msg_req_sig {
            // 美化视图不经文本框 → 置空,避免给隐藏的输入框做解码 / 分词。
            let (text, hl) = if req_view == MsgView::Pretty {
                (String::new(), Vec::new())
            } else {
                self.current_flow()
                    .map(|f| {
                        let text = message_text(self.lang, true, f, req_view);
                        let hl = message_highlights(&text, true, f, req_view, c);
                        (text, hl)
                    })
                    .unwrap_or_default()
            };
            self.msg_req.update(cx, |s, cx| {
                s.set_text(text, cx);
                s.set_highlights(hl, cx);
            });
            self.msg_req_sig = req_sig;
        }
        if resp_sig != self.msg_resp_sig {
            let (text, hl) = if resp_view == MsgView::Pretty {
                (String::new(), Vec::new())
            } else {
                self.current_flow()
                    .map(|f| {
                        let text = message_text(self.lang, false, f, resp_view);
                        let hl = message_highlights(&text, false, f, resp_view, c);
                        (text, hl)
                    })
                    .unwrap_or_default()
            };
            self.msg_resp.update(cx, |s, cx| {
                s.set_text(text, cx);
                s.set_highlights(hl, cx);
            });
            self.msg_resp_sig = resp_sig;
        }
    }

    /// 右键复制报文(原始 / 十六进制视图):有选区复制选区,否则复制整段。
    pub fn copy_message(&mut self, is_req: bool, cx: &mut Context<Self>) {
        let input = if is_req { &self.msg_req } else { &self.msg_resp };
        let st = input.read(cx);
        let sel = st.selected_text();
        let text = if sel.is_empty() {
            st.text().to_string()
        } else {
            sel.to_string()
        };
        if text.is_empty() {
            return;
        }
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        let msg = self.lang.t("Copied to clipboard").to_string();
        self.show_toast(msg, cx);
    }
}

/// 美化视图首行:请求行 `METHOD path HTTP/1.1`(方法按方法色加粗、路径常规、版本弱化)/
/// 状态行 `HTTP/1.1 CODE REASON`(版本弱化、状态码 + 原因按状态色加粗)。
fn pretty_first_line(is_req: bool, f: &HttpFlow, c: ThemeColors) -> AnyElement {
    if is_req {
        div()
            .flex()
            .flex_row()
            .items_start()
            .child(
                div()
                    .flex_shrink_0()
                    .text_color(method_color(&f.method, c))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(f.method.clone()),
            )
            .child(div().flex_shrink_0().child(" "))
            .child(div().min_w(px(0.0)).text_color(c.text).child(f.path.clone()))
            .child(div().flex_shrink_0().child(" "))
            .child(div().flex_shrink_0().text_color(c.text_subtle).child("HTTP/1.1"))
            .into_any_element()
    } else {
        div()
            .flex()
            .flex_row()
            .items_start()
            .child(div().flex_shrink_0().text_color(c.text_subtle).child("HTTP/1.1"))
            .child(div().flex_shrink_0().child(" "))
            .child(
                div()
                    .flex_shrink_0()
                    .text_color(status_color(f.status, c))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(format!("{} {}", f.status, status_reason(f.status))),
            )
            .into_any_element()
    }
}

/// 美化视图头部行:`Key: Value`——键名按方向分色(请求 `accent` / 响应 `primary`),值 `text_muted` 弱化以突出键名。
fn pretty_header_line(k: &str, v: &str, key_color: Hsla, c: ThemeColors) -> AnyElement {
    div()
        .flex()
        .flex_row()
        .items_start()
        .gap(px(6.0))
        .child(div().flex_shrink_0().text_color(key_color).child(format!("{k}:")))
        .child(div().min_w(px(0.0)).text_color(c.text_muted).child(v.to_string()))
        .into_any_element()
}

/// 行标记颜色:序号(1..=5)→ 主题语义色(红 / 橙 / 绿 / 蓝 / 紫)。
fn mark_color(idx: usize, c: ThemeColors) -> Hsla {
    match idx {
        1 => c.danger,
        2 => c.warning,
        3 => c.success,
        4 => c.primary,
        _ => c.accent,
    }
}

/// 把图片字节落到 `~/.scry/preview/<sha1>.<ext>`(按内容哈希命名 → 同图复用 gpui 缓存),返回路径。
/// best-effort:写失败返回 `None`。
fn write_preview_file(bytes: &[u8], content_type: &str) -> Option<std::path::PathBuf> {
    let ext = match content_type {
        ct if ct.contains("png") => "png",
        ct if ct.contains("jpeg") || ct.contains("jpg") => "jpg",
        ct if ct.contains("gif") => "gif",
        ct if ct.contains("webp") => "webp",
        ct if ct.contains("bmp") => "bmp",
        ct if ct.contains("icon") || ct.contains("ico") => "ico",
        _ => "img",
    };
    let dir = scry_ca::default_ca_dir().join("preview");
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join(format!("{}.{ext}", scry_core::sha1_hex(bytes)));
    if !path.exists() {
        std::fs::write(&path, bytes).ok()?;
    }
    Some(path)
}

/// WebSocket payload 单行预览(截断 + 去换行 / 制表)。
fn ws_preview(payload: &[u8]) -> String {
    let n = payload.len().min(160);
    let s = String::from_utf8_lossy(&payload[..n]);
    let one: String = s
        .chars()
        .map(|ch| {
            if ch == '\n' || ch == '\r' || ch == '\t' {
                ' '
            } else {
                ch
            }
        })
        .collect();
    if payload.len() > n {
        format!("{one}\u{2026}")
    } else {
        one
    }
}

/// 把一条流的请求 / 响应按视图渲染成**纯文本**(供只读可选中文本框)。
/// Pretty = 解码 + 美化(JSON 缩进 / gzip 解压 / charset);Raw = 原始字节;Hex = hexdump。
/// `pub(crate)`:Repeater / Intruder 的响应查看器复用同一条渲染路径(改一处全得益)。
pub(crate) fn message_text(lang: Lang, is_req: bool, f: &HttpFlow, view: MsgView) -> String {
    let headers = if is_req { &f.req_headers } else { &f.resp_headers };
    let body = if is_req { &f.req_body } else { &f.resp_body };
    if !is_req && f.status == 0 {
        return lang.t("Awaiting response…").to_string();
    }
    match view {
        // Render 视图由 `response_preview`(图片预览)处理,不走文本路径 → 文本框置空。
        MsgView::Render => String::new(),
        MsgView::Hex => cap_text(&hexdump(body, 8192, lang).join("\n"), body.len(), lang),
        MsgView::Raw | MsgView::Pretty => {
            let first = if is_req {
                format!("{} {} HTTP/1.1", f.method, f.path)
            } else {
                format!("HTTP/1.1 {} {}", f.status, status_reason(f.status))
            };
            let mut s = String::with_capacity(256);
            s.push_str(&first);
            s.push('\n');
            for (k, v) in headers {
                s.push_str(k);
                s.push_str(": ");
                s.push_str(v);
                s.push('\n');
            }
            s.push('\n');
            let body_str = if body.is_empty() {
                String::new()
            } else if matches!(view, MsgView::Pretty) {
                scry_decode::display_pretty_json(headers, body)
                    .unwrap_or_else(|| body_text(headers, body))
            } else {
                String::from_utf8_lossy(body).into_owned()
            };
            s.push_str(&body_str);
            cap_text(&s, body.len(), lang)
        }
    }
}

/// 为只读报文文本框计算**语法高亮区间**(字节范围 → 颜色),与 [`message_text`] 的产出严格对齐。
///
/// - **首行**:请求行的方法按方法色 / 响应行的状态码 + 原因按状态色,协议版本弱化;
/// - **头部** `Key: Value`:键名按请求(`accent`)/ 响应(`primary`)分色,值弱化以突出键名;
/// - **Pretty body**:按 `content-type` 选 JSON / 表单分词着色;
/// - **Raw**:仅首行 + 头部键值(body 不分词,保持原始观感);
/// - **Hex / Render**:不高亮。
///
/// 分词结果按字节顺序拼回整行,故逐 token 累加偏移即得准确字节范围。
/// `pub(crate)`:Repeater / Intruder 响应查看器与代理共用,保证多色与可选中文本严格对齐。
pub(crate) fn message_highlights(
    text: &str,
    is_req: bool,
    f: &HttpFlow,
    view: MsgView,
    c: ThemeColors,
) -> Vec<(Range<usize>, Hsla)> {
    if matches!(view, MsgView::Hex | MsgView::Render) {
        return Vec::new();
    }
    let headers = if is_req { &f.req_headers } else { &f.resp_headers };
    let key_color = if is_req { c.accent } else { c.primary };
    // body 是否为表单(x-www-form-urlencoded)→ 选表单分词器,否则按 JSON。
    let is_form = scry_decode::header_get(headers, "content-type")
        .map(|ct| ct.to_ascii_lowercase().contains("x-www-form-urlencoded"))
        .unwrap_or(false);

    let mut out: Vec<(Range<usize>, Hsla)> = Vec::new();
    let mut byte = 0usize;
    let mut in_body = false;
    for (li, line) in text.split('\n').enumerate() {
        let ls = byte;
        if li == 0 {
            // 首行:请求行(方法色)/ 状态行(状态色),协议版本弱化。
            first_line_highlights(line, ls, is_req, f, c, &mut out);
        } else if !in_body {
            if line.is_empty() {
                in_body = true; // 空行分隔头部与 body
            } else if let Some(colon) = line.find(':') {
                if colon > 0 {
                    out.push((ls..ls + colon, key_color)); // 键名
                    // 值(冒号 + 空白之后到行尾)弱化,让键名更突出。
                    if let Some(off) = line[colon + 1..].find(|ch: char| !ch.is_whitespace()) {
                        out.push((ls + colon + 1 + off..ls + line.len(), c.text_muted));
                    }
                }
            }
        } else if matches!(view, MsgView::Pretty) {
            let mut loff = ls;
            let toks = if is_form {
                crate::highlight::tokenize_form_line(line)
            } else {
                crate::highlight::tokenize_json_line(line)
            };
            for (txt, tok) in toks {
                let len = txt.len();
                if !matches!(tok, crate::highlight::Tok::Plain) {
                    out.push((loff..loff + len, crate::highlight::token_color(tok, c)));
                }
                loff += len;
            }
        }
        byte += line.len() + 1; // +1 = 换行符
    }
    out
}

/// 首行高亮(`base` = 该行起始字节偏移):
/// - 请求行 `METHOD path HTTP/x` → 方法按方法色,末尾 `HTTP/x` 版本弱化;
/// - 状态行 `HTTP/x CODE REASON` → 版本弱化,其后状态码 + 原因按状态色。
fn first_line_highlights(
    line: &str,
    base: usize,
    is_req: bool,
    f: &HttpFlow,
    c: ThemeColors,
    out: &mut Vec<(Range<usize>, Hsla)>,
) {
    if line.is_empty() {
        return;
    }
    if is_req {
        let m_end = line.find(' ').unwrap_or(line.len());
        out.push((base..base + m_end, method_color(&f.method, c)));
        if let Some(vpos) = line.rfind(" HTTP/") {
            out.push((base + vpos + 1..base + line.len(), c.text_subtle));
        }
    } else if let Some(sp) = line.find(' ') {
        out.push((base..base + sp, c.text_subtle));
        out.push((base + sp + 1..base + line.len(), status_color(f.status, c)));
    } else {
        out.push((base..base + line.len(), c.text_subtle));
    }
}

/// 文本超过 [`MSG_TEXT_CAP`] 字符时截断并加尾注(只影响展示;原始字节仍在库里)。
fn cap_text(text: &str, raw_len: usize, lang: Lang) -> String {
    let mut out: String = text.chars().take(MSG_TEXT_CAP).collect();
    if out.len() < text.len() {
        if lang.is_zh() {
            out.push_str(&format!("\n… (已截断,共 {raw_len} 字节)"));
        } else {
            out.push_str(&format!("\n… (truncated, {raw_len} bytes total)"));
        }
    }
    out
}

// ── 全文搜索索引(性能关键)─────────────────────────────────────────────
// 过滤框输入时,若每次键击都对所有流的 body 做 gzip/charset 解码,几百 KB × N 条 → 直接卡死。
// 这里按 (req/resp body 堆指针 + 长度) 缓存「小写化 + body 截断」的可搜索文本,**解码只做一次**;
// `Vec<u8>` 堆指针在父 Vec 移动时稳定,故缓存跨帧、跨键击持续命中,键击只剩廉价子串匹配。
/// 搜索索引缓存条目:`(req_ptr, req_len, resp_ptr, resp_len) → 可搜索文本`。
type SearchEntry = ((usize, usize, usize, usize), Rc<String>);
thread_local! {
    static SEARCH_CACHE: RefCell<Vec<SearchEntry>> = const { RefCell::new(Vec::new()) };
}
const SEARCH_CACHE_CAP: usize = 2048;
/// 每个 body 进搜索索引的解码字符上限(够搜 URL / 参数 / JSON 头部,避免给大响应建超大索引)。
const SEARCH_BODY_CHARS: usize = 8192;

/// 取路径的扩展名(`/a/b.js?x=1` → `js`;无则空)。供 HTTPQL `req.ext` 字段用。
fn path_ext(path: &str) -> &str {
    let p = path.split(['?', '#']).next().unwrap_or(path);
    let seg = p.rsplit('/').next().unwrap_or(p);
    match seg.rsplit_once('.') {
        Some((name, ext)) if !name.is_empty() && !ext.is_empty() => ext,
        _ => "",
    }
}

/// 把头表拼成 `Key: Value\n` 文本(供 HTTPQL `req.headers` / `resp.headers` 字段匹配)。
fn join_headers(headers: &[(String, String)]) -> String {
    let mut s = String::new();
    for (k, v) in headers {
        s.push_str(k);
        s.push_str(": ");
        s.push_str(v);
        s.push('\n');
    }
    s
}

/// 取(或构建并缓存)一条流的小写可搜索文本:url + 头 + 解码后的 req/resp body(截断)。
fn flow_search_text(f: &HttpFlow) -> Rc<String> {
    let key = (
        f.req_body.as_ptr() as usize,
        f.req_body.len(),
        f.resp_body.as_ptr() as usize,
        f.resp_body.len(),
    );
    if let Some(hit) =
        SEARCH_CACHE.with(|c| c.borrow().iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone()))
    {
        return hit;
    }
    let mut s = f.url().to_ascii_lowercase();
    s.push('\n');
    for (k, v) in f.req_headers.iter().chain(f.resp_headers.iter()) {
        s.push_str(&k.to_ascii_lowercase());
        s.push(' ');
        s.push_str(&v.to_ascii_lowercase());
        s.push('\n');
    }
    for (headers, body) in [(&f.req_headers, &f.req_body), (&f.resp_headers, &f.resp_body)] {
        if body.is_empty() {
            continue;
        }
        let txt: String = body_text(headers, body)
            .to_ascii_lowercase()
            .chars()
            .take(SEARCH_BODY_CHARS)
            .collect();
        s.push_str(&txt);
        s.push('\n');
    }
    let rc = Rc::new(s);
    SEARCH_CACHE.with(|c| {
        let mut c = c.borrow_mut();
        c.push((key, rc.clone()));
        if c.len() > SEARCH_CACHE_CAP {
            let drop = c.len() - SEARCH_CACHE_CAP;
            c.drain(0..drop);
        }
    });
    rc
}

// ── hexdump(Hex 视图;message_text 用)────────────────────────────────

/// 经典 hexdump:`offset  hex×16  ascii`。
fn hexdump(bytes: &[u8], max_lines: usize, lang: Lang) -> Vec<String> {
    if bytes.is_empty() {
        return vec![lang.t("(empty body)").to_string()];
    }
    let mut lines = Vec::new();
    for (i, chunk) in bytes.chunks(16).enumerate().take(max_lines) {
        let off = i * 16;
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let hexpart = hex.join(" ");
        let ascii: String = chunk
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        lines.push(format!("{off:08x}  {hexpart:<47}  {ascii}"));
    }
    if bytes.len() > max_lines * 16 {
        lines.push(if lang.is_zh() {
            format!("… (共 {} 字节)", bytes.len())
        } else {
            format!("… ({} bytes total)", bytes.len())
        });
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一条 POST + JSON 响应的样例流。
    fn json_flow() -> HttpFlow {
        HttpFlow::request(
            "POST",
            "https",
            "api.example.com",
            443,
            "/v1/login",
            vec![("Host".to_string(), "api.example.com".to_string())],
            br#"{"user":"admin"}"#.to_vec(),
        )
        .with_response(
            200,
            vec![("Content-Type".to_string(), "application/json".to_string())],
            br#"{"ok":true}"#.to_vec(),
            12,
        )
    }

    /// 高亮区间必须全部落在文本字节内且 start ≤ end(字节对齐的硬约束)。
    fn ranges_in_bounds(text: &str, hl: &[(Range<usize>, Hsla)]) -> bool {
        hl.iter()
            .all(|(r, _)| r.start <= r.end && r.end <= text.len() && text.is_char_boundary(r.start) && text.is_char_boundary(r.end))
    }

    #[test]
    fn request_method_and_header_key_aligned() {
        let c = ThemeColors::dark();
        let f = json_flow();
        let text = message_text(Lang::En, true, &f, MsgView::Pretty);
        let hl = message_highlights(&text, true, &f, MsgView::Pretty, c);
        assert!(ranges_in_bounds(&text, &hl));
        // 首行方法 "POST" 按方法色(POST = accent)。
        assert!(hl
            .iter()
            .any(|(r, col)| &text[r.clone()] == "POST" && *col == method_color("POST", c)));
        // 请求头键名 "Host" 按请求键色(accent)。
        assert!(hl.iter().any(|(r, col)| &text[r.clone()] == "Host" && *col == c.accent));
    }

    #[test]
    fn response_status_colored_by_code() {
        let c = ThemeColors::dark();
        let f = json_flow();
        let text = message_text(Lang::En, false, &f, MsgView::Pretty);
        let hl = message_highlights(&text, false, &f, MsgView::Pretty, c);
        assert!(ranges_in_bounds(&text, &hl));
        // 状态码 + 原因 "200 OK" 按状态色(2xx = success)。
        assert!(hl
            .iter()
            .any(|(r, col)| &text[r.clone()] == "200 OK" && *col == status_color(200, c)));
    }

    #[test]
    fn form_body_uses_form_tokenizer() {
        let c = ThemeColors::dark();
        let f = HttpFlow::request(
            "POST",
            "https",
            "ex.com",
            443,
            "/login",
            vec![(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            )],
            b"user=admin&pw=123".to_vec(),
        );
        let text = message_text(Lang::En, true, &f, MsgView::Pretty);
        let hl = message_highlights(&text, true, &f, MsgView::Pretty, c);
        assert!(ranges_in_bounds(&text, &hl));
        // 表单键 "user" 走表单分词器,按 Key 色着色。
        let key_col = crate::highlight::token_color(crate::highlight::Tok::Key, c);
        assert!(hl
            .iter()
            .any(|(r, col)| &text[r.clone()] == "user" && *col == key_col));
    }

    #[test]
    fn hex_view_has_no_highlights() {
        let c = ThemeColors::dark();
        let f = json_flow();
        let text = message_text(Lang::En, false, &f, MsgView::Hex);
        let hl = message_highlights(&text, false, &f, MsgView::Hex, c);
        assert!(hl.is_empty());
    }
}
