//! Repeater 页:把选中流灌入可编辑报文 → 改包 → [`scry_proxy::replay`] 重发 → 右栏看响应。
//!
//! async 桥接:`replay::send` 是 tokio future,gpui 主线程不在 tokio 运行时里;丢到
//! `background_executor` 线程上建临时 current-thread runtime `block_on` 驱动(只阻塞该后台线程),
//! 完成后 `cx.spawn` 回主线程写回响应并重绘。

use std::hash::{Hash, Hasher};
use std::ops::Range;

use mage_ui::gpui::MouseButton;
use mage_ui::prelude::*;
use scry_core::HttpFlow;
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};

use crate::i18n::Lang;
use crate::model::{human_len, status_color, status_reason};
use crate::state::{MsgView, ScryApp};
use crate::widgets::divider;

impl ScryApp {
    /// 把 Repeater 响应同步进只读可选中高亮查看器(签名不变则跳过,免每帧重置选区)。
    /// 由 `render`(Repeater 页可见时)调用。
    pub fn sync_repeater_views(&mut self, cx: &mut Context<Self>) {
        let c = cx.theme().colors;
        let dark = cx.theme().mode.is_dark();
        let built = {
            let sig =
                resp_view_sig(dark, self.rp_resp_view, self.rp_resp.as_ref(), self.rp_err.as_deref());
            if sig == self.rp_resp_sig {
                None
            } else {
                Some((
                    sig,
                    build_resp_view(
                        self.lang,
                        self.rp_resp_view,
                        self.rp_resp.as_ref(),
                        self.rp_err.as_deref(),
                        c,
                    ),
                ))
            }
        };
        if let Some((sig, (text, hl))) = built {
            let input = self.rp_resp_input.clone();
            input.update(cx, |s, cx| {
                s.set_text(text, cx);
                s.set_highlights(hl, cx);
            });
            self.rp_resp_sig = sig;
        }
    }

    /// 把选中流灌进 Repeater 编辑区(目标栏 + 原始报文),清空上次响应。
    pub fn fill_repeater_from_flow(&mut self, flow: &HttpFlow, cx: &mut Context<Self>) {
        let target = target_string(flow);
        let raw = render_raw_request(flow);
        self.rp_target.update(cx, |s, cx| s.set_text(target, cx));
        self.rp_req.update(cx, |s, cx| s.set_text(raw, cx));
        self.rp_resp = None;
        self.rp_err = None;
    }

    /// 把 Repeater 当前**编辑中的请求**送进比较器 A(`to_a=true`)或 B。
    fn rp_request_to_comparer(&mut self, to_a: bool, cx: &mut Context<Self>) {
        let text = self.rp_req.read(cx).text().to_string();
        self.send_to_comparer(to_a, text, cx);
    }

    /// 把 Repeater **当前响应**送进比较器 A / B(无响应则忽略)。
    fn rp_response_to_comparer(&mut self, to_a: bool, cx: &mut Context<Self>) {
        if let Some(f) = self.rp_resp.clone() {
            self.send_to_comparer(to_a, render_raw_response(&f), cx);
        }
    }

    /// 发送 Repeater 请求:解析编辑区 → 后台 tokio 跑 [`replay::send`] → 回主线程刷新响应。
    pub fn send_repeater(&mut self, cx: &mut Context<Self>) {
        if self.rp_sending {
            return;
        }
        let target = self.rp_target.read(cx).text().to_string();
        let raw = self.rp_req.read(cx).text().to_string();
        let up = self.upstream_proxy(cx);
        let req = match parse_raw_request(&target, &raw) {
            Ok(r) => r,
            Err(e) => {
                let prefix = if self.lang.is_zh() {
                    "请求解析失败:"
                } else {
                    "Request parse failed: "
                };
                self.rp_err = Some(format!("{prefix}{e}"));
                self.rp_resp = None;
                cx.notify();
                return;
            }
        };

        self.rp_sending = true;
        self.rp_err = None;
        cx.notify();

        let task = cx.background_executor().spawn(async move {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => return Err(format!("创建运行时失败:{e}")),
            };
            rt.block_on(async move {
                let cfg = ReplayConfig {
                    upstream: up,
                    ..Default::default()
                };
                replay::send(&req, &cfg)
                    .await
                    .map_err(|e| format!("{e:#}"))
            })
        });

        cx.spawn(async move |this, cx| {
            let result = task.await;
            let _ = this.update(cx, |this, cx| {
                this.rp_sending = false;
                match result {
                    Ok(flow) => {
                        this.rp_resp = Some(flow);
                        this.rp_err = None;
                    }
                    Err(e) => {
                        this.rp_err = Some(e);
                        this.rp_resp = None;
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// Repeater 页主体。
    pub fn repeater_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let (status_text, status_col) = if self.rp_sending {
            (self.lang.t("Sending…").to_string(), c.warning)
        } else if let Some(f) = &self.rp_resp {
            (
                format!("{} · {} · {} ms", f.status, human_len(f.resp_len()), f.duration_ms),
                status_color(f.status, c),
            )
        } else if self.rp_err.is_some() {
            (self.lang.t("Failed").to_string(), c.danger)
        } else {
            (self.lang.t("Ready").to_string(), c.text_subtle)
        };

        let toolbar = div()
            .flex()
            .items_center()
            .gap(t.space.md)
            .flex_shrink_0()
            .child(div().flex_1().min_w(px(0.0)).child(self.rp_target.clone()))
            .child(
                GlowButton::new(
                    "rp-send",
                    if self.rp_sending {
                        self.lang.t("Sending…")
                    } else {
                        format!("{}  ▶", self.lang.t("Send")).into()
                    },
                )
                .on_click(cx.listener(|this, _e, _w, cx| this.send_repeater(cx))),
            )
            .child(
                div()
                    .flex_shrink_0()
                    .flex()
                    .items_center()
                    .gap(px(7.0))
                    .px(t.space.md)
                    .py(px(6.0))
                    .rounded(t.radius.full)
                    .bg(c.glass)
                    .border_1()
                    .border_color(c.glass_border)
                    .child(StatusDot::new(status_col))
                    .child(
                        div()
                            .text_size(t.font_size.xs)
                            .text_color(c.text_muted)
                            .child(status_text),
                    ),
            );

        // 左:请求区(Pretty 只读高亮 / Raw 可编辑)。
        let rq_views = [MsgView::Pretty, MsgView::Raw];
        let rq_idx = rq_views.iter().position(|m| *m == self.rp_req_view).unwrap_or(0);
        let view_rq = cx.entity();
        let req_seg = Segmented::new("rp-req-view")
            .items(rq_views.map(|m| self.lang.t(m.label())))
            .selected(rq_idx)
            .on_select(move |i, _e, _w, app| {
                view_rq.update(app, |this, cx| {
                    this.rp_req_view = rq_views[i];
                    cx.notify();
                });
            });
        let req_hint = if self.rp_req_view == MsgView::Raw {
            "editable · request line + headers + blank + body"
        } else {
            "highlighted · switch to Raw to edit"
        };
        // 请求面板头右侧:「比较器 A/B」发送组 + Pretty/Raw 视图分段。
        let req_cmp = div()
            .flex()
            .items_center()
            .gap(px(4.0))
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("Comparer")),
            )
            .child(
                Button::new("rp-req-cmp-a", "A")
                    .ghost()
                    .size(ButtonSize::Sm)
                    .on_click(cx.listener(|this, _e, _w, cx| this.rp_request_to_comparer(true, cx))),
            )
            .child(
                Button::new("rp-req-cmp-b", "B")
                    .ghost()
                    .size(ButtonSize::Sm)
                    .on_click(cx.listener(|this, _e, _w, cx| this.rp_request_to_comparer(false, cx))),
            );
        let req_header = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.sm)
            .flex_shrink_0()
            .child(PanelTitle::new(self.lang.t("Request")).hint(self.lang.t(req_hint)))
            .child(div().flex().items_center().gap(t.space.sm).child(req_cmp).child(req_seg));

        let req_body = if self.rp_req_view == MsgView::Raw {
            div()
                .id("rp-req-scroll")
                .flex_1()
                .min_h(px(0.0))
                .overflow_y_scroll()
                .child(self.rp_req.clone())
                .into_any_element()
        } else {
            let raw = self.rp_req.read(cx).text().to_string();
            CodeView::new("rp-req-code")
                .lines(crate::highlight::request_lines(&raw, 400, self.lang, c))
                .fill()
                .into_any_element()
        };

        let req_panel = div()
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
            .child(req_header)
            .child(divider(c))
            .child(req_body);

        // 右:只读**可选中高亮**响应查看器(选中 + Cmd/Ctrl+C + 右键复制);文本/高亮由 sync_repeater_views 灌入。
        // 错误也走同一查看器(整段标红、可复制);皆无时显示占位。
        let resp_body = if self.rp_resp.is_none() && self.rp_err.is_none() {
            div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .child(
                    div()
                        .text_size(t.font_size.sm)
                        .text_color(c.text_subtle)
                        .child(self.lang.t("Edit the request on the left, then Send")),
                )
                .into_any_element()
        } else if self.rp_resp_view == MsgView::Render && self.rp_err.is_none() {
            // 渲染视图:图片直接预览(复用代理响应预览),非文本框。
            self.response_preview(self.rp_resp.as_ref(), cx)
        } else {
            div()
                .id("rp-resp-scroll")
                .flex_1()
                .min_h(px(0.0))
                .overflow_y_scroll()
                .on_mouse_down(
                    MouseButton::Right,
                    cx.listener(|this, _e, _w, cx| {
                        let inp = this.rp_resp_input.clone();
                        this.copy_from_input(inp, cx);
                    }),
                )
                .child(self.rp_resp_input.clone())
                .into_any_element()
        };

        // 响应区视图切换(Pretty 高亮 / Raw / Hex);有响应时才显示。
        let has_resp = self.rp_resp.is_some() && self.rp_err.is_none();
        let rp_views = [MsgView::Pretty, MsgView::Raw, MsgView::Hex, MsgView::Render];
        let rv_idx = rp_views
            .iter()
            .position(|m| *m == self.rp_resp_view)
            .unwrap_or(0);
        let view = cx.entity();
        let resp_seg = Segmented::new("rp-resp-view")
            .items(rp_views.map(|m| self.lang.t(m.label())))
            .selected(rv_idx)
            .on_select(move |i, _e, _w, app| {
                view.update(app, |this, cx| {
                    this.rp_resp_view = rp_views[i];
                    cx.notify();
                });
            });

        let resp_hint = if self.rp_err.is_some() {
            "failed"
        } else {
            "read-only"
        };
        // 响应面板头右侧(有响应时):「比较器 A/B」发送组 + Pretty/Raw/Hex 视图分段。
        let resp_cmp = div()
            .flex()
            .items_center()
            .gap(px(4.0))
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("Comparer")),
            )
            .child(
                Button::new("rp-resp-cmp-a", "A")
                    .ghost()
                    .size(ButtonSize::Sm)
                    .on_click(cx.listener(|this, _e, _w, cx| this.rp_response_to_comparer(true, cx))),
            )
            .child(
                Button::new("rp-resp-cmp-b", "B")
                    .ghost()
                    .size(ButtonSize::Sm)
                    .on_click(
                        cx.listener(|this, _e, _w, cx| this.rp_response_to_comparer(false, cx)),
                    ),
            );
        let resp_header = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.sm)
            .flex_shrink_0()
            .child(PanelTitle::new(self.lang.t("Response")).hint(self.lang.t(resp_hint)))
            .when(has_resp, |d| {
                d.child(div().flex().items_center().gap(t.space.sm).child(resp_cmp).child(resp_seg))
            });

        let resp_panel = div()
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
            .child(resp_header)
            .child(divider(c))
            .child(resp_body);

        div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .gap(t.space.md)
            .p(t.space.lg)
            .child(toolbar)
            .child(
                div()
                    .flex()
                    .gap(t.space.md)
                    .flex_1()
                    .min_h(px(0.0))
                    .child(req_panel)
                    .child(resp_panel),
            )
    }
}

// ── 响应查看器(只读可选中高亮)共享装配 —— Repeater 与 Intruder 复用 ─────────────

/// 响应查看器的同步签名:状态码 / body 长度 / 头数 / 耗时 / 视图 / 主题 / 错误任一变化即重灌。
/// 不哈希 body 字节(大响应也廉价),靠这些廉价字段判定「是否换了内容」。
pub(crate) fn resp_view_sig(
    dark: bool,
    view: MsgView,
    flow: Option<&HttpFlow>,
    err: Option<&str>,
) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    dark.hash(&mut h);
    (view as u8).hash(&mut h);
    match err {
        Some(e) => {
            1u8.hash(&mut h);
            e.hash(&mut h);
        }
        None => match flow {
            Some(f) => {
                2u8.hash(&mut h);
                f.status.hash(&mut h);
                f.resp_body.len().hash(&mut h);
                f.resp_headers.len().hash(&mut h);
                f.duration_ms.hash(&mut h);
            }
            None => 0u8.hash(&mut h),
        },
    }
    h.finish()
}

/// 构造响应查看器的文本 + 高亮区间:
/// 错误 → 整段标红(可复制);有响应 → 复用 [`crate::proxy::message_text`] / [`crate::proxy::message_highlights`]
/// (与代理页同一条渲染路径,多色与字节严格对齐);皆无 → 空。
pub(crate) fn build_resp_view(
    lang: Lang,
    view: MsgView,
    flow: Option<&HttpFlow>,
    err: Option<&str>,
    c: ThemeColors,
) -> (String, Vec<(Range<usize>, Hsla)>) {
    if let Some(e) = err {
        let text = e.to_string();
        let n = text.len();
        return (text, vec![(0..n, c.danger)]);
    }
    match flow {
        Some(f) => {
            let text = crate::proxy::message_text(lang, false, f, view);
            let hl = crate::proxy::message_highlights(&text, false, f, view, c);
            (text, hl)
        }
        None => (String::new(), Vec::new()),
    }
}


// ── 报文解析(自由函数 + 单测)──────────────────────────────────────

/// 由流推出 Repeater 目标栏 `scheme://host[:port]`(默认端口省略)。
pub fn target_string(flow: &HttpFlow) -> String {
    if matches!(
        (flow.scheme.as_str(), flow.port),
        ("http", 80) | ("https", 443)
    ) {
        format!("{}://{}", flow.scheme, flow.host)
    } else {
        format!("{}://{}:{}", flow.scheme, flow.host, flow.port)
    }
}

/// 把一条流的**请求部分**渲染成可编辑的原始报文(请求行 + 头 + 空行 + body)。
pub fn render_raw_request(flow: &HttpFlow) -> String {
    let mut s = format!("{} {} HTTP/1.1\n", flow.method, flow.path);
    for (k, v) in &flow.req_headers {
        s.push_str(&format!("{k}: {v}\n"));
    }
    s.push('\n');
    s.push_str(&String::from_utf8_lossy(&flow.req_body));
    s
}

/// 把一条流的**响应部分**渲染成原始报文(状态行 + 头 + 空行 + body);供「发送到比较器」用。
pub fn render_raw_response(flow: &HttpFlow) -> String {
    let mut s = format!("HTTP/1.1 {} {}\n", flow.status, status_reason(flow.status));
    for (k, v) in &flow.resp_headers {
        s.push_str(&format!("{k}: {v}\n"));
    }
    s.push('\n');
    s.push_str(&String::from_utf8_lossy(&flow.resp_body));
    s
}

/// 解析 Repeater 目标栏 `scheme://host[:port]` → (scheme, host, port)。
pub fn parse_target(target: &str) -> Result<(String, String, u16), String> {
    let t = target.trim();
    if t.is_empty() {
        return Err("目标不能为空(形如 https://host[:port])".into());
    }
    let (scheme, rest) = match t.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => ("https".to_string(), t),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        return Err("目标 host 不能为空".into());
    }
    let default_port = if scheme == "http" { 80 } else { 443 };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| format!("非法端口:{p}"))?,
        ),
        None => (authority.to_string(), default_port),
    };
    Ok((scheme, host, port))
}

/// 把目标栏 + 原始报文解析成可重放的 [`ReplayRequest`]。
pub fn parse_raw_request(target: &str, raw: &str) -> Result<ReplayRequest, String> {
    let (scheme, host, port) = parse_target(target)?;

    let norm = raw.replace("\r\n", "\n");
    let (head, body_str) = match norm.split_once("\n\n") {
        Some((h, b)) => (h, b),
        None => (norm.as_str(), ""),
    };

    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("").trim();
    if request_line.is_empty() {
        return Err("请求行为空(形如 GET /path HTTP/1.1)".into());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("缺少请求方法")?.to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        match line.split_once(':') {
            Some((k, v)) => headers.push((k.trim().to_string(), v.trim().to_string())),
            None => return Err(format!("非法头部行(应为 Key: Value):{line}")),
        }
    }
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        let host_hdr = if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        headers.push(("Host".to_string(), host_hdr));
    }

    Ok(ReplayRequest {
        method,
        scheme,
        host,
        port,
        path,
        headers,
        body: body_str.as_bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_variants() {
        assert_eq!(
            parse_target("https://api.example.com").unwrap(),
            ("https".to_string(), "api.example.com".to_string(), 443)
        );
        assert_eq!(
            parse_target("http://h:8080").unwrap(),
            ("http".to_string(), "h".to_string(), 8080)
        );
        assert_eq!(
            parse_target("api.example.com").unwrap(),
            ("https".to_string(), "api.example.com".to_string(), 443)
        );
        assert_eq!(
            parse_target("https://h/path?x=1").unwrap(),
            ("https".to_string(), "h".to_string(), 443)
        );
        assert!(parse_target("   ").is_err());
        assert!(parse_target("https://h:notaport").is_err());
    }

    #[test]
    fn parse_raw_request_basic() {
        let raw = "POST /api/login HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"u\":\"a\"}";
        let req = parse_raw_request("https://api.example.com", raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/login");
        assert_eq!(req.scheme, "https");
        assert_eq!(req.host, "api.example.com");
        assert_eq!(req.port, 443);
        assert!(req.is_https());
        assert_eq!(req.body, b"{\"u\":\"a\"}");
        assert!(req
            .headers
            .iter()
            .any(|(k, v)| k == "Content-Type" && v == "application/json"));
    }

    #[test]
    fn parse_raw_request_autofills_host_with_port() {
        let req = parse_raw_request("https://h:8443", "GET / HTTP/1.1\n\n").unwrap();
        assert_eq!(req.port, 8443);
        let host = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.as_str());
        assert_eq!(host, Some("h:8443"));
    }

    #[test]
    fn parse_rejects_bad_header_line() {
        let raw = "GET / HTTP/1.1\nthis-is-not-a-header\n\n";
        assert!(parse_raw_request("https://h", raw).is_err());
    }

    #[test]
    fn render_then_parse_roundtrip_keeps_request() {
        let flow = HttpFlow::request(
            "GET",
            "https",
            "api.example.com",
            443,
            "/v1/users?page=1",
            vec![
                ("Host".to_string(), "api.example.com".to_string()),
                ("Accept".to_string(), "*/*".to_string()),
            ],
            b"".to_vec(),
        );
        let raw = render_raw_request(&flow);
        let req = parse_raw_request("https://api.example.com", &raw).unwrap();
        assert_eq!(req.method, flow.method);
        assert_eq!(req.path, flow.path);
        assert_eq!(req.host, flow.host);
        assert_eq!(req.port, flow.port);
        assert_eq!(req.headers.len(), flow.req_headers.len());
    }
}
