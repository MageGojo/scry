//! GraphQL 页:**GraphQL 工作台**(对标 **Burp / Reqable 的 GraphQL 视图**)。
//!
//! 现代 API 单端点 + 自描述 schema,Repeater 直接改 JSON 体不直观。本页把 [`scry_graphql`] 提到 GUI:
//! - **美化 / 压缩**查询([`scry_graphql::prettify`] / [`scry_graphql::minify`]);
//! - **变量分离**:query 与 variables 分两栏编辑,发送前包成标准 `{"query":…,"variables":…}` POST 体;
//! - **introspection 拉 schema**:一键发内省查询,把回来的 schema 解析成类型 → 字段 → 参数树供浏览。
//!
//! 发包复用 [`scry_proxy::replay`](与 Repeater 同一条 async 路径)。代理右键「发送到 GraphQL」会把
//! 端点 + 请求体里的 query 自动带入。

use mage_ui::gpui::MouseButton;
use mage_ui::prelude::*;
use scry_core::{Header, HttpFlow};
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};

use crate::model::{human_len, status_color};
use crate::repeater::{build_resp_view, resp_view_sig, target_string};
use crate::state::{MsgView, ScryApp};
use crate::widgets::{divider, section_label};

impl ScryApp {
    /// 同步 GraphQL 响应进只读可选中高亮查看器(签名不变则跳过)。
    pub fn sync_graphql_view(&mut self, cx: &mut Context<Self>) {
        let c = cx.theme().colors;
        let dark = cx.theme().mode.is_dark();
        let built = {
            let sig = resp_view_sig(
                dark,
                self.graphql_resp_view,
                self.graphql_resp.as_ref(),
                self.graphql_err.as_deref(),
            );
            if sig == self.graphql_resp_sig {
                None
            } else {
                Some((
                    sig,
                    build_resp_view(
                        self.lang,
                        self.graphql_resp_view,
                        self.graphql_resp.as_ref(),
                        self.graphql_err.as_deref(),
                        c,
                    ),
                ))
            }
        };
        if let Some((sig, (text, hl))) = built {
            let input = self.graphql_resp_input.clone();
            input.update(cx, |s, cx| {
                s.set_text(text, cx);
                s.set_highlights(hl, cx);
            });
            self.graphql_resp_sig = sig;
        }
    }

    /// 代理右键「发送到 GraphQL」:带入端点 + 请求体里的 query。
    pub fn fill_graphql_from_flow(&mut self, flow: &HttpFlow, cx: &mut Context<Self>) {
        let endpoint = format!("{}{}", target_string(flow), flow.path);
        self.graphql_endpoint.update(cx, |s, cx| s.set_text(endpoint, cx));
        // 尝试从 JSON 体里抽出 query / variables。
        let body = scry_decode::display_text(&flow.req_headers, &flow.req_body);
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
            if let Some(q) = v.get("query").and_then(|q| q.as_str()) {
                self.graphql_query
                    .update(cx, |s, cx| s.set_text(scry_graphql::prettify(q), cx));
            }
            if let Some(vars) = v.get("variables") {
                if !vars.is_null() {
                    let pretty = serde_json::to_string_pretty(vars).unwrap_or_default();
                    self.graphql_vars.update(cx, |s, cx| s.set_text(pretty, cx));
                }
            }
        }
        self.graphql_resp = None;
        self.graphql_err = None;
        self.graphql_msg = Some(self.lang.t("Imported from request").to_string());
        cx.notify();
    }

    /// 美化当前查询。
    fn graphql_beautify(&mut self, cx: &mut Context<Self>) {
        let q = self.graphql_query.read(cx).text().to_string();
        self.graphql_query
            .update(cx, |s, cx| s.set_text(scry_graphql::prettify(&q), cx));
        cx.notify();
    }

    /// 压缩当前查询。
    fn graphql_minify(&mut self, cx: &mut Context<Self>) {
        let q = self.graphql_query.read(cx).text().to_string();
        self.graphql_query
            .update(cx, |s, cx| s.set_text(scry_graphql::minify(&q), cx));
        cx.notify();
    }

    /// 由端点 + 额外头 + JSON 体构造一条 POST 重放请求(自动补 Host / Content-Type / Content-Length)。
    fn build_graphql_request(&self, endpoint: &str, body: Vec<u8>, cx: &Context<Self>) -> Result<ReplayRequest, String> {
        let len = body.len();
        let mut req = ReplayRequest::from_url("POST", endpoint, Vec::new(), body)
            .ok_or_else(|| self.lang.t("Invalid endpoint URL").to_string())?;
        let host_hdr = if matches!((req.scheme.as_str(), req.port), ("http", 80) | ("https", 443)) {
            req.host.clone()
        } else {
            format!("{}:{}", req.host, req.port)
        };
        let mut headers: Vec<Header> = vec![
            ("Host".into(), host_hdr),
            ("Content-Type".into(), "application/json".into()),
            ("Accept".into(), "application/json".into()),
            ("User-Agent".into(), "scry-graphql".into()),
        ];
        // 合并用户额外头(如 Authorization),跳过会与上面冲突的 Content-Length(自算)。
        for line in self.graphql_headers.read(cx).text().lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                let (k, v) = (k.trim(), v.trim());
                if k.is_empty() || k.eq_ignore_ascii_case("content-length") {
                    continue;
                }
                headers.retain(|(hk, _)| !hk.eq_ignore_ascii_case(k));
                headers.push((k.to_string(), v.to_string()));
            }
        }
        headers.push(("Content-Length".into(), len.to_string()));
        req.headers = headers;
        Ok(req)
    }

    /// 发送当前 query + variables。
    pub fn send_graphql(&mut self, cx: &mut Context<Self>) {
        let query = self.graphql_query.read(cx).text().to_string();
        let vars = self.graphql_vars.read(cx).text().to_string();
        let body = scry_graphql::build_request_body(&query, &vars, None).into_bytes();
        self.graphql_run(body, false, cx);
    }

    /// 发 introspection 查询拉 schema。
    pub fn introspect_graphql(&mut self, cx: &mut Context<Self>) {
        let body = scry_graphql::build_request_body(scry_graphql::INTROSPECTION_QUERY, "", None).into_bytes();
        self.graphql_run(body, true, cx);
    }

    /// 公共发包流程:构造请求 → 后台 replay → 回主线程刷新响应(introspect 时顺带解析 schema)。
    fn graphql_run(&mut self, body: Vec<u8>, introspect: bool, cx: &mut Context<Self>) {
        if self.graphql_sending {
            return;
        }
        let endpoint = self.graphql_endpoint.read(cx).text().to_string();
        let req = match self.build_graphql_request(&endpoint, body, cx) {
            Ok(r) => r,
            Err(e) => {
                self.graphql_err = Some(e);
                self.graphql_resp = None;
                cx.notify();
                return;
            }
        };
        let up = self.upstream_proxy(cx);
        self.graphql_sending = true;
        self.graphql_err = None;
        self.graphql_msg = Some(if introspect {
            self.lang.t("Introspecting…").to_string()
        } else {
            self.lang.t("Sending…").to_string()
        });
        cx.notify();

        let task = cx.background_executor().spawn(async move {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => return Err(format!("创建运行时失败:{e}")),
            };
            rt.block_on(async move {
                let cfg = ReplayConfig {
                    upstream: up,
                    ..Default::default()
                };
                replay::send(&req, &cfg).await.map_err(|e| format!("{e:#}"))
            })
        });

        cx.spawn(async move |this, cx| {
            let result = task.await;
            let _ = this.update(cx, |this, cx| {
                this.graphql_sending = false;
                match result {
                    Ok(flow) => {
                        if introspect {
                            let text = scry_decode::display_text(&flow.resp_headers, &flow.resp_body);
                            match scry_graphql::parse_introspection(&text) {
                                Ok(schema) => {
                                    this.graphql_msg = Some(format!(
                                        "{} {} types",
                                        this.lang.t("Schema loaded ·"),
                                        schema.type_count()
                                    ));
                                    this.graphql_schema = Some(schema);
                                }
                                Err(e) => this.graphql_msg = Some(e),
                            }
                        } else {
                            this.graphql_msg = None;
                        }
                        this.graphql_resp = Some(flow);
                        this.graphql_err = None;
                    }
                    Err(e) => {
                        this.graphql_err = Some(e);
                        this.graphql_resp = None;
                        this.graphql_msg = None;
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// GraphQL 页主体。
    pub fn graphql_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let (status_text, status_col) = if self.graphql_sending {
            (self.lang.t("Sending…").to_string(), c.warning)
        } else if let Some(f) = &self.graphql_resp {
            (
                format!("{} · {} · {} ms", f.status, human_len(f.resp_len()), f.duration_ms),
                status_color(f.status, c),
            )
        } else if self.graphql_err.is_some() {
            (self.lang.t("Failed").to_string(), c.danger)
        } else {
            (self.lang.t("Ready").to_string(), c.text_subtle)
        };

        let toolbar = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .flex_shrink_0()
            .child(div().flex_1().min_w(px(0.0)).child(self.graphql_endpoint.clone()))
            .child(
                Button::new("gql-introspect", self.lang.t("Introspect"))
                    .size(ButtonSize::Sm)
                    .icon(IconName::Search)
                    .on_click(cx.listener(|this, _e, _w, cx| this.introspect_graphql(cx))),
            )
            .child(
                GlowButton::new(
                    "gql-send",
                    if self.graphql_sending {
                        self.lang.t("Sending…")
                    } else {
                        format!("{}  ▶", self.lang.t("Send")).into()
                    },
                )
                .on_click(cx.listener(|this, _e, _w, cx| this.send_graphql(cx))),
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
                    .child(div().text_size(t.font_size.xs).text_color(c.text_muted).child(status_text)),
            );

        // 查询面板头:标题 + 美化 / 压缩。
        let query_header = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.sm)
            .flex_shrink_0()
            .child(PanelTitle::new(self.lang.t("Query")))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(4.0))
                    .child(
                        Button::new("gql-beautify", self.lang.t("Beautify"))
                            .ghost()
                            .size(ButtonSize::Sm)
                            .on_click(cx.listener(|this, _e, _w, cx| this.graphql_beautify(cx))),
                    )
                    .child(
                        Button::new("gql-minify", self.lang.t("Minify"))
                            .ghost()
                            .size(ButtonSize::Sm)
                            .on_click(cx.listener(|this, _e, _w, cx| this.graphql_minify(cx))),
                    ),
            );

        let left = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0))
            .child(query_header)
            .child(
                div()
                    .id("gql-query-scroll")
                    .flex_1()
                    .min_h(px(0.0))
                    .overflow_y_scroll()
                    .rounded(t.radius.lg)
                    .border_1()
                    .border_color(c.border)
                    .bg(c.surface)
                    .p(t.space.sm)
                    .child(self.graphql_query.clone()),
            )
            .child(section_label(self.lang.t("Variables (JSON)"), c, t))
            .child(self.graphql_vars.clone())
            .child(section_label(self.lang.t("Headers"), c, t))
            .child(self.graphql_headers.clone());

        // 右:schema 树(已 introspect)+ 响应。
        let mut right = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0));
        if self.graphql_schema.is_some() {
            right = right.child(self.graphql_schema_view(c, t));
        }
        right = right.child(self.graphql_response_view(c, t, cx));
        if let Some(msg) = &self.graphql_msg {
            right = right.child(
                div()
                    .flex_shrink_0()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(msg.clone()),
            );
        }

        let body = div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .gap(t.space.md)
            .child(left)
            .child(right);

        div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .gap(t.space.md)
            .p(t.space.lg)
            .child(toolbar)
            .child(divider(c))
            .child(body)
    }

    /// Schema 浏览树(introspection 解析结果:类型 → 字段)。
    fn graphql_schema_view(&self, c: ThemeColors, t: Tokens) -> AnyElement {
        let Some(schema) = &self.graphql_schema else {
            return div().into_any_element();
        };
        let mut list = div()
            .id("gql-schema")
            .flex_shrink_0()
            .max_h(px(260.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(px(6.0));

        let roots = format!(
            "Query: {} · Mutation: {} · Subscription: {}",
            schema.query_type.as_deref().unwrap_or("-"),
            schema.mutation_type.as_deref().unwrap_or("-"),
            schema.subscription_type.as_deref().unwrap_or("-"),
        );
        list = list.child(
            div()
                .font_family(crate::model::MONO)
                .text_size(t.font_size.xs)
                .text_color(c.text_subtle)
                .child(roots),
        );

        for ty in schema.types.iter().take(60) {
            let mut block = div()
                .flex()
                .flex_col()
                .gap(px(2.0))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(6.0))
                        .child(Badge::new(ty.kind.clone(), c.primary))
                        .child(
                            div()
                                .font_family(crate::model::MONO)
                                .text_size(t.font_size.xs)
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(c.text)
                                .child(ty.name.clone()),
                        ),
                );
            for f in ty.fields.iter().take(40) {
                let args = if f.args.is_empty() {
                    String::new()
                } else {
                    let a: Vec<String> = f.args.iter().map(|a| format!("{}: {}", a.name, a.type_name)).collect();
                    format!("({})", a.join(", "))
                };
                block = block.child(
                    div()
                        .pl(px(14.0))
                        .font_family(crate::model::MONO)
                        .text_size(t.font_size.xs)
                        .text_color(c.text_muted)
                        .child(format!("{}{args}: {}", f.name, f.type_name)),
                );
            }
            list = list.child(block);
        }

        div()
            .flex_shrink_0()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .p(t.space.sm)
            .rounded(t.radius.lg)
            .bg(c.surface)
            .border_1()
            .border_color(c.border)
            .child(section_label(self.lang.t("Schema"), c, t))
            .child(list)
            .into_any_element()
    }

    /// 响应区(视图分段 + 只读可选中查看器 / 图片渲染)。
    fn graphql_response_view(&self, c: ThemeColors, t: Tokens, cx: &mut Context<Self>) -> AnyElement {
        let has_resp = self.graphql_resp.is_some() && self.graphql_err.is_none();
        let views = MsgView::ALL;
        let idx = views.iter().position(|m| *m == self.graphql_resp_view).unwrap_or(0);
        let view = cx.entity();
        let seg = Segmented::new("gql-resp-view")
            .items(views.map(|m| self.lang.t(m.label())))
            .selected(idx)
            .on_select(move |i, _e, _w, app| {
                view.update(app, |this, cx| {
                    this.graphql_resp_view = views[i];
                    cx.notify();
                });
            });

        let header = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.sm)
            .flex_shrink_0()
            .child(PanelTitle::new(self.lang.t("Response")))
            .when(has_resp, |d| d.child(seg));

        let body = if self.graphql_resp.is_none() && self.graphql_err.is_none() {
            div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .child(
                    div()
                        .text_size(t.font_size.sm)
                        .text_color(c.text_subtle)
                        .child(self.lang.t("Send a query or run Introspect")),
                )
                .into_any_element()
        } else if self.graphql_resp_view == MsgView::Render && self.graphql_err.is_none() {
            self.response_preview(self.graphql_resp.as_ref(), cx)
        } else {
            div()
                .id("gql-resp-scroll")
                .flex_1()
                .min_h(px(0.0))
                .overflow_y_scroll()
                .on_mouse_down(
                    MouseButton::Right,
                    cx.listener(|this, _e, _w, cx| {
                        let inp = this.graphql_resp_input.clone();
                        this.copy_from_input(inp, cx);
                    }),
                )
                .child(self.graphql_resp_input.clone())
                .into_any_element()
        };

        div()
            .flex_1()
            .min_h(px(0.0))
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
            .into_any_element()
    }
}
