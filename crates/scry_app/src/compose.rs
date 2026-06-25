//! Compose 页:**从零构造请求**(对标 **Reqable Compose / Postman**)。
//!
//! 与 Repeater(从抓到的流改包重发)不同,Compose 是**空手起请求**:自己写请求行 + 头 + body,配合
//! **环境变量** `{{var}}`(发送前替换),并把常用请求**命名存进集合**(持久化 `~/.scry/compose.json`),
//! 下次一键载入。发包复用 [`scry_proxy::replay`](与 Repeater 同一条 async 路径)。
//!
//! 环境变量让「同一请求打不同环境(dev/staging/prod)」「批量改 token/host」变得轻松:把易变的部分
//! 写成 `{{host}}` / `{{token}}`,只在环境表里改一处。

use mage_ui::gpui::MouseButton;
use mage_ui::prelude::*;
use serde::{Deserialize, Serialize};

use crate::model::{human_len, status_color};
use crate::repeater::{build_resp_view, parse_raw_request, resp_view_sig};
use crate::state::{MsgView, ScryApp};
use crate::widgets::{divider, section_label};

/// 集合里一条命名请求(目标 + 原始报文快照)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedRequest {
    pub name: String,
    pub target: String,
    pub raw: String,
}

/// 持久化容器(环境变量 + 集合)。
#[derive(Default, Serialize, Deserialize)]
struct ComposeStore {
    #[serde(default)]
    env: Vec<(String, String)>,
    #[serde(default)]
    saved: Vec<SavedRequest>,
}

/// 存盘位置:`~/.scry/compose.json`(取不到 HOME 时退回当前目录)。
fn compose_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home).join(".scry").join("compose.json")
}

/// 加载环境变量 + 集合(文件不存在 / 坏 JSON → 空)。
pub fn load_compose() -> (Vec<(String, String)>, Vec<SavedRequest>) {
    match std::fs::read_to_string(compose_path()) {
        Ok(s) => match serde_json::from_str::<ComposeStore>(&s) {
            Ok(st) => (st.env, st.saved),
            Err(_) => (Vec::new(), Vec::new()),
        },
        Err(_) => (Vec::new(), Vec::new()),
    }
}

/// 保存环境变量 + 集合;best-effort,失败静默。
fn save_compose(env: &[(String, String)], saved: &[SavedRequest]) {
    let path = compose_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let store = ComposeStore {
        env: env.to_vec(),
        saved: saved.to_vec(),
    };
    if let Ok(s) = serde_json::to_string_pretty(&store) {
        let _ = std::fs::write(&path, s);
    }
}

/// 把文本里的 `{{name}}` 用环境变量值替换(纯函数;未定义的变量原样保留)。
pub fn substitute_vars(text: &str, vars: &[(String, String)]) -> String {
    let mut out = text.to_string();
    for (k, v) in vars {
        if k.is_empty() {
            continue;
        }
        out = out.replace(&format!("{{{{{k}}}}}"), v);
    }
    out
}

impl ScryApp {
    /// 代理右键「发送到 Compose」:把一条流灌进编辑区(便于参数化为 `{{var}}` 后存进集合)。
    pub fn fill_compose_from_flow(&mut self, flow: &scry_core::HttpFlow, cx: &mut Context<Self>) {
        let target = crate::repeater::target_string(flow);
        let raw = crate::repeater::render_raw_request(flow);
        self.compose_target.update(cx, |s, cx| s.set_text(target, cx));
        self.compose_req.update(cx, |s, cx| s.set_text(raw, cx));
        self.compose_resp = None;
        self.compose_err = None;
        cx.notify();
    }

    /// 同步 Compose 响应进只读可选中高亮查看器(签名不变则跳过)。
    pub fn sync_compose_view(&mut self, cx: &mut Context<Self>) {
        let c = cx.theme().colors;
        let dark = cx.theme().mode.is_dark();
        let built = {
            let sig = resp_view_sig(
                dark,
                self.compose_resp_view,
                self.compose_resp.as_ref(),
                self.compose_err.as_deref(),
            );
            if sig == self.compose_resp_sig {
                None
            } else {
                Some((
                    sig,
                    build_resp_view(
                        self.lang,
                        self.compose_resp_view,
                        self.compose_resp.as_ref(),
                        self.compose_err.as_deref(),
                        c,
                    ),
                ))
            }
        };
        if let Some((sig, (text, hl))) = built {
            let input = self.compose_resp_input.clone();
            input.update(cx, |s, cx| {
                s.set_text(text, cx);
                s.set_highlights(hl, cx);
            });
            self.compose_resp_sig = sig;
        }
    }

    /// 发送 Compose 请求:`{{var}}` 替换 → 解析 → 后台 replay → 回主线程刷新响应。
    pub fn send_compose(&mut self, cx: &mut Context<Self>) {
        if self.compose_sending {
            return;
        }
        let target = substitute_vars(self.compose_target.read(cx).text(), &self.compose_env);
        let raw = substitute_vars(self.compose_req.read(cx).text(), &self.compose_env);
        let up = self.upstream_proxy(cx);
        let req = match parse_raw_request(&target, &raw) {
            Ok(r) => r,
            Err(e) => {
                let prefix = if self.lang.is_zh() {
                    "请求解析失败:"
                } else {
                    "Request parse failed: "
                };
                self.compose_err = Some(format!("{prefix}{e}"));
                self.compose_resp = None;
                cx.notify();
                return;
            }
        };

        self.compose_sending = true;
        self.compose_err = None;
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
                let cfg = scry_proxy::replay::ReplayConfig {
                    upstream: up,
                    ..Default::default()
                };
                scry_proxy::replay::send(&req, &cfg)
                    .await
                    .map_err(|e| format!("{e:#}"))
            })
        });

        cx.spawn(async move |this, cx| {
            let result = task.await;
            let _ = this.update(cx, |this, cx| {
                this.compose_sending = false;
                match result {
                    Ok(flow) => {
                        this.compose_resp = Some(flow);
                        this.compose_err = None;
                    }
                    Err(e) => {
                        this.compose_err = Some(e);
                        this.compose_resp = None;
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// 新增 / 更新一个环境变量(同名覆盖),并持久化。
    fn compose_add_env(&mut self, cx: &mut Context<Self>) {
        let name = self.compose_env_name.read(cx).text().trim().to_string();
        let value = self.compose_env_value.read(cx).text().to_string();
        if name.is_empty() {
            return;
        }
        if let Some(slot) = self.compose_env.iter_mut().find(|(k, _)| *k == name) {
            slot.1 = value;
        } else {
            self.compose_env.push((name, value));
        }
        self.compose_env_name.update(cx, |s, cx| s.set_text(String::new(), cx));
        self.compose_env_value.update(cx, |s, cx| s.set_text(String::new(), cx));
        save_compose(&self.compose_env, &self.compose_saved);
        cx.notify();
    }

    /// 删除第 `i` 个环境变量。
    fn compose_del_env(&mut self, i: usize, cx: &mut Context<Self>) {
        if i < self.compose_env.len() {
            self.compose_env.remove(i);
            save_compose(&self.compose_env, &self.compose_saved);
            cx.notify();
        }
    }

    /// 把当前请求存进集合(命名;同名覆盖),并持久化。
    fn compose_save(&mut self, cx: &mut Context<Self>) {
        let name = self.compose_name.read(cx).text().trim().to_string();
        let name = if name.is_empty() {
            format!("request-{}", self.compose_saved.len() + 1)
        } else {
            name
        };
        let target = self.compose_target.read(cx).text().to_string();
        let raw = self.compose_req.read(cx).text().to_string();
        let item = SavedRequest { name: name.clone(), target, raw };
        if let Some(slot) = self.compose_saved.iter_mut().find(|s| s.name == name) {
            *slot = item;
        } else {
            self.compose_saved.push(item);
        }
        save_compose(&self.compose_env, &self.compose_saved);
        self.show_toast(format!("{} {name}", self.lang.t("Saved request")), cx);
    }

    /// 载入集合里第 `i` 条到编辑区。
    fn compose_load(&mut self, i: usize, cx: &mut Context<Self>) {
        if let Some(item) = self.compose_saved.get(i).cloned() {
            self.compose_target.update(cx, |s, cx| s.set_text(item.target, cx));
            self.compose_req.update(cx, |s, cx| s.set_text(item.raw, cx));
            self.compose_name.update(cx, |s, cx| s.set_text(item.name, cx));
            self.compose_resp = None;
            self.compose_err = None;
            cx.notify();
        }
    }

    /// 删除集合里第 `i` 条。
    fn compose_delete(&mut self, i: usize, cx: &mut Context<Self>) {
        if i < self.compose_saved.len() {
            self.compose_saved.remove(i);
            save_compose(&self.compose_env, &self.compose_saved);
            cx.notify();
        }
    }

    /// Compose 页主体。
    pub fn compose_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let (status_text, status_col) = if self.compose_sending {
            (self.lang.t("Sending…").to_string(), c.warning)
        } else if let Some(f) = &self.compose_resp {
            (
                format!("{} · {} · {} ms", f.status, human_len(f.resp_len()), f.duration_ms),
                status_color(f.status, c),
            )
        } else if self.compose_err.is_some() {
            (self.lang.t("Failed").to_string(), c.danger)
        } else {
            (self.lang.t("Ready").to_string(), c.text_subtle)
        };

        let toolbar = div()
            .flex()
            .items_center()
            .gap(t.space.md)
            .flex_shrink_0()
            .child(div().flex_1().min_w(px(0.0)).child(self.compose_target.clone()))
            .child(
                GlowButton::new(
                    "compose-send",
                    if self.compose_sending {
                        self.lang.t("Sending…")
                    } else {
                        format!("{}  ▶", self.lang.t("Send")).into()
                    },
                )
                .on_click(cx.listener(|this, _e, _w, cx| this.send_compose(cx))),
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

        // 左:请求编辑 + 保存集合。
        let save_row = div()
            .flex()
            .items_center()
            .gap(px(6.0))
            .flex_shrink_0()
            .child(div().flex_1().min_w(px(0.0)).child(self.compose_name.clone()))
            .child(
                Button::new("compose-save", self.lang.t("Save"))
                    .size(ButtonSize::Sm)
                    .icon(IconName::Download)
                    .on_click(cx.listener(|this, _e, _w, cx| this.compose_save(cx))),
            );

        let left = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0))
            .child(section_label(self.lang.t("Request"), c, t))
            .child(
                div()
                    .id("compose-req-scroll")
                    .flex_1()
                    .min_h(px(0.0))
                    .overflow_y_scroll()
                    .rounded(t.radius.lg)
                    .border_1()
                    .border_color(c.border)
                    .bg(c.surface)
                    .p(t.space.sm)
                    .child(self.compose_req.clone()),
            )
            .child(save_row)
            .child(self.compose_collection_view(c, t, cx));

        // 右:环境变量 + 响应。
        let right = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0))
            .child(self.compose_env_view(c, t, cx))
            .child(self.compose_response_view(c, t, cx));

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
            .child(
                div()
                    .flex_shrink_0()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t(
                        "Build a request from scratch. Use {{var}} placeholders, defined in Environment on the right.",
                    )),
            )
            .child(divider(c))
            .child(body)
    }

    /// 环境变量编辑卡(新增行 + 现有列表)。
    fn compose_env_view(&self, c: ThemeColors, t: Tokens, cx: &mut Context<Self>) -> AnyElement {
        let add_row = div()
            .flex()
            .items_center()
            .gap(px(6.0))
            .flex_shrink_0()
            .child(div().w(px(120.0)).flex_shrink_0().child(self.compose_env_name.clone()))
            .child(div().flex_1().min_w(px(0.0)).child(self.compose_env_value.clone()))
            .child(
                Button::new("compose-env-add", self.lang.t("Add"))
                    .size(ButtonSize::Sm)
                    .icon(IconName::Plus)
                    .on_click(cx.listener(|this, _e, _w, cx| this.compose_add_env(cx))),
            );

        let mut list = div().flex().flex_col().gap(px(3.0));
        if self.compose_env.is_empty() {
            list = list.child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("No variables yet")),
            );
        }
        for (i, (k, v)) in self.compose_env.iter().enumerate() {
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .child(
                        div()
                            .w(px(120.0))
                            .flex_shrink_0()
                            .font_family(crate::model::MONO)
                            .text_size(t.font_size.xs)
                            .text_color(c.accent)
                            .child(format!("{{{{{k}}}}}")),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .font_family(crate::model::MONO)
                            .text_size(t.font_size.xs)
                            .text_color(c.text_muted)
                            .child(v.clone()),
                    )
                    .child(
                        IconButton::new(("compose-env-del", i), IconName::Trash)
                            .ghost()
                            .on_click(cx.listener(move |this, _e, _w, cx| this.compose_del_env(i, cx))),
                    ),
            );
        }

        div()
            .flex_shrink_0()
            .flex()
            .flex_col()
            .gap(px(6.0))
            .p(t.space.sm)
            .rounded(t.radius.lg)
            .bg(c.surface)
            .border_1()
            .border_color(c.border)
            .child(section_label(self.lang.t("Environment"), c, t))
            .child(add_row)
            .child(list)
            .into_any_element()
    }

    /// 集合列表(载入 / 删除)。
    fn compose_collection_view(&self, c: ThemeColors, t: Tokens, cx: &mut Context<Self>) -> AnyElement {
        if self.compose_saved.is_empty() {
            return div()
                .flex_shrink_0()
                .text_size(t.font_size.xs)
                .text_color(c.text_subtle)
                .child(self.lang.t("Saved requests appear here"))
                .into_any_element();
        }
        let mut list = div()
            .id("compose-collection")
            .flex_shrink_0()
            .max_h(px(150.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(px(3.0));
        for (i, item) in self.compose_saved.iter().enumerate() {
            let name = item.name.clone();
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .child(
                        div()
                            .id(("compose-load", i))
                            .flex_1()
                            .min_w(px(0.0))
                            .cursor_pointer()
                            .text_size(t.font_size.xs)
                            .text_color(c.text)
                            .child(name)
                            .on_click(cx.listener(move |this, _e, _w, cx| this.compose_load(i, cx))),
                    )
                    .child(
                        IconButton::new(("compose-del", i), IconName::Trash)
                            .ghost()
                            .on_click(cx.listener(move |this, _e, _w, cx| this.compose_delete(i, cx))),
                    ),
            );
        }
        div()
            .flex_shrink_0()
            .flex()
            .flex_col()
            .gap(px(4.0))
            .child(section_label(self.lang.t("Collection"), c, t))
            .child(list)
            .into_any_element()
    }

    /// 响应区(视图分段 + 只读可选中查看器 / 图片渲染)。
    fn compose_response_view(&self, c: ThemeColors, t: Tokens, cx: &mut Context<Self>) -> AnyElement {
        let has_resp = self.compose_resp.is_some() && self.compose_err.is_none();
        let views = MsgView::ALL;
        let idx = views.iter().position(|m| *m == self.compose_resp_view).unwrap_or(0);
        let view = cx.entity();
        let seg = Segmented::new("compose-resp-view")
            .items(views.map(|m| self.lang.t(m.label())))
            .selected(idx)
            .on_select(move |i, _e, _w, app| {
                view.update(app, |this, cx| {
                    this.compose_resp_view = views[i];
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

        let body = if self.compose_resp.is_none() && self.compose_err.is_none() {
            div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .child(
                    div()
                        .text_size(t.font_size.sm)
                        .text_color(c.text_subtle)
                        .child(self.lang.t("Build the request on the left, then Send")),
                )
                .into_any_element()
        } else if self.compose_resp_view == MsgView::Render && self.compose_err.is_none() {
            self.response_preview(self.compose_resp.as_ref(), cx)
        } else {
            div()
                .id("compose-resp-scroll")
                .flex_1()
                .min_h(px(0.0))
                .overflow_y_scroll()
                .on_mouse_down(
                    MouseButton::Right,
                    cx.listener(|this, _e, _w, cx| {
                        let inp = this.compose_resp_input.clone();
                        this.copy_from_input(inp, cx);
                    }),
                )
                .child(self.compose_resp_input.clone())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitute_replaces_known_vars() {
        let vars = vec![
            ("host".to_string(), "example.com".to_string()),
            ("token".to_string(), "abc123".to_string()),
        ];
        let out = substitute_vars("GET / HTTP/1.1\nHost: {{host}}\nAuth: {{token}}", &vars);
        assert_eq!(out, "GET / HTTP/1.1\nHost: example.com\nAuth: abc123");
    }

    #[test]
    fn substitute_leaves_unknown_and_empty() {
        let vars = vec![("a".to_string(), "1".to_string()), (String::new(), "x".to_string())];
        // 未定义的 {{b}} 原样保留;空名变量跳过(不会把 {{}} 替成 x)。
        assert_eq!(substitute_vars("{{a}}-{{b}}-{{}}", &vars), "1-{{b}}-{{}}");
    }

    #[test]
    fn saved_request_serde_roundtrip() {
        let item = SavedRequest {
            name: "login".to_string(),
            target: "https://h".to_string(),
            raw: "POST /login HTTP/1.1\n\nuser=a".to_string(),
        };
        let store = ComposeStore {
            env: vec![("k".to_string(), "v".to_string())],
            saved: vec![item],
        };
        let json = serde_json::to_string(&store).unwrap();
        let back: ComposeStore = serde_json::from_str(&json).unwrap();
        assert_eq!(back.env, store.env);
        assert_eq!(back.saved.len(), 1);
        assert_eq!(back.saved[0].name, "login");
    }
}
