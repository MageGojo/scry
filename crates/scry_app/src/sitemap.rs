//! Site map(站点地图)—— 代理页子页签,对标 Burp **Target / Site map** 与 Caido 的站点树。
//!
//! 把抓到的流量按 **host → 路径段** 组织成可展开树(纯函数 [`build_site_tree`] 构建,可单测);
//! 点节点在右侧列出该子树下的全部请求,点请求一键发到重放。与 HTTPQL(扁平结构化查询)互补:
//! 一个按结构浏览、一个按字段查询。

use std::collections::{BTreeMap, HashSet};

use mage_ui::prelude::*;
use scry_core::HttpFlow;

use crate::model::MONO;
use crate::state::{HistTab, ScryApp, Tab};

/// 站点树节点(host 根 或 路径段)。
pub struct SiteNode {
    /// 显示名(host 根 = host;否则路径段)。
    pub label: String,
    /// 该节点代表的完整 URL 前缀(`scheme://host/seg1/seg2`),用作展开/选中键。
    pub full: String,
    /// 是否 host 根节点。
    pub is_host: bool,
    /// 是否有请求**精确**命中此路径(端点)。
    pub endpoint: bool,
    /// 子树下请求数。
    pub count: usize,
    pub children: Vec<SiteNode>,
    /// 子树下全部请求在 `flows` 里的下标(含后代)。
    pub subtree_idxs: Vec<usize>,
}

impl SiteNode {
    /// 生成定位此节点流量的 HTTPQL 查询(与 HTTPQL 互补:在 Site map 按结构选中,
    /// 一键回到 HTTP History 按字段过滤)。host 根 → `req.host.eq:"host"`;
    /// 路径节点再追加 `req.path.cont:"/seg…"`。`full` 形如 `scheme://host/seg1/seg2`。
    pub fn httpql_query(&self) -> String {
        let rest = self
            .full
            .split_once("://")
            .map(|x| x.1)
            .unwrap_or(self.full.as_str());
        match rest.split_once('/') {
            Some((host, path)) => format!("req.host.eq:\"{host}\" AND req.path.cont:\"/{path}\""),
            None => format!("req.host.eq:\"{rest}\""),
        }
    }
}

#[derive(Default)]
struct Trie {
    children: BTreeMap<String, Trie>,
    idxs: Vec<usize>,
}

/// 由流量构建站点树(按 host 分组 → 路径段 trie);纯函数。
pub fn build_site_tree(flows: &[HttpFlow]) -> Vec<SiteNode> {
    let mut hosts: BTreeMap<String, (String, Trie)> = BTreeMap::new();
    for (i, f) in flows.iter().enumerate() {
        let entry = hosts
            .entry(f.host.clone())
            .or_insert_with(|| (f.scheme.clone(), Trie::default()));
        let path = f.path.split(['?', '#']).next().unwrap_or(&f.path);
        let mut node = &mut entry.1;
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            node = node.children.entry(seg.to_string()).or_default();
        }
        node.idxs.push(i);
    }

    let mut out = Vec::new();
    for (host, (scheme, trie)) in hosts {
        let base_full = format!("{scheme}://{host}");
        let children = convert(&trie.children, &base_full, "");
        let mut subtree = trie.idxs.clone();
        for c in &children {
            subtree.extend(&c.subtree_idxs);
        }
        out.push(SiteNode {
            label: host,
            full: base_full,
            is_host: true,
            endpoint: !trie.idxs.is_empty(),
            count: subtree.len(),
            children,
            subtree_idxs: subtree,
        });
    }
    out
}

fn convert(children: &BTreeMap<String, Trie>, base_full: &str, base_path: &str) -> Vec<SiteNode> {
    let mut out = Vec::new();
    for (seg, sub) in children {
        let full = format!("{base_full}/{seg}");
        let path = format!("{base_path}/{seg}");
        let child_nodes = convert(&sub.children, &full, &path);
        let mut subtree = sub.idxs.clone();
        for c in &child_nodes {
            subtree.extend(&c.subtree_idxs);
        }
        out.push(SiteNode {
            label: seg.clone(),
            full,
            is_host: false,
            endpoint: !sub.idxs.is_empty(),
            count: subtree.len(),
            children: child_nodes,
            subtree_idxs: subtree,
        });
    }
    out
}

/// 把树按展开状态拍平成渲染行 `(depth, node)`(折叠节点不下钻)。
fn flatten<'a>(
    nodes: &'a [SiteNode],
    expanded: &HashSet<String>,
    depth: usize,
    out: &mut Vec<(usize, &'a SiteNode)>,
) {
    for n in nodes {
        out.push((depth, n));
        if !n.children.is_empty() && expanded.contains(&n.full) {
            flatten(&n.children, expanded, depth + 1, out);
        }
    }
}

/// 在树里按 `full` 找节点。
fn find_node<'a>(nodes: &'a [SiteNode], full: &str) -> Option<&'a SiteNode> {
    for n in nodes {
        if n.full == full {
            return Some(n);
        }
        if let Some(x) = find_node(&n.children, full) {
            return Some(x);
        }
    }
    None
}

impl ScryApp {
    /// 点树节点:选中它;若有子节点则切换展开/折叠。
    pub fn sitemap_toggle(&mut self, full: String, has_children: bool, cx: &mut Context<Self>) {
        self.sitemap_selected = Some(full.clone());
        if has_children && !self.sitemap_expanded.remove(&full) {
            self.sitemap_expanded.insert(full);
        }
        cx.notify();
    }

    /// Site map 子页签主体:左树 + 右请求列表。
    pub fn sitemap_panel(&self, cx: &mut Context<Self>) -> AnyElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let tree = build_site_tree(&self.flows);
        if tree.is_empty() {
            return EmptyState::new(self.lang.t("No traffic captured yet"))
                .icon(IconName::Globe)
                .into_any_element();
        }

        // 左:树。
        let mut rows: Vec<(usize, &SiteNode)> = Vec::new();
        flatten(&tree, &self.sitemap_expanded, 0, &mut rows);
        let mut tree_col = div()
            .id("sitemap-tree")
            .w(px(360.0))
            .flex_shrink_0()
            .min_h(px(0.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(px(1.0))
            .p(t.space.sm)
            .rounded(t.radius.lg)
            .bg(c.surface)
            .border_1()
            .border_color(c.border);
        for (depth, node) in &rows {
            tree_col = tree_col.child(self.sitemap_row(*depth, node, c, t, cx));
        }

        // 右:选中节点子树的请求列表。
        let selected = self
            .sitemap_selected
            .as_ref()
            .and_then(|s| find_node(&tree, s));
        let right = self.sitemap_requests(selected, c, t, cx);

        div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .gap(t.space.md)
            .child(tree_col)
            .child(right)
            .into_any_element()
    }

    /// 单个树行:缩进 + 折叠箭头 + 图标 + 名字 + 计数。
    fn sitemap_row(
        &self,
        depth: usize,
        node: &SiteNode,
        c: ThemeColors,
        t: Tokens,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let has_children = !node.children.is_empty();
        let expanded = self.sitemap_expanded.contains(&node.full);
        let selected = self.sitemap_selected.as_deref() == Some(node.full.as_str());
        let full = node.full.clone();

        let chevron = if has_children {
            Icon::new(if expanded {
                IconName::ChevronDown
            } else {
                IconName::ChevronRight
            })
            .size(px(12.0))
            .color(c.text_subtle)
            .into_any_element()
        } else {
            div().w(px(12.0)).into_any_element()
        };
        // 端点(有精确命中的请求)用 Tag,纯路径容器用 Folder。
        let leaf_icon = if node.is_host {
            IconName::Globe
        } else if node.endpoint {
            IconName::Tag
        } else {
            IconName::Folder
        };

        div()
            .id(SharedString::from(format!("sm-{}", node.full)))
            .flex()
            .items_center()
            .gap(px(4.0))
            .py(px(3.0))
            .pr(px(6.0))
            .pl(px(6.0 + depth as f32 * 14.0))
            .rounded(t.radius.sm)
            .cursor_pointer()
            .when(selected, |r| r.bg(c.elevated))
            .hover(|r| r.bg(c.elevated))
            .on_click(cx.listener(move |this, _e, _w, cx| {
                this.sitemap_toggle(full.clone(), has_children, cx)
            }))
            .child(chevron)
            .child(Icon::new(leaf_icon).size(px(13.0)).color(if node.is_host {
                c.primary
            } else {
                c.text_subtle
            }))
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .truncate()
                    .font_family(MONO)
                    .text_size(t.font_size.xs)
                    .text_color(if node.is_host { c.text } else { c.text_muted })
                    .child(if node.is_host {
                        node.label.clone()
                    } else {
                        format!("/{}", node.label)
                    }),
            )
            .child(
                div()
                    .flex_shrink_0()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(node.count.to_string()),
            )
    }

    /// 右侧:选中节点子树下的请求列表(点行发到重放)。
    fn sitemap_requests(
        &self,
        node: Option<&SiteNode>,
        c: ThemeColors,
        t: Tokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let Some(node) = node else {
            return EmptyState::new(self.lang.t("Select a node to list its requests"))
                .icon(IconName::GitBranch)
                .into_any_element();
        };

        // 子树请求按时间倒序,封顶 300 行。
        let mut idxs: Vec<usize> = node.subtree_idxs.clone();
        idxs.sort_by(|&a, &b| {
            let ta = self.flows.get(a).map(|f| f.ts).unwrap_or(0);
            let tb = self.flows.get(b).map(|f| f.ts).unwrap_or(0);
            tb.cmp(&ta)
        });
        idxs.truncate(300);

        // 与 HTTPQL 互补:把此结构节点一键变成 HTTP History 的字段查询。
        let query = node.httpql_query();
        let header = div()
            .flex_shrink_0()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .truncate()
                    .font_family(MONO)
                    .text_size(t.font_size.xs)
                    .text_color(c.text)
                    .child(node.full.clone()),
            )
            .child(
                div()
                    .flex_shrink_0()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(format!("{} {}", node.count, self.lang.t("requests"))),
            )
            .child(
                Button::new("sitemap-query", self.lang.t("Query in history"))
                    .ghost()
                    .size(ButtonSize::Sm)
                    .icon(IconName::Filter)
                    .on_click(cx.listener(move |this, _e, _w, cx| {
                        let q = query.clone();
                        this.search.update(cx, |s, cx| s.set_text(q, cx));
                        this.host_filter = None;
                        this.hist_tab = HistTab::History;
                        cx.notify();
                    })),
            );

        let mut list = div()
            .id("sitemap-reqs")
            .flex_1()
            .min_h(px(0.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(px(1.0));
        for idx in idxs {
            let Some(f) = self.flows.get(idx) else {
                continue;
            };
            list = list.child(self.sitemap_req_row(idx, f, c, t, cx));
        }

        div()
            .flex_1()
            .min_w(px(0.0))
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .child(header)
            .child(list)
            .into_any_element()
    }

    /// 请求行:方法 + 状态 + 路径;点击发到重放。
    fn sitemap_req_row(
        &self,
        idx: usize,
        f: &HttpFlow,
        c: ThemeColors,
        t: Tokens,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let status_color = if f.status >= 500 {
            c.danger
        } else if f.status >= 400 {
            c.warning
        } else if f.status >= 300 {
            c.accent
        } else if f.status >= 200 {
            c.success
        } else {
            c.text_subtle
        };
        div()
            .id(("sm-req", idx))
            .flex()
            .items_center()
            .gap(t.space.sm)
            .py(px(3.0))
            .px(px(6.0))
            .rounded(t.radius.sm)
            .cursor_pointer()
            .hover(|r| r.bg(c.elevated))
            .on_click(cx.listener(move |this, _e, _w, cx| {
                if let Some(f) = this.flows.get(idx).cloned() {
                    this.fill_repeater_from_flow(&f, cx);
                    this.selected = Some(idx);
                    this.tab = Tab::Repeater;
                    cx.notify();
                }
            }))
            .child(
                div()
                    .w(px(52.0))
                    .flex_shrink_0()
                    .font_family(MONO)
                    .text_size(t.font_size.xs)
                    .text_color(c.text_muted)
                    .child(f.method.clone()),
            )
            .child(
                div()
                    .w(px(34.0))
                    .flex_shrink_0()
                    .font_family(MONO)
                    .text_size(t.font_size.xs)
                    .text_color(status_color)
                    .child(if f.status == 0 {
                        "—".to_string()
                    } else {
                        f.status.to_string()
                    }),
            )
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .truncate()
                    .font_family(MONO)
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(f.path.clone()),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(host: &str, path: &str) -> HttpFlow {
        HttpFlow::request("GET", "https", host, 443, path, vec![], vec![])
    }

    #[test]
    fn builds_host_and_path_tree() {
        let flows = vec![
            flow("a.com", "/api/v1/users"),
            flow("a.com", "/api/v1/orders"),
            flow("a.com", "/login"),
            flow("b.com", "/"),
        ];
        let tree = build_site_tree(&flows);
        assert_eq!(tree.len(), 2); // a.com, b.com
        let a = tree.iter().find(|n| n.label == "a.com").unwrap();
        assert!(a.is_host);
        assert_eq!(a.count, 3); // 3 个请求在 a.com 子树
                                // a.com 下应有 api、login 两个直接子节点
        let api = a.children.iter().find(|n| n.label == "api").unwrap();
        assert_eq!(api.count, 2);
        let v1 = api.children.iter().find(|n| n.label == "v1").unwrap();
        assert_eq!(v1.children.len(), 2); // users, orders
        assert!(a.children.iter().any(|n| n.label == "login" && n.endpoint));
    }

    #[test]
    fn query_is_stripped_for_structure() {
        let flows = vec![
            flow("h", "/search?q=1"),
            flow("h", "/search?q=2"),
        ];
        let tree = build_site_tree(&flows);
        let h = &tree[0];
        let search = h.children.iter().find(|n| n.label == "search").unwrap();
        // 同路径不同查询 → 同一节点,两条请求。
        assert_eq!(search.count, 2);
        assert!(search.endpoint);
    }

    #[test]
    fn empty_flows_empty_tree() {
        assert!(build_site_tree(&[]).is_empty());
    }

    #[test]
    fn httpql_query_for_host_and_path() {
        let flows = vec![flow("a.com", "/api/v1/users")];
        let tree = build_site_tree(&flows);
        let a = tree.iter().find(|n| n.label == "a.com").unwrap();
        // host 根:仅按 host 精确过滤。
        assert_eq!(a.httpql_query(), "req.host.eq:\"a.com\"");
        // 路径节点:host 精确 + path 前缀包含。
        let api = a.children.iter().find(|n| n.label == "api").unwrap();
        assert_eq!(
            api.httpql_query(),
            "req.host.eq:\"a.com\" AND req.path.cont:\"/api\""
        );
        let v1 = api.children.iter().find(|n| n.label == "v1").unwrap();
        assert_eq!(
            v1.httpql_query(),
            "req.host.eq:\"a.com\" AND req.path.cont:\"/api/v1\""
        );
    }
}
