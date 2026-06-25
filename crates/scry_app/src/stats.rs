//! Stats 页:**流量统计 / 图表**(锦上添花,对标抓包工具的概览面板)。
//!
//! 对当前会话已抓到的流量(`self.flows`)做**纯函数聚合**(按方法 / 状态码段 / 内容类型 / 主机),
//! 再用简单的横向条形图展示。聚合逻辑 [`aggregate`] 与分类 [`categorize_content_type`] 都是纯函数 + 单测,
//! 与渲染解耦。

use mage_ui::prelude::*;
use scry_core::HttpFlow;

use crate::model::{human_len, MONO};
use crate::state::ScryApp;
use crate::widgets::{divider, section_label};

/// 一个分组计数(标签 + 条数),用于条形图一行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountBar {
    pub label: String,
    pub count: usize,
}

/// 流量统计聚合结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrafficStats {
    pub total: usize,
    pub https: usize,
    pub http: usize,
    pub ws: usize,
    pub total_resp_bytes: usize,
    /// 按请求方法(降序)。
    pub by_method: Vec<CountBar>,
    /// 按状态码段(`2xx`/`3xx`/`4xx`/`5xx`/`—`,降序)。
    pub by_status: Vec<CountBar>,
    /// 按内容类型大类(降序)。
    pub by_type: Vec<CountBar>,
    /// 按主机(取前若干,降序)。
    pub by_host: Vec<CountBar>,
}

/// 按内容类型字符串归到一个大类(纯函数,便于单测)。
pub fn categorize_content_type(ct: Option<&str>) -> &'static str {
    let Some(ct) = ct else {
        return "Other";
    };
    let ct = ct.to_ascii_lowercase();
    if ct.contains("html") {
        "HTML"
    } else if ct.contains("json") {
        "JSON"
    } else if ct.contains("javascript") || ct.contains("ecmascript") {
        "JS"
    } else if ct.contains("css") {
        "CSS"
    } else if ct.starts_with("image/") {
        "Image"
    } else if ct.contains("font") || ct.contains("woff") {
        "Font"
    } else if ct.contains("xml") {
        "XML"
    } else if ct.starts_with("text/") {
        "Text"
    } else {
        "Other"
    }
}

/// 状态码 → 段标签(`0` = 无响应记为 `—`)。
fn status_class(status: u16) -> String {
    if status == 0 {
        "—".to_string()
    } else {
        format!("{}xx", status / 100)
    }
}

/// 把计数 map 折叠成按条数降序的 `Vec<CountBar>`(同条数按标签字典序稳定)。
fn sorted_bars(map: std::collections::HashMap<String, usize>) -> Vec<CountBar> {
    let mut v: Vec<CountBar> = map
        .into_iter()
        .map(|(label, count)| CountBar { label, count })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.label.cmp(&b.label)));
    v
}

/// 聚合一批流量为 [`TrafficStats`](纯函数)。
pub fn aggregate(flows: &[HttpFlow]) -> TrafficStats {
    use std::collections::HashMap;
    let mut by_method: HashMap<String, usize> = HashMap::new();
    let mut by_status: HashMap<String, usize> = HashMap::new();
    let mut by_type: HashMap<String, usize> = HashMap::new();
    let mut by_host: HashMap<String, usize> = HashMap::new();
    let (mut https, mut http, mut ws, mut bytes) = (0usize, 0usize, 0usize, 0usize);

    for f in flows {
        *by_method.entry(f.method.clone()).or_default() += 1;
        *by_status.entry(status_class(f.status)).or_default() += 1;
        *by_type
            .entry(categorize_content_type(f.content_type()).to_string())
            .or_default() += 1;
        if !f.host.is_empty() {
            *by_host.entry(f.host.clone()).or_default() += 1;
        }
        match f.scheme.as_str() {
            "https" => https += 1,
            "http" => http += 1,
            "ws" | "wss" => ws += 1,
            _ => {}
        }
        bytes += f.resp_body.len();
    }

    let mut by_host = sorted_bars(by_host);
    const TOP_HOSTS: usize = 12;
    by_host.truncate(TOP_HOSTS);

    TrafficStats {
        total: flows.len(),
        https,
        http,
        ws,
        total_resp_bytes: bytes,
        by_method: sorted_bars(by_method),
        by_status: sorted_bars(by_status),
        by_type: sorted_bars(by_type),
        by_host,
    }
}

impl ScryApp {
    /// Stats 页主体:概览指标卡 + 各维度条形图。
    pub fn stats_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let stats = aggregate(&self.flows);

        let header = div()
            .flex()
            .flex_col()
            .gap(px(2.0))
            .flex_shrink_0()
            .child(
                div()
                    .text_size(t.font_size.lg)
                    .text_color(c.text)
                    .child(self.lang.t("Traffic stats")),
            )
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("Aggregated over the current session's captured flows")),
            );

        let body: AnyElement = if stats.total == 0 {
            EmptyState::new(self.lang.t("No traffic captured yet"))
                .icon(IconName::Search)
                .into_any_element()
        } else {
            // 概览指标卡。
            let metrics = div()
                .flex()
                .flex_wrap()
                .gap(t.space.md)
                .flex_shrink_0()
                .child(
                    Metric::new(
                        IconName::Layers,
                        self.lang.t("Total flows"),
                        stats.total.to_string(),
                    )
                    .color(c.primary),
                )
                .child(Metric::new(IconName::Tag, "HTTPS", stats.https.to_string()).color(c.success))
                .child(Metric::new(IconName::Globe, "HTTP", stats.http.to_string()).color(c.accent))
                .child(Metric::new(IconName::Globe, "WS", stats.ws.to_string()).color(c.warning))
                .child(
                    Metric::new(
                        IconName::Download,
                        self.lang.t("Response bytes"),
                        human_len(stats.total_resp_bytes),
                    )
                    .color(c.text_muted),
                );

            // 各维度条形图(自动换行多列)。
            let grid = div()
                .flex()
                .flex_wrap()
                .gap(t.space.md)
                .child(self.bar_section(self.lang.t("By method"), &stats.by_method, c.primary, c, t))
                .child(self.bar_section(self.lang.t("By status"), &stats.by_status, c.success, c, t))
                .child(self.bar_section(self.lang.t("By type"), &stats.by_type, c.accent, c, t))
                .child(self.bar_section(self.lang.t("Top hosts"), &stats.by_host, c.warning, c, t));

            div()
                .flex()
                .flex_col()
                .gap(t.space.lg)
                .child(metrics)
                .child(divider(c))
                .child(grid)
                .into_any_element()
        };

        div()
            .id("stats-scroll")
            .flex_1()
            .min_h(px(0.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(t.space.lg)
            .p(t.space.lg)
            .child(header)
            .child(body)
    }

    /// 一个维度的条形图卡(标题 + 若干条;条宽按占最大值比例)。
    fn bar_section(
        &self,
        title: SharedString,
        bars: &[CountBar],
        color: Hsla,
        c: ThemeColors,
        t: Tokens,
    ) -> AnyElement {
        let max = bars.iter().map(|b| b.count).max().unwrap_or(1).max(1) as f32;
        let mut col = div()
            .flex()
            .flex_col()
            .gap(px(5.0))
            .w(px(360.0))
            .flex_shrink_0()
            .p(t.space.md)
            .rounded(t.radius.lg)
            .bg(c.surface)
            .border_1()
            .border_color(c.border)
            .child(section_label(title, c, t));
        for b in bars.iter().take(12) {
            col = col.child(bar_row(&b.label, b.count, b.count as f32 / max, color, c, t));
        }
        col.into_any_element()
    }
}

/// 条形图一行:标签(定宽)+ 轨道 + 填充(按比例)+ 计数。
fn bar_row(label: &str, count: usize, frac: f32, color: Hsla, c: ThemeColors, t: Tokens) -> impl IntoElement {
    let track = 180.0_f32;
    let frac = frac.clamp(0.0, 1.0);
    div()
        .flex()
        .items_center()
        .gap(t.space.sm)
        .child(
            div()
                .w(px(96.0))
                .flex_shrink_0()
                .truncate()
                .font_family(MONO)
                .text_size(t.font_size.xs)
                .text_color(c.text_muted)
                .child(label.to_string()),
        )
        .child(
            div()
                .w(px(track))
                .h(px(9.0))
                .flex_shrink_0()
                .rounded(t.radius.full)
                .bg(c.background)
                .border_1()
                .border_color(c.glass_border)
                .overflow_hidden()
                .child(div().h_full().w(px(track * frac)).bg(color)),
        )
        .child(
            div()
                .flex_shrink_0()
                .font_family(MONO)
                .text_size(t.font_size.xs)
                .text_color(c.text_subtle)
                .child(count.to_string()),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(method: &str, scheme: &str, host: &str, status: u16, ct: &str, body: &[u8]) -> HttpFlow {
        HttpFlow::request(method, scheme, host, 443, "/", vec![], vec![]).with_response(
            status,
            vec![("Content-Type".to_string(), ct.to_string())],
            body.to_vec(),
            5,
        )
    }

    #[test]
    fn categorize_covers_common_types() {
        assert_eq!(categorize_content_type(Some("text/html; charset=utf-8")), "HTML");
        assert_eq!(categorize_content_type(Some("application/json")), "JSON");
        assert_eq!(categorize_content_type(Some("application/javascript")), "JS");
        assert_eq!(categorize_content_type(Some("image/png")), "Image");
        assert_eq!(categorize_content_type(Some("text/css")), "CSS");
        assert_eq!(categorize_content_type(Some("application/font-woff2")), "Font");
        assert_eq!(categorize_content_type(Some("application/xml")), "XML");
        assert_eq!(categorize_content_type(Some("application/octet-stream")), "Other");
        assert_eq!(categorize_content_type(None), "Other");
    }

    #[test]
    fn aggregate_counts_dimensions() {
        let flows = vec![
            flow("GET", "https", "a.com", 200, "text/html", b"<html>"),
            flow("GET", "https", "a.com", 200, "application/json", b"{}"),
            flow("POST", "https", "b.com", 404, "text/html", b"nope"),
            flow("GET", "http", "a.com", 301, "text/html", b""),
        ];
        let s = aggregate(&flows);
        assert_eq!(s.total, 4);
        assert_eq!(s.https, 3);
        assert_eq!(s.http, 1);
        assert_eq!(s.total_resp_bytes, 6 + 2 + 4);
        // 方法:GET 3 在前,POST 1。
        assert_eq!(s.by_method[0], CountBar { label: "GET".into(), count: 3 });
        // 状态段:2xx 2、3xx 1、4xx 1。
        let twoxx = s.by_status.iter().find(|b| b.label == "2xx").unwrap();
        assert_eq!(twoxx.count, 2);
        // 主机:a.com 3 在前。
        assert_eq!(s.by_host[0], CountBar { label: "a.com".into(), count: 3 });
        // 类型:HTML 3、JSON 1。
        let html = s.by_type.iter().find(|b| b.label == "HTML").unwrap();
        assert_eq!(html.count, 3);
    }

    #[test]
    fn aggregate_empty_is_zero() {
        let s = aggregate(&[]);
        assert_eq!(s.total, 0);
        assert!(s.by_method.is_empty());
    }
}
