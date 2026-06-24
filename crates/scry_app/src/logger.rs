//! 事件日志(Logger 页):把抓包 / 扫描 / 证书 / 上游 等运行时事件**实时**记录成一条条带级别
//! 的日志,在顶栏「Logger」页里按级别过滤 / 全文搜索 / 复制 / 清空查看。
//!
//! 设计要点:
//! - 纯数据 [`LogEntry`] + 级别 [`LogLevel`];最新在表头(`insert(0)`,与 history 一致),带上限防膨胀。
//! - [`ScryApp::push_log`] 只改数据不刷新,调用方各自 `cx.notify()`(它们本就要 notify),
//!   这样在 `cx.spawn` 回调 / 同步路径里都能直接埋点。
//! - 过滤 / 搜索 / 格式化是**纯函数**,带单测;不依赖 gpui,便于回归。

use mage_ui::gpui::ClipboardItem;
use mage_ui::prelude::*;
use scry_core::HttpFlow;

use crate::model::{clock_hms, MONO};
use crate::state::ScryApp;
use crate::widgets::divider;

/// 单条日志的级别(决定取色与过滤分组)。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogLevel {
    Error,
    Warning,
    Success,
    Info,
    Debug,
}

impl LogLevel {
    /// 过滤 chip 的展示顺序(高→低)。
    pub const ALL: [LogLevel; 5] = [
        LogLevel::Error,
        LogLevel::Warning,
        LogLevel::Success,
        LogLevel::Info,
        LogLevel::Debug,
    ];

    /// 英文 key(交给 [`crate::i18n::Lang::t`] 翻译;也用于复制导出与搜索匹配)。
    pub fn label(self) -> &'static str {
        match self {
            LogLevel::Error => "Error",
            LogLevel::Warning => "Warning",
            LogLevel::Success => "Success",
            LogLevel::Info => "Info",
            LogLevel::Debug => "Debug",
        }
    }

    /// 级别 → 主题语义色。
    pub fn color(self, c: ThemeColors) -> Hsla {
        match self {
            LogLevel::Error => c.danger,
            LogLevel::Warning => c.warning,
            LogLevel::Success => c.success,
            LogLevel::Info => c.accent,
            LogLevel::Debug => c.text_subtle,
        }
    }
}

/// 一条事件日志。`ts` 为 Unix 毫秒;`source` 是来源模块(capture / cert / scan / flow / system …)。
#[derive(Clone, Debug)]
pub struct LogEntry {
    pub ts: i64,
    pub level: LogLevel,
    pub source: SharedString,
    pub message: String,
}

impl LogEntry {
    /// 以「当前时间」新建一条日志。
    pub fn new(level: LogLevel, source: &str, message: impl Into<String>) -> Self {
        LogEntry {
            ts: now_millis(),
            level,
            source: SharedString::from(source.to_string()),
            message: message.into(),
        }
    }
}

/// 当前 Unix 毫秒时间戳。
fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 启动时的初始日志(一条):告知应用已启动,并区分是否为演示数据。
pub fn initial_logs(demo: bool) -> Vec<LogEntry> {
    let msg = if demo {
        "Scry 启动 · 当前为演示数据,点「开始抓包」后显示真实流量"
    } else {
        "Scry 启动 · 已载入历史流量"
    };
    vec![LogEntry::new(LogLevel::Info, "system", msg)]
}

/// 一条日志是否命中搜索词(已小写化);匹配 message / source / 级别名,大小写不敏感。
fn entry_matches(e: &LogEntry, q_lower: &str) -> bool {
    if q_lower.is_empty() {
        return true;
    }
    e.message.to_lowercase().contains(q_lower)
        || e.source.to_lowercase().contains(q_lower)
        || e.level.label().to_lowercase().contains(q_lower)
}

/// 把一条日志格式化成一行文本(复制 / 导出用):`HH:MM:SS [Level] source message`。
fn format_entry_line(e: &LogEntry) -> String {
    format!(
        "{} [{}] {} {}",
        clock_hms(e.ts),
        e.level.label(),
        e.source,
        e.message
    )
}

impl ScryApp {
    /// 追加一条事件日志(最新在表头)。**不**调用 `cx.notify()` —— 调用方负责刷新。
    pub fn push_log(&mut self, level: LogLevel, source: &str, message: impl Into<String>) {
        const MAX: usize = 1000; // 上限,防内存无限增长
        self.logs.insert(0, LogEntry::new(level, source, message));
        if self.logs.len() > MAX {
            self.logs.truncate(MAX);
        }
    }

    /// 把一条新抓到的流量记成日志(级别随状态码:5xx 错误 / 4xx 警告 / 其余成功;未完成为信息)。
    pub fn push_flow_log(&mut self, f: &HttpFlow) {
        let level = match f.status {
            0 => LogLevel::Info,
            s if s >= 500 => LogLevel::Error,
            s if s >= 400 => LogLevel::Warning,
            _ => LogLevel::Success,
        };
        let status = if f.status == 0 {
            "…".to_string()
        } else {
            f.status.to_string()
        };
        self.push_log(level, "flow", format!("{} {} → {}", f.method, f.url(), status));
    }

    /// Logger 页主体:工具条(级别过滤 chip + 搜索 + 复制 + 清空)+ 日志列表。
    pub fn logger_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;
        let l = self.lang;

        let query = self.log_search.read(cx).text().trim().to_lowercase();
        let shown: Vec<&LogEntry> = self
            .logs
            .iter()
            .filter(|e| self.log_filter.map(|lv| lv == e.level).unwrap_or(true))
            .filter(|e| entry_matches(e, &query))
            .collect();

        // ── 级别过滤 chips(All + 各级,带计数,仅显示出现过的级别)──
        let total = self.logs.len();
        let all_chip = Chip::new("log-all", format!("{} {}", l.t("All"), total))
            .active(self.log_filter.is_none())
            .on_click(cx.listener(|this, _e, _w, cx| {
                this.log_filter = None;
                cx.notify();
            }));
        let mut chips = div().flex().items_center().gap(px(4.0)).child(all_chip);
        for lv in LogLevel::ALL {
            let n = self.logs.iter().filter(|e| e.level == lv).count();
            if n == 0 {
                continue;
            }
            let label = format!("{} {}", l.t(lv.label()), n);
            chips = chips.child(
                Chip::new(SharedString::from(format!("log-{}", lv.label())), label)
                    .active(self.log_filter == Some(lv))
                    .on_click(cx.listener(move |this, _e, _w, cx| {
                        this.log_filter = Some(lv);
                        cx.notify();
                    })),
            );
        }

        // ── 搜索框 + 复制 + 清空 ──
        let search_box = div()
            .flex_1()
            .min_w(px(0.0))
            .flex()
            .items_center()
            .gap(t.space.sm)
            .child(Icon::new(IconName::Search).size(px(15.0)).color(c.text_subtle))
            .child(div().flex_1().min_w(px(0.0)).child(self.log_search.clone()));

        let copy_btn = Button::new("log-copy", l.t("Copy all"))
            .ghost()
            .size(ButtonSize::Sm)
            .icon(IconName::Copy)
            .on_click(cx.listener(|this, _e, _w, cx| {
                if this.logs.is_empty() {
                    return;
                }
                // 复制按时间正序(最旧在前),便于阅读。
                let text = this
                    .logs
                    .iter()
                    .rev()
                    .map(format_entry_line)
                    .collect::<Vec<_>>()
                    .join("\n");
                cx.write_to_clipboard(ClipboardItem::new_string(text));
                let msg = this.lang.t("Copied to clipboard").to_string();
                this.show_toast(msg, cx);
            }));
        let clear_btn = Button::new("log-clear", l.t("Clear log"))
            .ghost()
            .size(ButtonSize::Sm)
            .icon(IconName::Trash)
            .on_click(cx.listener(|this, _e, _w, cx| {
                this.logs.clear();
                this.log_filter = None;
                cx.notify();
            }));

        let header = div()
            .flex()
            .items_center()
            .gap(t.space.md)
            .flex_shrink_0()
            .child(chips)
            .child(search_box)
            .child(copy_btn)
            .child(clear_btn);

        // ── 日志列表 ──
        let body = if shown.is_empty() {
            let hint = if self.logs.is_empty() {
                l.t("No log entries yet")
            } else {
                l.t("No issues found")
            };
            div()
                .flex_1()
                .flex()
                .flex_col()
                .items_center()
                .justify_center()
                .gap(t.space.md)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_center()
                        .w(px(64.0))
                        .h(px(64.0))
                        .rounded(t.radius.xl)
                        .bg(c.glass)
                        .border_1()
                        .border_color(c.glass_border)
                        .child(Icon::new(IconName::Clock).size(px(26.0)).color(c.primary)),
                )
                .child(
                    div()
                        .text_size(t.font_size.sm)
                        .text_color(c.text_subtle)
                        .child(hint),
                )
                .into_any_element()
        } else {
            // 性能:日志行高可变(消息换行),不适合 uniform_list 等高虚拟化;改为**封顶渲染最近 N 条**
            //(最新在表头,看的就是近期),避免上千条全量构建元素导致卡顿。
            const MAX_RENDER: usize = 300;
            let total_shown = shown.len();
            let mut list = div()
                .id("log-list")
                .flex_1()
                .min_h(px(0.0))
                .overflow_y_scroll()
                .flex()
                .flex_col()
                .gap(px(2.0));
            for e in shown.into_iter().take(MAX_RENDER) {
                list = list.child(log_row(e, l, c, t));
            }
            if total_shown > MAX_RENDER {
                list = list.child(
                    div()
                        .flex_shrink_0()
                        .px(t.space.sm)
                        .py(px(6.0))
                        .text_size(t.font_size.xs)
                        .text_color(c.text_subtle)
                        .child(if l.is_zh() {
                            format!("… 仅显示最近 {MAX_RENDER} 条 / 共 {total_shown} 条(搜索可定位更早)")
                        } else {
                            format!("… showing latest {MAX_RENDER} of {total_shown} (use search to find older)")
                        }),
                );
            }
            list.into_any_element()
        };

        div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .gap(t.space.md)
            .p(t.space.lg)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(2.0))
                    .flex_shrink_0()
                    .child(
                        div()
                            .text_size(t.font_size.xl)
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(c.text)
                            .child(l.t("Event Log")),
                    )
                    .child(
                        div()
                            .text_size(t.font_size.sm)
                            .text_color(c.text_subtle)
                            .child(l.t(
                                "Logs are recorded as you capture, scan, and manage certificates.",
                            )),
                    ),
            )
            .child(header)
            .child(divider(c))
            .child(body)
    }
}

/// 单条日志行:时间 + 级别徽标 + 来源 + 消息(等宽,消息可换行)。
fn log_row(e: &LogEntry, lang: crate::i18n::Lang, c: ThemeColors, t: Tokens) -> impl IntoElement {
    let color = e.level.color(c);
    div()
        .flex()
        .items_start()
        .gap(t.space.sm)
        .flex_shrink_0()
        .px(t.space.sm)
        .py(px(5.0))
        .rounded(t.radius.md)
        .border_1()
        .border_color(c.border.opacity(0.5))
        .bg(c.surface.opacity(0.4))
        // 时间(等宽弱化,定宽)
        .child(
            div()
                .w(px(62.0))
                .flex_shrink_0()
                .font_family(MONO)
                .text_size(t.font_size.xs)
                .text_color(c.text_subtle)
                .child(clock_hms(e.ts)),
        )
        // 级别徽标(定宽容器,保证消息列对齐)
        .child(
            div()
                .w(px(78.0))
                .flex_shrink_0()
                .child(Badge::new(lang.t(e.level.label()), color)),
        )
        // 来源(等宽弱化,定宽截断)
        .child(
            div()
                .w(px(64.0))
                .flex_shrink_0()
                .truncate()
                .font_family(MONO)
                .text_size(t.font_size.xs)
                .text_color(c.text_muted)
                .child(e.source.clone()),
        )
        // 消息(占满剩余,允许换行)
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .font_family(MONO)
                .text_size(t.font_size.xs)
                .text_color(c.text)
                .child(e.message.clone()),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(level: LogLevel, source: &str, message: &str) -> LogEntry {
        LogEntry {
            ts: 0,
            level,
            source: SharedString::from(source.to_string()),
            message: message.to_string(),
        }
    }

    #[test]
    fn levels_have_distinct_labels() {
        let mut seen = std::collections::HashSet::new();
        for lv in LogLevel::ALL {
            assert!(seen.insert(lv.label()), "duplicate label: {}", lv.label());
        }
        assert_eq!(LogLevel::ALL.len(), 5);
    }

    #[test]
    fn search_matches_message_source_and_level_case_insensitive() {
        let e = entry(LogLevel::Error, "capture", "端口 8888 被占用");
        assert!(entry_matches(&e, "8888")); // message
        assert!(entry_matches(&e, "capture")); // source
        assert!(entry_matches(&e, "error")); // level label, 小写
        assert!(entry_matches(&e, "")); // 空词放行
        assert!(!entry_matches(&e, "warning")); // 不命中其它级别
    }

    #[test]
    fn format_line_has_time_level_source_message() {
        let e = entry(LogLevel::Success, "cert", "已安装并信任");
        let line = format_entry_line(&e);
        assert_eq!(line, "00:00:00 [Success] cert 已安装并信任");
    }

    #[test]
    fn initial_logs_is_single_info_entry() {
        let demo = initial_logs(true);
        assert_eq!(demo.len(), 1);
        assert_eq!(demo[0].level, LogLevel::Info);
        assert!(demo[0].message.contains("演示"));

        let real = initial_logs(false);
        assert_eq!(real.len(), 1);
        assert_eq!(real[0].level, LogLevel::Info);
        assert!(!real[0].message.contains("演示"));
    }
}
