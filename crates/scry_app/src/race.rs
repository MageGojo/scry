//! Race 页:**HTTP 竞态 / single-packet 攻击**(对标 Burp Repeater「并行发送组」/ Turbo Intruder)。
//!
//! 把一条(可编辑的)请求**同时**发 N 路 —— 默认用 [`RaceMode::LastByteSync`](最后字节同步:
//! 预连接 + 写到只剩最后 1 字节 + barrier 同放扳机,h1 上最可靠的竞态手法),也可切「并行」兜底。
//! 用来打超额提现 / 优惠券复用 / 限购击穿 / TOCTOU 等竞态类漏洞。
//!
//! 发包内核是 [`scry_proxy::race`](纯函数判定 + async 同步发送);UI 沿用越权 / SQLi / XSS 同一条
//! async 路径(后台临时 runtime 驱动 + mpsc 流式回填 + 前台 120ms 轮询)。判定 [`race::summarize`]:
//! 响应**不一致**(状态码或长度不全相同)= 疑似竞态命中,**需人工确认**(竞态偶发)。
//!
//! ⚠️ 会向目标真实并发发包,**只对你已获授权的目标使用**。

use std::sync::mpsc::{self, Sender};
use std::time::Duration;

use mage_ui::prelude::*;
use scry_core::HttpFlow;
use scry_proxy::race::{self, RaceConfig, RaceMode, RaceResult, RACE_MAX};
use scry_proxy::replay::ReplayRequest;
use scry_proxy::upstream::UpstreamProxy;

use crate::logger::LogLevel;
use crate::model;
use crate::repeater::{parse_raw_request, render_raw_request, target_string};
use crate::state::{RaceMsg, ScryApp, SqliLevel, SqliLine};
use crate::widgets::{divider, section_label};

/// 可选并发路数(Segmented 选项)。
const RACE_COUNTS: [usize; 6] = [5, 10, 20, 30, 50, RACE_MAX];
/// 测试日志最多保留行数。
const RACE_LOG_CAP: usize = 400;

// ───────────────────────── 后台 runner ─────────────────────────

fn line(level: SqliLevel, text: impl Into<String>) -> SqliLine {
    SqliLine {
        level,
        text: text.into(),
    }
}

/// 整条竞态流程:并发发 N 路 → 统计 → 流式回传(全程经 `tx`)。
async fn run_race_job(
    req: ReplayRequest,
    count: usize,
    mode: RaceMode,
    upstream: Option<UpstreamProxy>,
    tx: Sender<RaceMsg>,
) {
    let cfg = RaceConfig {
        mode,
        upstream,
        ..Default::default()
    };
    let results = race::run_race(&req, count, &cfg).await;
    let summary = race::summarize(&results);

    // 逐路结果回传为日志行(N ≤ 64,不会刷屏)。
    for r in &results {
        let l = match &r.error {
            Some(e) => line(SqliLevel::Bad, format!("#{} 出错:{e}", r.idx)),
            None => line(
                if (200..300).contains(&r.status) {
                    SqliLevel::Good
                } else {
                    SqliLevel::Info
                },
                format!(
                    "#{} → HTTP {} · {} B · {} ms",
                    r.idx, r.status, r.body_len, r.elapsed_ms
                ),
            ),
        };
        let _ = tx.send(RaceMsg {
            line: Some(l),
            results: None,
            summary: None,
            progress: None,
            done: false,
        });
    }

    let verdict = if summary.diverged {
        "响应有差异(疑似竞态,需人工确认)"
    } else {
        "响应一致(未见明显竞态)"
    };
    let _ = tx.send(RaceMsg {
        line: Some(line(
            if summary.diverged {
                SqliLevel::Bad
            } else {
                SqliLevel::Good
            },
            format!(
                "完成 · {}/{} 成功 · {verdict} · 同步窗口 {} ms",
                summary.ok, summary.total, summary.window_ms
            ),
        )),
        results: Some(results),
        summary: Some(summary),
        progress: Some("完成".into()),
        done: true,
    });
}

// ───────────────────────── UI + 控制 ─────────────────────────

impl ScryApp {
    /// 从一条流带入竞态测试(代理右键「发送到竞态」)。
    pub fn fill_race_from_flow(&mut self, flow: &HttpFlow, cx: &mut Context<Self>) {
        let target = target_string(flow);
        let raw = render_raw_request(flow);
        self.race_target.update(cx, |s, cx| s.set_text(target, cx));
        self.race_req.update(cx, |s, cx| s.set_text(raw, cx));
        self.race_results.clear();
        self.race_summary = None;
        self.race_log.clear();
        self.race_ran = false;
        self.race_progress = None;
    }

    /// 停止竞态(置 busy=false + 丢弃接收端;后台一次性发包很快结束,孤儿任务自行收尾)。
    pub fn stop_race(&mut self, cx: &mut Context<Self>) {
        self.race_busy = false;
        self.race_rx = None;
        self.race_progress = Some(self.lang.t("Stopped").to_string());
        self.push_log(LogLevel::Warning, "race", "竞态测试已停止");
        cx.notify();
    }

    /// 开始竞态测试:解析请求 → 后台并发发 N 路 + 流式回填。
    pub fn start_race(&mut self, cx: &mut Context<Self>) {
        if self.race_busy {
            return;
        }
        let target = self.race_target.read(cx).text().to_string();
        let raw = self.race_req.read(cx).text().to_string();
        let base_req = match parse_raw_request(&target, &raw) {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("请求解析失败:{e}");
                self.race_log = vec![line(SqliLevel::Bad, msg.clone())];
                self.race_progress = Some(msg);
                self.race_ran = true;
                cx.notify();
                return;
            }
        };
        let count = self.race_count.clamp(1, RACE_MAX);
        let mode = if self.race_mode_sync {
            RaceMode::LastByteSync
        } else {
            RaceMode::Parallel
        };
        let up = self.upstream_proxy(cx);

        self.race_busy = true;
        self.race_ran = true;
        self.race_results = Vec::new();
        self.race_summary = None;
        self.race_log = vec![line(
            SqliLevel::Info,
            format!(
                "开始竞态 · {} · {count} 路 · {}",
                base_req.host,
                mode_label(mode, self.lang)
            ),
        )];
        self.race_progress = Some("发送中…".to_string());
        let (tx, rx) = mpsc::channel::<RaceMsg>();
        self.race_rx = Some(rx);
        self.push_log(
            LogLevel::Info,
            "race",
            format!("竞态测试开始 · {} · {count} 路", base_req.host),
        );
        cx.notify();

        // 后台:多线程 runtime 真并发驱动 N 路(单包同步发);worker 数随路数缩放。
        let workers = count.clamp(2, 16);
        cx.background_executor()
            .spawn(async move {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(workers)
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => return,
                };
                rt.block_on(run_race_job(base_req, count, mode, up, tx));
            })
            .detach();

        // 前台轮询:并入日志 / 结果 / 进度,结束即收尾。
        cx.spawn(async move |this, cx| loop {
            cx.background_executor()
                .timer(Duration::from_millis(120))
                .await;
            let keep = this.update(cx, |this, cx| {
                this.drain_race();
                cx.notify();
                this.race_busy
            });
            match keep {
                Ok(true) => continue,
                _ => break,
            }
        })
        .detach();
    }

    /// 排空通道:并入日志 / 结果 / 统计 / 进度;结束则收尾。
    fn drain_race(&mut self) {
        let Some(rx) = &self.race_rx else {
            return;
        };
        let mut done = false;
        while let Ok(msg) = rx.try_recv() {
            if let Some(l) = msg.line {
                self.race_log.push(l);
            }
            if let Some(r) = msg.results {
                self.race_results = r;
            }
            if let Some(s) = msg.summary {
                self.race_summary = Some(s);
            }
            if let Some(p) = msg.progress {
                self.race_progress = Some(p);
            }
            if msg.done {
                done = true;
            }
        }
        if self.race_log.len() > RACE_LOG_CAP {
            let cut = self.race_log.len() - RACE_LOG_CAP;
            self.race_log.drain(0..cut);
        }
        if done {
            self.race_busy = false;
            self.race_rx = None;
            match &self.race_summary {
                Some(s) if s.diverged => self.push_log(
                    LogLevel::Success,
                    "race",
                    format!("竞态测试完成 · 响应有差异(疑似命中,{}/{} 成功)", s.ok, s.total),
                ),
                Some(s) => self.push_log(
                    LogLevel::Info,
                    "race",
                    format!("竞态测试完成 · 响应一致({}/{} 成功)", s.ok, s.total),
                ),
                None => self.push_log(LogLevel::Info, "race", "竞态测试完成"),
            }
        }
    }

    /// 竞态页主体。
    pub fn race_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        // 并发路数(Segmented)。
        let count_idx = RACE_COUNTS
            .iter()
            .position(|n| *n == self.race_count)
            .unwrap_or(2);
        let view_n = cx.entity();
        let count_seg = Segmented::new("race-count")
            .items(RACE_COUNTS.map(|n| SharedString::from(n.to_string())))
            .selected(count_idx)
            .on_select(move |i, _e, _w, app| {
                view_n.update(app, |this, cx| {
                    this.race_count = RACE_COUNTS[i];
                    cx.notify();
                });
            });

        // 发送模式(Segmented:最后字节同步 / 并行)。
        let mode_idx = if self.race_mode_sync { 0 } else { 1 };
        let view_m = cx.entity();
        let mode_seg = Segmented::new("race-mode")
            .items([
                self.lang.t("Last-byte sync"),
                self.lang.t("Parallel"),
            ])
            .selected(mode_idx)
            .on_select(move |i, _e, _w, app| {
                view_m.update(app, |this, cx| {
                    this.race_mode_sync = i == 0;
                    cx.notify();
                });
            });

        let action = if self.race_busy {
            Button::new("race-stop", self.lang.t("Stop"))
                .variant(ButtonVariant::Danger)
                .size(ButtonSize::Sm)
                .icon(IconName::Box)
                .on_click(cx.listener(|this, _e, _w, cx| this.stop_race(cx)))
        } else {
            Button::new("race-start", self.lang.t("Send group"))
                .variant(ButtonVariant::Danger)
                .size(ButtonSize::Sm)
                .icon(IconName::Zap)
                .on_click(cx.listener(|this, _e, _w, cx| this.start_race(cx)))
        };

        let mut toolbar = div()
            .flex()
            .items_center()
            .gap(t.space.md)
            .flex_shrink_0()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .flex_shrink_0()
                    .child(Icon::new(IconName::Zap).size(px(15.0)).color(c.text_subtle))
                    .child(
                        div()
                            .text_size(t.font_size.sm)
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(c.text)
                            .child(self.lang.t("Race / single-packet")),
                    ),
            )
            .child(seg_group(self.lang.t("Requests"), count_seg, c, t))
            .child(seg_group(self.lang.t("Mode"), mode_seg, c, t))
            .child(action);
        if let Some(p) = &self.race_progress {
            toolbar = toolbar.child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(if self.race_busy { c.warning } else { c.text_muted })
                    .child(p.clone()),
            );
        }

        let hint = div()
            .flex_shrink_0()
            .text_size(t.font_size.xs)
            .text_color(c.text_subtle)
            .child(self.lang.t(
                "Fires N identical requests at once (last-byte sync). Diverging responses suggest a race condition — confirm manually. Authorized targets only.",
            ));

        // 左:目标 + 可编辑请求。
        let left = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0))
            .child(section_label(self.lang.t("Target"), c, t))
            .child(self.race_target.clone())
            .child(section_label(self.lang.t("Request"), c, t))
            .child(
                div()
                    .id("race-req-scroll")
                    .flex_1()
                    .min_h(px(0.0))
                    .overflow_y_scroll()
                    .rounded(t.radius.lg)
                    .border_1()
                    .border_color(c.border)
                    .bg(c.surface)
                    .p(t.space.sm)
                    .child(self.race_req.clone()),
            );

        // 右:统计卡 + 结果表 + 日志。
        let mut right = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0));
        if self.race_busy || self.race_ran {
            right = right.child(self.race_summary_card(c, t));
        }
        right = right.child(self.race_results_view(c, t));
        if !self.race_log.is_empty() {
            right = right.child(self.race_log_view(c, t));
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
            .child(hint)
            .child(divider(c))
            .child(body)
    }

    /// 统计卡:总体徽标 + 成功/出错/状态分布/同步窗口。
    fn race_summary_card(&self, c: ThemeColors, t: Tokens) -> AnyElement {
        let (badge_text, badge_color, accent) = match &self.race_summary {
            Some(s) if s.diverged => (self.lang.t("Possible race condition"), c.danger, true),
            Some(_) => (self.lang.t("Responses consistent"), c.success, false),
            None if self.race_busy => (self.lang.t("Sending…"), c.warning, false),
            None => (self.lang.t("Idle"), c.text_subtle, false),
        };

        let mut card = div()
            .flex()
            .flex_col()
            .gap(px(6.0))
            .flex_shrink_0()
            .p(t.space.md)
            .rounded(t.radius.lg)
            .bg(c.surface)
            .border_1()
            .border_color(if accent { c.danger } else { c.border })
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .child(Badge::new(badge_text, badge_color))
                    .child(
                        div()
                            .text_size(t.font_size.sm)
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(c.text)
                            .child(self.lang.t("Race / single-packet")),
                    ),
            );

        if let Some(s) = &self.race_summary {
            let dist = if s.status_counts.is_empty() {
                "—".to_string()
            } else {
                s.status_counts
                    .iter()
                    .map(|(st, n)| format!("{st}×{n}"))
                    .collect::<Vec<_>>()
                    .join(" · ")
            };
            let metrics = format!(
                "{}: {}/{} · {}: {} · {}: {} · {}: {} ms",
                self.lang.t("OK"),
                s.ok,
                s.total,
                self.lang.t("Errors"),
                s.errors,
                self.lang.t("Status"),
                dist,
                self.lang.t("Sync window"),
                s.window_ms,
            );
            card = card.child(
                div()
                    .font_family(crate::model::MONO)
                    .text_size(t.font_size.xs)
                    .text_color(c.text_muted)
                    .child(metrics),
            );
        }
        card.into_any_element()
    }

    /// 结果表:逐路 #idx / 状态 / 长度 / 耗时 /(出错信息)。
    fn race_results_view(&self, c: ThemeColors, t: Tokens) -> AnyElement {
        if self.race_results.is_empty() {
            let (text, icon) = if self.race_ran && !self.race_busy {
                (self.lang.t("No responses"), IconName::Box)
            } else {
                (self.lang.t("Set count and send the group"), IconName::Zap)
            };
            return EmptyState::new(text).icon(icon).into_any_element();
        }
        let mut list = div()
            .id("race-results")
            .flex_1()
            .min_h(px(0.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(px(2.0))
            .p(t.space.sm)
            .rounded(t.radius.lg)
            .bg(c.surface)
            .border_1()
            .border_color(c.border);
        for r in &self.race_results {
            list = list.child(race_result_row(r, c, t));
        }
        list.into_any_element()
    }

    /// 测试日志列表(彩色,最近 300 行)。
    fn race_log_view(&self, c: ThemeColors, t: Tokens) -> impl IntoElement {
        let mut list = div()
            .id("race-log")
            .flex_shrink_0()
            .h(px(140.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(px(2.0))
            .p(t.space.sm)
            .rounded(t.radius.lg)
            .bg(c.surface)
            .border_1()
            .border_color(c.border)
            .font_family(crate::model::MONO);
        let start = self.race_log.len().saturating_sub(300);
        for l in &self.race_log[start..] {
            let col = match l.level {
                SqliLevel::Good => c.success,
                SqliLevel::Warn => c.warning,
                SqliLevel::Bad => c.danger,
                SqliLevel::Info => c.text_muted,
            };
            list = list.child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(col)
                    .child(l.text.clone()),
            );
        }
        list
    }
}

/// 一行结果(#idx / 状态徽标 / 长度 / 耗时 / 出错)。
fn race_result_row(r: &RaceResult, c: ThemeColors, t: Tokens) -> impl IntoElement {
    let mut row = div()
        .flex()
        .items_center()
        .gap(t.space.sm)
        .font_family(crate::model::MONO)
        .child(
            div()
                .w(px(44.0))
                .flex_shrink_0()
                .text_size(t.font_size.xs)
                .text_color(c.text_subtle)
                .child(format!("#{}", r.idx)),
        );
    if let Some(e) = &r.error {
        row = row.child(Badge::new("ERR", c.danger)).child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .text_size(t.font_size.xs)
                .text_color(c.text_muted)
                .child(e.clone()),
        );
    } else {
        row = row
            .child(Badge::new(
                r.status.to_string(),
                model::status_color(r.status, c),
            ))
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(format!("{} B · {} ms", r.body_len, r.elapsed_ms)),
            );
    }
    row
}

/// 把「标签 + Segmented」组成一组(标签在左、控件在右)。
fn seg_group(label: SharedString, seg: Segmented, c: ThemeColors, t: Tokens) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .gap(px(6.0))
        .flex_shrink_0()
        .child(
            div()
                .text_size(t.font_size.xs)
                .text_color(c.text_subtle)
                .child(label),
        )
        .child(seg)
}

/// 模式 → 界面标签。
fn mode_label(mode: RaceMode, lang: crate::i18n::Lang) -> SharedString {
    match mode {
        RaceMode::LastByteSync => lang.t("Last-byte sync"),
        RaceMode::Parallel => lang.t("Parallel"),
    }
}
