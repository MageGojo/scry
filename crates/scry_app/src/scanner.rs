//! Scanner 页:对已抓到的流跑**被动扫描**(同步、纯函数),并可发起**主动扫描**(后台 replay
//! 逐个发探测请求 → 命中判定)。结果按严重度彩色分组列出,可按严重度过滤。
//!
//! async 桥接同 Repeater:`replay::send` 丢到 `background_executor` 线程上的临时 current-thread
//! runtime 里 `block_on` 串行驱动,完成后 `cx.spawn` 回主线程合并 findings。

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use mage_ui::prelude::*;
use scry_core::HttpFlow;
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};
use scry_scan::{Finding, Severity};

use crate::logger::LogLevel;
use crate::state::{ScanMsg, ScryApp};
use crate::widgets::divider;

/// 主动扫描单次最多发的探测数(防对目标狂轰;每个含查询参数的流产 3×参数 个探测)。
const ACTIVE_PROBE_CAP: usize = 120;

/// 敏感文件扫描:单次最多探测的目标 origin 数(每个 origin 跑整张高危路径库)。
const DISCOVERY_ORIGIN_CAP: usize = 16;

/// 主动扫描控制位的三态(存于 `AtomicU8`,后台线程逐探测查询)。
const SCAN_RUN: u8 = 0;
const SCAN_PAUSE: u8 = 1;
const SCAN_STOP: u8 = 2;

/// 严重度 → 主题色(Critical/High 红、Medium 黄、Low 青、Info 灰)。
pub fn severity_color(sev: Severity, c: ThemeColors) -> Hsla {
    match sev {
        Severity::Critical | Severity::High => c.danger,
        Severity::Medium => c.warning,
        Severity::Low => c.accent,
        Severity::Info => c.text_subtle,
    }
}

impl ScryApp {
    /// 当前可选的目标 host 列表(去重保序),用于目标下拉。
    pub(crate) fn scan_hosts(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut hosts = Vec::new();
        for f in &self.flows {
            if !f.host.is_empty() && seen.insert(f.host.clone()) {
                hosts.push(f.host.clone());
            }
        }
        hosts
    }

    /// 按当前目标筛出要扫描的流(`scan_target = None` 时为全部)。
    fn scoped_flows(&self) -> Vec<HttpFlow> {
        match &self.scan_target {
            Some(host) => self.flows.iter().filter(|f| &f.host == host).cloned().collect(),
            None => self.flows.clone(),
        }
    }

    /// 当前目标的中文/英文展示名(用于日志与提示)。
    fn scan_target_label(&self) -> String {
        match &self.scan_target {
            Some(h) => h.clone(),
            None => self.lang.t("All hosts").to_string(),
        }
    }

    /// 选择扫描目标(下拉 `idx`:0 = 全部,其余对应 host 列表)。
    pub fn set_scan_target(&mut self, idx: usize, cx: &mut Context<Self>) {
        let hosts = self.scan_hosts();
        self.scan_target = if idx == 0 {
            None
        } else {
            hosts.get(idx - 1).cloned()
        };
        self.scan_target_open = false;
        cx.notify();
    }

    /// 被动扫描:对**当前目标**的流跑只读规则(同步,瞬时)。
    pub fn run_passive_scan(&mut self, cx: &mut Context<Self>) {
        let scoped = self.scoped_flows();
        self.scan_findings = scry_scan::scan_flows(&scoped);
        self.scan_ran = true;
        self.scan_progress = None;
        self.push_log(
            LogLevel::Info,
            "scan",
            format!(
                "被动扫描完成 · 目标 {} · {} 条流量 · {} 条发现",
                self.scan_target_label(),
                scoped.len(),
                self.scan_findings.len()
            ),
        );
        cx.notify();
    }

    /// 主动扫描:对**当前目标**里含可注入参数的流生成探测,后台逐个 replay 发送 + 命中判定,
    /// 结果经通道**流式回填**;支持随时暂停 / 继续 / 停止。
    pub fn run_active_scan(&mut self, cx: &mut Context<Self>) {
        if self.scan_busy {
            return;
        }
        let scoped = self.scoped_flows();
        let mut probes: Vec<scry_scan::Probe> = Vec::new();
        for f in &scoped {
            for p in scry_scan::generate_probes(f) {
                probes.push(p);
                if probes.len() >= ACTIVE_PROBE_CAP {
                    break;
                }
            }
            if probes.len() >= ACTIVE_PROBE_CAP {
                break;
            }
        }
        if probes.is_empty() {
            self.push_log(
                LogLevel::Warning,
                "scan",
                format!(
                    "主动扫描跳过:目标 {} 下无可注入的查询参数(需带 ?参数 的请求)",
                    self.scan_target_label()
                ),
            );
            self.scan_progress = Some(
                if self.lang.is_zh() {
                    "无可注入的查询参数(主动扫描需要带 ?参数 的请求)"
                } else {
                    "No injectable query params for active scan"
                }
                .to_string(),
            );
            cx.notify();
            return;
        }

        let total = probes.len();
        self.scan_busy = true;
        self.scan_paused = false;
        self.scan_total = total;
        self.scan_done = 0;
        self.scan_ran = true;
        self.scan_progress = Some(format!("0 / {total}"));
        self.push_log(
            LogLevel::Info,
            "scan",
            format!(
                "主动扫描开始 · 目标 {} · {total} 个探测请求",
                self.scan_target_label()
            ),
        );

        let up = self.upstream_proxy(cx);
        let ctrl = Arc::new(AtomicU8::new(SCAN_RUN));
        self.scan_ctrl = Some(ctrl.clone());
        let (tx, rx) = mpsc::channel::<ScanMsg>();
        self.scan_rx = Some(rx);
        cx.notify();

        // 后台:临时 current-thread runtime 串行发探测;每条前查控制位(暂停则挂起、停止则退出),
        // 每条完成即经通道流式回传(含累计完成数 + 可选发现)。
        cx.background_executor()
            .spawn(async move {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => return,
                };
                rt.block_on(async move {
                    let cfg = ReplayConfig {
                        upstream: up,
                        ..Default::default()
                    };
                    for (i, probe) in probes.iter().enumerate() {
                        // 控制位:暂停 → 轮询挂起;停止 → 立即退出。
                        loop {
                            match ctrl.load(Ordering::Relaxed) {
                                SCAN_STOP => return,
                                SCAN_PAUSE => {
                                    tokio::time::sleep(Duration::from_millis(120)).await;
                                }
                                _ => break,
                            }
                        }
                        let req = ReplayRequest::from_flow(&probe.flow);
                        let finding = match replay::send(&req, &cfg).await {
                            Ok(resp) => scry_scan::evaluate(probe, &resp),
                            Err(_) => None,
                        };
                        // 接收端已丢弃(用户点了停止)→ 结束。
                        if tx.send(ScanMsg { done: i + 1, finding }).is_err() {
                            return;
                        }
                    }
                });
            })
            .detach();

        // 前台轮询:把陆续到达的发现并入列表、更新进度;全部到齐即收尾。
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(120))
                    .await;
                let keep_going = this.update(cx, |this, cx| {
                    this.drain_scan_results();
                    cx.notify();
                    this.scan_busy
                });
                match keep_going {
                    Ok(true) => continue,
                    _ => break,
                }
            }
        })
        .detach();
    }

    /// 敏感文件 / 路径扫描(**Nikto 式**):对当前目标的各 origin 请求内置高危路径库
    /// (`.git` / `.env` / 备份 / Actuator / swagger 等)。每个 origin **先取一个 soft-404 基线**
    /// 再逐路径探测,命中经通道流式回填;复用主动扫描同一套暂停 / 停止 / 进度机制。
    pub fn run_discovery_scan(&mut self, cx: &mut Context<Self>) {
        if self.scan_busy {
            return;
        }
        let scoped = self.scoped_flows();
        let mut origins = scry_scan::discovery::origins(&scoped);
        origins.truncate(DISCOVERY_ORIGIN_CAP);
        if origins.is_empty() {
            self.push_log(
                LogLevel::Warning,
                "scan",
                format!(
                    "敏感文件扫描跳过:目标 {} 下无可探测的 origin(先抓点流量再扫)",
                    self.scan_target_label()
                ),
            );
            self.scan_progress = Some(
                if self.lang.is_zh() {
                    "无目标 origin(先抓点流量再扫)"
                } else {
                    "No target origins (capture some traffic first)"
                }
                .to_string(),
            );
            cx.notify();
            return;
        }

        let paths = scry_scan::discovery::PATHS;
        let per = paths.len();
        let total = origins.len() * per;

        self.scan_busy = true;
        self.scan_paused = false;
        self.scan_total = total;
        self.scan_done = 0;
        self.scan_ran = true;
        self.scan_progress = Some(format!("0 / {total}"));
        self.push_log(
            LogLevel::Info,
            "scan",
            format!(
                "敏感文件扫描开始 · 目标 {} · {} 个 origin × {per} 条路径 · 共 {total} 个探测",
                self.scan_target_label(),
                origins.len()
            ),
        );

        let up = self.upstream_proxy(cx);
        let ctrl = Arc::new(AtomicU8::new(SCAN_RUN));
        self.scan_ctrl = Some(ctrl.clone());
        let (tx, rx) = mpsc::channel::<ScanMsg>();
        self.scan_rx = Some(rx);
        cx.notify();

        // 后台:每个 origin 先发一个基线请求(soft-404),再逐条发高危路径探测;
        // 每条前查控制位(暂停挂起 / 停止退出),完成即经通道流式回传。
        cx.background_executor()
            .spawn(async move {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => return,
                };
                rt.block_on(async move {
                    let cfg = ReplayConfig {
                        upstream: up,
                        ..Default::default()
                    };
                    let mut done = 0usize;
                    for o in &origins {
                        // origin 间也响应停止 / 暂停。
                        loop {
                            match ctrl.load(Ordering::Relaxed) {
                                SCAN_STOP => return,
                                SCAN_PAUSE => {
                                    tokio::time::sleep(Duration::from_millis(120)).await
                                }
                                _ => break,
                            }
                        }
                        // soft-404 基线(不计入进度;失败则该 origin 不做基线压制)。
                        let baseline = {
                            let bflow = scry_scan::discovery::probe_flow(
                                o,
                                scry_scan::discovery::baseline_path(),
                            );
                            let req = ReplayRequest::from_flow(&bflow);
                            match replay::send(&req, &cfg).await {
                                Ok(resp) => Some(scry_scan::discovery::build_baseline(&resp)),
                                Err(_) => None,
                            }
                        };
                        for entry in paths {
                            loop {
                                match ctrl.load(Ordering::Relaxed) {
                                    SCAN_STOP => return,
                                    SCAN_PAUSE => {
                                        tokio::time::sleep(Duration::from_millis(120)).await
                                    }
                                    _ => break,
                                }
                            }
                            let pflow = scry_scan::discovery::probe_flow(o, entry.path);
                            let req = ReplayRequest::from_flow(&pflow);
                            let finding = match replay::send(&req, &cfg).await {
                                Ok(resp) => scry_scan::discovery::evaluate_path(
                                    entry,
                                    &resp,
                                    baseline.as_ref(),
                                ),
                                Err(_) => None,
                            };
                            done += 1;
                            if tx.send(ScanMsg { done, finding }).is_err() {
                                return;
                            }
                        }
                    }
                });
            })
            .detach();

        // 前台轮询:并入发现、刷新进度,全部到齐即收尾(与主动扫描共用)。
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(120))
                    .await;
                let keep_going = this.update(cx, |this, cx| {
                    this.drain_scan_results();
                    cx.notify();
                    this.scan_busy
                });
                match keep_going {
                    Ok(true) => continue,
                    _ => break,
                }
            }
        })
        .detach();
    }

    /// 暂停 / 继续主动扫描(切换控制位;暂停时后台挂起、进度冻结)。
    pub fn toggle_scan_pause(&mut self, cx: &mut Context<Self>) {
        if !self.scan_busy {
            return;
        }
        let Some(ctrl) = &self.scan_ctrl else {
            return;
        };
        if self.scan_paused {
            ctrl.store(SCAN_RUN, Ordering::Relaxed);
            self.scan_paused = false;
            self.push_log(LogLevel::Info, "scan", "主动扫描已继续");
        } else {
            ctrl.store(SCAN_PAUSE, Ordering::Relaxed);
            self.scan_paused = true;
            self.push_log(LogLevel::Info, "scan", "主动扫描已暂停");
        }
        self.scan_progress = Some(self.scan_progress_text());
        cx.notify();
    }

    /// 停止主动扫描(置停止位 + 丢弃接收端;停在已到结果)。
    pub fn stop_active_scan(&mut self, cx: &mut Context<Self>) {
        if !self.scan_busy {
            return;
        }
        if let Some(ctrl) = &self.scan_ctrl {
            ctrl.store(SCAN_STOP, Ordering::Relaxed);
        }
        self.scan_busy = false;
        self.scan_paused = false;
        self.scan_rx = None;
        self.scan_ctrl = None;
        self.scan_progress = Some(self.scan_progress_text());
        self.push_log(
            LogLevel::Warning,
            "scan",
            format!("主动扫描已停止 · {} / {}", self.scan_done, self.scan_total),
        );
        cx.notify();
    }

    /// 把通道里已到的发现并入列表、刷新进度;全部到齐则收尾。
    fn drain_scan_results(&mut self) {
        let Some(rx) = &self.scan_rx else {
            return;
        };
        let mut new_findings: Vec<Finding> = Vec::new();
        let mut got = false;
        while let Ok(msg) = rx.try_recv() {
            self.scan_done = msg.done;
            if let Some(f) = msg.finding {
                new_findings.push(f);
            }
            got = true;
        }
        if !new_findings.is_empty() {
            self.scan_findings.extend(new_findings);
            merge_sort_findings(&mut self.scan_findings);
        }
        let done = self.scan_total > 0 && self.scan_done >= self.scan_total;
        if got || done {
            self.scan_progress = Some(self.scan_progress_text());
        }
        if done {
            self.scan_busy = false;
            self.scan_paused = false;
            self.scan_rx = None;
            self.scan_ctrl = None;
            self.push_log(
                LogLevel::Success,
                "scan",
                format!(
                    "扫描完成 · 目标 {} · 共 {} 条发现",
                    self.scan_target_label(),
                    self.scan_findings.len()
                ),
            );
        }
    }

    /// 进度文案(带 暂停 / 停止 后缀)。
    fn scan_progress_text(&self) -> String {
        let base = format!("{} / {}", self.scan_done, self.scan_total);
        if self.scan_paused {
            let suffix = if self.lang.is_zh() { "(已暂停)" } else { " (paused)" };
            format!("{base}{suffix}")
        } else if !self.scan_busy && self.scan_done < self.scan_total {
            let suffix = if self.lang.is_zh() { "(已停止)" } else { " (stopped)" };
            format!("{base}{suffix}")
        } else {
            base
        }
    }

    /// Scanner 页主体。
    pub fn scanner_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let shown: Vec<&Finding> = self
            .scan_findings
            .iter()
            .filter(|f| self.scan_filter.map(|s| s == f.severity).unwrap_or(true))
            .collect();

        // ── 工具条:目标选择 + 扫描按钮(暂停/停止)+ 进度 ──
        // 目标 host 下拉:第 0 项「全部 host」,其余为抓到的各 host。
        let hosts = self.scan_hosts();
        let mut target_opts: Vec<SharedString> = vec![self.lang.t("All hosts")];
        target_opts.extend(hosts.iter().cloned().map(SharedString::from));
        let target_idx = match &self.scan_target {
            None => 0,
            Some(h) => hosts.iter().position(|x| x == h).map(|p| p + 1).unwrap_or(0),
        };
        let view_t = cx.entity();
        let view_s = cx.entity();
        let target_select = Select::new("scan-target", target_opts, target_idx)
            .width(px(240.0))
            .open(self.scan_target_open)
            .on_toggle(move |_e, _w, app| {
                view_t.update(app, |this, cx| {
                    this.scan_target_open = !this.scan_target_open;
                    cx.notify();
                });
            })
            .on_select(move |i, _e, _w, app| {
                view_s.update(app, |this, cx| this.set_scan_target(i, cx));
            });
        let target_group = div()
            .flex()
            .items_center()
            .gap(px(6.0))
            .flex_shrink_0()
            .child(Icon::new(IconName::Globe).size(px(15.0)).color(c.text_subtle))
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("Target")),
            )
            .child(target_select);

        let passive_btn = Button::new("scan-passive", self.lang.t("Passive scan"))
            .variant(ButtonVariant::Primary)
            .size(ButtonSize::Sm)
            .icon(IconName::Search)
            .on_click(cx.listener(|this, _e, _w, cx| this.run_passive_scan(cx)));

        // 控制按钮:空闲 → 主动扫描;进行中 → 暂停/继续 + 停止。
        let mut controls = div().flex().items_center().gap(t.space.sm).child(passive_btn);
        if self.scan_busy {
            let pause_label = if self.scan_paused {
                self.lang.t("Resume")
            } else {
                self.lang.t("Pause")
            };
            controls = controls
                .child(
                    Button::new("scan-pause", pause_label)
                        .variant(ButtonVariant::Ghost)
                        .size(ButtonSize::Sm)
                        .icon(if self.scan_paused {
                            IconName::Zap
                        } else {
                            IconName::Box
                        })
                        .on_click(cx.listener(|this, _e, _w, cx| this.toggle_scan_pause(cx))),
                )
                .child(
                    Button::new("scan-stop", self.lang.t("Stop"))
                        .variant(ButtonVariant::Danger)
                        .size(ButtonSize::Sm)
                        .icon(IconName::Box)
                        .on_click(cx.listener(|this, _e, _w, cx| this.stop_active_scan(cx))),
                );
        } else {
            controls = controls
                .child(
                    Button::new("scan-active", self.lang.t("Active scan"))
                        .variant(ButtonVariant::Danger)
                        .size(ButtonSize::Sm)
                        .icon(IconName::Zap)
                        .on_click(cx.listener(|this, _e, _w, cx| this.run_active_scan(cx))),
                )
                .child(
                    Button::new("scan-discovery", self.lang.t("Sensitive files"))
                        .variant(ButtonVariant::Ghost)
                        .size(ButtonSize::Sm)
                        .icon(IconName::Folder)
                        .on_click(cx.listener(|this, _e, _w, cx| this.run_discovery_scan(cx))),
                );
        }

        let mut toolbar = div()
            .flex()
            .items_center()
            .gap(t.space.md)
            .flex_shrink_0()
            .child(target_group)
            .child(controls);
        if let Some(prog) = &self.scan_progress {
            toolbar = toolbar.child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(if self.scan_busy { c.warning } else { c.text_muted })
                    .child(prog.clone()),
            );
        }

        // ── 严重度统计 chip(All + 各级,带计数,可过滤)──
        let total = self.scan_findings.len();
        let all_chip = Chip::new("sev-all", format!("{} {}", self.lang.t("All"), total))
            .active(self.scan_filter.is_none())
            .on_click(cx.listener(|this, _e, _w, cx| {
                this.scan_filter = None;
                cx.notify();
            }));
        let mut chips = div().flex().items_center().gap(px(4.0)).child(all_chip);
        for sev in Severity::ALL_DESC {
            let n = self.scan_findings.iter().filter(|f| f.severity == sev).count();
            if n == 0 {
                continue;
            }
            let label = format!("{} {}", self.lang.t(sev.label()), n);
            chips = chips.child(
                Chip::new(SharedString::from(format!("sev-{}", sev.label())), label)
                    .active(self.scan_filter == Some(sev))
                    .on_click(cx.listener(move |this, _e, _w, cx| {
                        this.scan_filter = Some(sev);
                        cx.notify();
                    })),
            );
        }

        let header = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.md)
            .flex_shrink_0()
            .child(toolbar)
            .child(chips);

        // ── 结果区 ──
        let body = if !self.scan_ran {
            EmptyState::new(self.lang.t("Run a scan to find issues"))
                .icon(IconName::Search)
                .into_any_element()
        } else if shown.is_empty() {
            EmptyState::new(self.lang.t("No issues found")).icon(IconName::Check).into_any_element()
        } else {
            let mut list = div()
                .id("scan-list")
                .flex_1()
                .min_h(px(0.0))
                .overflow_y_scroll()
                .flex()
                .flex_col()
                .gap(t.space.sm);
            for f in shown {
                list = list.child(finding_card(f, self.lang, c, t));
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
            .child(header)
            .child(divider(c))
            .child(body)
    }

}

/// 合并后去重 + 排序(被动 + 主动 findings 统一口径)。
fn merge_sort_findings(v: &mut Vec<Finding>) {
    v.sort_by(|a, b| (a.rule_id, &a.url).cmp(&(b.rule_id, &b.url)));
    v.dedup_by(|a, b| a.rule_id == b.rule_id && a.url == b.url);
    v.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.url.cmp(&b.url)));
}

/// 单条发现卡片:严重度徽标 + 标题 + 详情 + URL。
pub(crate) fn finding_card(
    f: &Finding,
    lang: crate::i18n::Lang,
    c: ThemeColors,
    t: Tokens,
) -> impl IntoElement {
    let sev_color = crate::scanner::severity_color(f.severity, c);
    div()
        .flex()
        .flex_col()
        .gap(px(4.0))
        .flex_shrink_0()
        .p(t.space.sm)
        .rounded(t.radius.lg)
        .bg(c.surface)
        .border_1()
        .border_color(c.border)
        .child(
            div()
                .flex()
                .items_center()
                .gap(t.space.sm)
                .child(Badge::new(lang.t(f.severity.label()), sev_color))
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.0))
                        .text_size(t.font_size.sm)
                        .text_color(c.text)
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(lang.t(f.title)),
                ),
        )
        .child(
            div()
                .text_size(t.font_size.xs)
                .text_color(c.text_muted)
                .child(f.detail.clone()),
        )
        .child(
            div()
                .font_family(crate::model::MONO)
                .min_w(px(0.0))
                .truncate()
                .text_size(t.font_size.xs)
                .text_color(c.text_subtle)
                .child(f.url.clone()),
        )
}

