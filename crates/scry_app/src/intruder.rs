//! 爆破页(对标 Burp Intruder):在请求模板里用 `§…§` 标记注入点 → 给一组载荷 → 按
//! 攻击模式批量发包 → 结果表(状态 / 长度 / 耗时)流式回填,点行看响应。
//!
//! 分层(沿用本项目「纯函数 + 单测」纪律):
//! - 引擎([`Template`] / [`build_jobs`] / [`auto_mark`] / [`fix_content_length`])是无 IO 纯函数,带单测;
//! - UI([`ScryApp::intruder_content`])无状态,经 `cx.listener` 回写 [`ScryApp`];
//! - 发包复用 [`scry_proxy::replay`] 与 Repeater 的报文解析,async 桥接同 Scanner:后台
//!   `background_executor` 线程上的临时 current-thread runtime 串行驱动,**每条结果经 mpsc 通道
//!   流式回主线程**(边打边出,不必等全部完成)。

use std::sync::mpsc;
use std::time::Duration;

use futures::stream::StreamExt;
use mage_ui::gpui::MouseButton;
use mage_ui::prelude::*;
use regex::Regex;
use scry_core::HttpFlow;
use scry_proxy::replay::{self, ReplayConfig, ReplayRequest};

use crate::model::{human_len, status_color, MONO};
use crate::repeater::{build_resp_view, parse_raw_request, render_raw_request, resp_view_sig, target_string};
use crate::state::{AttackMode, AttackResult, MsgView, PayloadKind, ProcOp, ScryApp, SortBy};
use crate::widgets::divider;

/// 注入点标记字符(同 Burp 的 `§`;mac 上 `⌥6` 可打出)。
pub const MARKER: char = '§';

/// 单次爆破最多发的请求数(防 cluster bomb 组合爆炸 / 误对目标狂轰)。
pub const ATTACK_CAP: usize = 1000;

// ── 引擎:请求模板(§标记§)─────────────────────────────────────────

/// 把带 `§…§` 标记的请求文本拆成「字面段」+「注入点原始值」。
///
/// 不变式:`literals.len() == originals.len() + 1`;重建即
/// `literals[0] + v[0] + literals[1] + v[1] + … + literals[n]`。容错:落单的开标记(无闭合)
/// 当普通文本并回退,不会丢字符。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Template {
    literals: Vec<String>,
    originals: Vec<String>,
}

impl Template {
    /// 解析模板文本。
    pub fn parse(raw: &str) -> Self {
        let mut literals: Vec<String> = Vec::new();
        let mut originals: Vec<String> = Vec::new();
        let mut buf = String::new();
        let mut marker = String::new();
        let mut in_marker = false;

        for ch in raw.chars() {
            if ch == MARKER {
                if in_marker {
                    // 闭标记 → 收下一个注入点。
                    originals.push(std::mem::take(&mut marker));
                    in_marker = false;
                } else {
                    // 开标记 → 结束当前字面段。
                    literals.push(std::mem::take(&mut buf));
                    in_marker = true;
                }
            } else if in_marker {
                marker.push(ch);
            } else {
                buf.push(ch);
            }
        }

        if in_marker {
            // 落单开标记:把 `§ + 已收字符` 折回上一段字面,不当注入点。
            let mut restored = literals.pop().unwrap_or_default();
            restored.push(MARKER);
            restored.push_str(&marker);
            literals.push(restored);
        } else {
            literals.push(buf);
        }

        Template { literals, originals }
    }

    /// 注入点数量。
    pub fn position_count(&self) -> usize {
        self.originals.len()
    }

    /// 各注入点的原始值(去标记后的本来内容)。
    pub fn originals(&self) -> &[String] {
        &self.originals
    }

    /// 用给定每个注入点的值重建请求文本(缺省位用空串)。
    pub fn render(&self, values: &[String]) -> String {
        let mut s = String::new();
        for (i, lit) in self.literals.iter().enumerate() {
            s.push_str(lit);
            if let Some(v) = values.get(i) {
                s.push_str(v);
            }
        }
        s
    }

    /// 去掉标记、还原成原始请求文本(各注入点填回原始值)。
    pub fn original(&self) -> String {
        self.render(&self.originals)
    }
}

// ── 引擎:攻击作业生成 ───────────────────────────────────────────

/// 一条待发作业:每个注入点要填的值 + 展示用标签 + (狙击手模式下)命中的位置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttackJob {
    pub values: Vec<String>,
    pub label: String,
    pub position: Option<usize>,
}

/// 取第 `p` 个注入点对应的载荷块:块数足够则用各自的块,否则回退到最后一块
/// (即「单块」时所有注入点共用同一份,与历史行为一致)。
fn block_for(blocks: &[Vec<String>], p: usize) -> &[String] {
    if blocks.is_empty() {
        return &[];
    }
    &blocks[p.min(blocks.len() - 1)]
}

/// 按攻击模式 + **每注入点载荷块**生成作业列表(总数封顶 `cap`)。
///
/// `blocks` 每个元素是一个注入点的载荷集;单块 = 所有注入点共用。
/// - **Sniper**:逐个注入点轮流注入(用该点的块),其余位保持原值;
/// - **BatteringRam**:同一载荷灌进所有注入点(多块合并为一份);
/// - **ClusterBomb**:各注入点用**各自的块**做笛卡尔积(易爆炸,靠 `cap` 兜底)。
pub(crate) fn build_jobs(
    tmpl: &Template,
    blocks: &[Vec<String>],
    mode: AttackMode,
    cap: usize,
) -> Vec<AttackJob> {
    let n = tmpl.position_count();
    if n == 0 || blocks.is_empty() || cap == 0 {
        return Vec::new();
    }
    let orig = tmpl.originals().to_vec();
    let mut jobs: Vec<AttackJob> = Vec::new();

    match mode {
        AttackMode::Sniper => {
            for p in 0..n {
                for pl in block_for(blocks, p) {
                    let mut values = orig.clone();
                    values[p] = pl.clone();
                    jobs.push(AttackJob {
                        values,
                        label: pl.clone(),
                        position: Some(p),
                    });
                    if jobs.len() >= cap {
                        return jobs;
                    }
                }
            }
        }
        AttackMode::BatteringRam => {
            for pl in blocks.iter().flatten() {
                jobs.push(AttackJob {
                    values: vec![pl.clone(); n],
                    label: pl.clone(),
                    position: None,
                });
                if jobs.len() >= cap {
                    return jobs;
                }
            }
        }
        AttackMode::ClusterBomb => {
            let lists: Vec<&[String]> = (0..n).map(|p| block_for(blocks, p)).collect();
            if lists.iter().any(|l| l.is_empty()) {
                return jobs;
            }
            let mut idx = vec![0usize; n];
            'outer: loop {
                let values: Vec<String> = (0..n).map(|p| lists[p][idx[p]].clone()).collect();
                jobs.push(AttackJob {
                    label: values.join(", "),
                    values,
                    position: None,
                });
                if jobs.len() >= cap {
                    break;
                }
                // 各位置按各自块大小做混合进制里程表自增,全溢出即枚举完毕。
                let mut pos = n;
                loop {
                    if pos == 0 {
                        break 'outer;
                    }
                    pos -= 1;
                    idx[pos] += 1;
                    if idx[pos] < lists[pos].len() {
                        break;
                    }
                    idx[pos] = 0;
                }
            }
        }
    }

    jobs
}

/// 预估总请求数(用于界面展示,未封顶)。
pub(crate) fn attack_total(mode: AttackMode, positions: usize, payloads: usize) -> usize {
    if positions == 0 || payloads == 0 {
        return 0;
    }
    match mode {
        AttackMode::Sniper => positions.saturating_mul(payloads),
        AttackMode::BatteringRam => payloads,
        AttackMode::ClusterBomb => payloads.checked_pow(positions as u32).unwrap_or(usize::MAX),
    }
}

// ── 引擎:载荷生成器 + 处理器 ─────────────────────────────────────

/// 物化载荷的硬上限(防字符集暴破 / 大数字区间炸内存;作业数另受 [`ATTACK_CAP`] 限制)。
pub const GEN_CAP: usize = 5000;

/// 载荷生成配置(从 UI 各输入框读出后打包,交纯函数生成,便于单测)。
#[derive(Debug, Clone, Copy)]
pub(crate) struct GenSpec<'a> {
    pub kind: PayloadKind,
    /// 列表来源:每行一个。
    pub list: &'a str,
    /// 数字区间串:`from-to[:step]`。
    pub numbers: &'a str,
    /// 字符集暴破:字符集。
    pub charset: &'a str,
    /// 字符集暴破:长度区间 `min-max`。
    pub lengths: &'a str,
    /// 处理器位掩码(见 [`ProcOp::bit`])。
    pub mask: u16,
    /// 处理器前缀。
    pub prefix: &'a str,
    /// 处理器后缀。
    pub suffix: &'a str,
}

impl GenSpec<'_> {
    /// 基础载荷条数(施加处理器前;未封顶,溢出饱和)。用于界面预估与提示「已封顶」。
    pub fn base_count(&self) -> usize {
        match self.kind {
            PayloadKind::List => list_payloads(self.list).len(),
            PayloadKind::Numbers => parse_num_range(self.numbers)
                .map(|(a, b, s)| num_range_count(a, b, s))
                .unwrap_or(0),
            PayloadKind::Brute => {
                let n = unique_chars(self.charset).len();
                match parse_len_range(self.lengths) {
                    Some((mn, mx)) => brute_count(n, mn.max(1), mx),
                    None => 0,
                }
            }
        }
    }

    /// 物化最终载荷(已施加处理器),上限 `cap`。处理器恒成功,故不返回错误。
    pub fn generate(&self, cap: usize) -> Vec<String> {
        let base = match self.kind {
            PayloadKind::List => {
                let mut v = list_payloads(self.list);
                v.truncate(cap);
                v
            }
            PayloadKind::Numbers => match parse_num_range(self.numbers) {
                Some((a, b, s)) => gen_numbers(a, b, s, cap),
                None => Vec::new(),
            },
            PayloadKind::Brute => {
                let cs = unique_chars(self.charset);
                match parse_len_range(self.lengths) {
                    Some((mn, mx)) => gen_brute(&cs, mn.max(1), mx, cap),
                    None => Vec::new(),
                }
            }
        };
        self.proc_block(base)
    }

    /// 物化「每注入点载荷块」:列表来源按 `---` 行分块(每块给一个注入点),数字 / 暴破为单块。
    /// 各块上限 `cap`。块数少于注入点时,多出的注入点回退用最后一块(见 [`block_for`])。
    pub fn generate_blocks(&self, cap: usize) -> Vec<Vec<String>> {
        match self.kind {
            PayloadKind::List => split_payload_blocks(self.list)
                .into_iter()
                .map(|mut b| {
                    b.truncate(cap);
                    self.proc_block(b)
                })
                .collect(),
            _ => vec![self.generate(cap)],
        }
    }

    /// 对一块载荷逐条施加处理器(无处理器时原样返回)。
    fn proc_block(&self, b: Vec<String>) -> Vec<String> {
        if self.mask == 0 && self.prefix.is_empty() && self.suffix.is_empty() {
            return b;
        }
        b.into_iter()
            .map(|p| apply_procs(&p, self.mask, self.prefix, self.suffix))
            .collect()
    }
}

/// 字符集去重(保留首次出现顺序),供暴破枚举用。
fn unique_chars(s: &str) -> Vec<char> {
    let mut seen = std::collections::HashSet::new();
    s.chars().filter(|c| !c.is_whitespace() && seen.insert(*c)).collect()
}

/// 把载荷文本按「单独一行的 `---`」切成多块(每块给一个注入点);跳过空行与空块。
fn split_payload_blocks(text: &str) -> Vec<Vec<String>> {
    let mut blocks: Vec<Vec<String>> = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "---" {
            if !cur.is_empty() {
                blocks.push(std::mem::take(&mut cur));
            }
        } else if !trimmed.is_empty() {
            cur.push(line.to_string());
        }
    }
    if !cur.is_empty() {
        blocks.push(cur);
    }
    blocks
}

/// 列表来源的全部载荷(扁平化所有块;排除空行与 `---` 分隔行)。
fn list_payloads(text: &str) -> Vec<String> {
    split_payload_blocks(text).concat()
}

/// Grep-Extract:用正则从响应(状态 + 头 + body 前 256KB)抽值,返回首个捕获组(无组则整体匹配)。
pub(crate) fn extract_value(flow: &HttpFlow, re: &Regex) -> Option<String> {
    let mut hay = format!("HTTP {}\n", flow.status);
    for (k, v) in &flow.resp_headers {
        hay.push_str(k);
        hay.push_str(": ");
        hay.push_str(v);
        hay.push('\n');
    }
    hay.push('\n');
    let cap = flow.resp_body.len().min(256 * 1024);
    hay.push_str(&String::from_utf8_lossy(&flow.resp_body[..cap]));

    let caps = re.captures(&hay)?;
    let m = caps.get(1).or_else(|| caps.get(0))?;
    Some(m.as_str().to_string())
}

/// 按排序键给结果行算出展示顺序的下标(稳定:同键回退按发出顺序)。
pub(crate) fn sorted_indices(results: &[AttackResult], sort: SortBy, desc: bool) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..results.len()).collect();
    idx.sort_by(|&a, &b| {
        let ra = &results[a];
        let rb = &results[b];
        let ord = match sort {
            SortBy::Order => ra.idx.cmp(&rb.idx),
            SortBy::Status => ra.status().cmp(&rb.status()),
            SortBy::Length => ra.resp_len().cmp(&rb.resp_len()),
            SortBy::Time => ra.ms().cmp(&rb.ms()),
        };
        ord.then(ra.idx.cmp(&rb.idx))
    });
    if desc {
        idx.reverse();
    }
    idx
}

/// 解析数字区间 `from-to[:step]`(单个数字 → 区间退化为该数;step 默认 1,不能为 0)。
fn parse_num_range(s: &str) -> Option<(i64, i64, i64)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (range, step) = match s.split_once(':') {
        Some((r, st)) => (r.trim(), st.trim().parse::<i64>().ok()?),
        None => (s, 1),
    };
    if step == 0 {
        return None;
    }
    let (a, b) = match range.split_once('-') {
        Some((a, b)) => (a.trim().parse::<i64>().ok()?, b.trim().parse::<i64>().ok()?),
        None => {
            let n = range.parse::<i64>().ok()?;
            (n, n)
        }
    };
    Some((a, b, step))
}

/// 数字区间条数(饱和)。步长方向需与区间方向一致,否则 0。
fn num_range_count(a: i64, b: i64, step: i64) -> usize {
    if step > 0 && b >= a {
        ((b - a) as u64 / step as u64 + 1) as usize
    } else if step < 0 && a >= b {
        ((a - b) as u64 / (-step) as u64 + 1) as usize
    } else if a == b {
        1
    } else {
        0
    }
}

/// 生成数字区间载荷(上限 `cap`)。
fn gen_numbers(a: i64, b: i64, step: i64, cap: usize) -> Vec<String> {
    let mut out = Vec::new();
    if step > 0 {
        let mut v = a;
        while v <= b && out.len() < cap {
            out.push(v.to_string());
            v = match v.checked_add(step) {
                Some(n) => n,
                None => break,
            };
        }
    } else if step < 0 {
        let mut v = a;
        while v >= b && out.len() < cap {
            out.push(v.to_string());
            v = match v.checked_add(step) {
                Some(n) => n,
                None => break,
            };
        }
    }
    out
}

/// 解析长度区间 `min-max`(单个数字 → `n-n`)。
fn parse_len_range(s: &str) -> Option<(usize, usize)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    match s.split_once('-') {
        Some((a, b)) => Some((a.trim().parse().ok()?, b.trim().parse().ok()?)),
        None => {
            let n = s.parse().ok()?;
            Some((n, n))
        }
    }
}

/// 字符集暴破条数(`Σ n^len`,饱和)。
fn brute_count(n: usize, min: usize, max: usize) -> usize {
    if n == 0 || max == 0 || min > max {
        return 0;
    }
    let mut total: usize = 0;
    for len in min..=max {
        total = total.saturating_add(n.checked_pow(len as u32).unwrap_or(usize::MAX));
    }
    total
}

/// 字符集暴破:对每个长度做里程表式全枚举(上限 `cap`)。
fn gen_brute(charset: &[char], min: usize, max: usize, cap: usize) -> Vec<String> {
    let mut out = Vec::new();
    if charset.is_empty() || max == 0 || min > max {
        return out;
    }
    let n = charset.len();
    for len in min..=max {
        let mut idx = vec![0usize; len];
        loop {
            out.push(idx.iter().map(|&i| charset[i]).collect::<String>());
            if out.len() >= cap {
                return out;
            }
            // 里程表自增:从最低位进位,全溢出即本长度枚举完毕。
            let mut carry = true;
            for p in (0..len).rev() {
                idx[p] += 1;
                if idx[p] < n {
                    carry = false;
                    break;
                }
                idx[p] = 0;
            }
            if carry {
                break;
            }
        }
    }
    out
}

/// 对单条载荷依次施加处理器:大小写 → 哈希 → Base64 → URL 编码,最后包上前后缀。
fn apply_procs(payload: &str, mask: u16, prefix: &str, suffix: &str) -> String {
    let mut s = payload.to_string();
    if mask & ProcOp::Upper.bit() != 0 {
        s = s.to_uppercase();
    }
    if mask & ProcOp::Lower.bit() != 0 {
        s = s.to_lowercase();
    }
    if mask & ProcOp::Md5.bit() != 0 {
        s = scry_codec::Transform::Md5.apply(&s).unwrap_or_default();
    }
    if mask & ProcOp::Sha1.bit() != 0 {
        s = scry_codec::Transform::Sha1.apply(&s).unwrap_or_default();
    }
    if mask & ProcOp::Base64.bit() != 0 {
        s = scry_codec::base64_encode(&s);
    }
    if mask & ProcOp::UrlEncode.bit() != 0 {
        s = scry_codec::url_encode(&s);
    }
    format!("{prefix}{s}{suffix}")
}

/// 把结果表导出为 CSV(idx / 载荷 / 位置 / 状态 / 长度 / 耗时 / 错误)。
pub(crate) fn results_to_csv(results: &[AttackResult]) -> String {
    let mut s = String::from("idx,payload,position,status,length,ms,error\n");
    for r in results {
        let pos = r.position.map(|p| (p + 1).to_string()).unwrap_or_default();
        let err = r.error.clone().unwrap_or_default();
        s.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            r.idx + 1,
            csv_field(&r.payload),
            pos,
            r.status(),
            r.resp_len(),
            r.ms(),
            csv_field(&err),
        ));
    }
    s
}

/// CSV 字段转义(含逗号 / 引号 / 换行时用双引号包裹并转义内部引号)。
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// 结果中「最常见的响应体长度」(仅统计有响应的行),用于把偏离它的行标为异常。
pub(crate) fn modal_length(results: &[AttackResult]) -> Option<usize> {
    let mut counts: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for r in results {
        if r.flow.is_some() {
            *counts.entry(r.resp_len()).or_default() += 1;
        }
    }
    counts.into_iter().max_by_key(|&(_, c)| c).map(|(len, _)| len)
}

// ── 引擎:自动标记 / Content-Length 修正 ──────────────────────────

/// 自动把请求里的「查询串参数值」和「urlencoded 表单体值」用 `§…§` 包起来(快速布点)。
///
/// 保守处理:只动 `key=value` 里的 value;JSON / 多行 / 无 `=` 的 body 一律不碰(交用户手动标)。
pub fn auto_mark(raw: &str) -> String {
    let norm = raw.replace("\r\n", "\n");
    let (head, body) = match norm.split_once("\n\n") {
        Some((h, b)) => (h, Some(b)),
        None => (norm.as_str(), None),
    };

    let mut head_lines = head.lines();
    let mut out = String::new();

    // 第一行(请求行):标记 target 的查询串。
    if let Some(first) = head_lines.next() {
        out.push_str(&mark_request_line(first));
    }
    for line in head_lines {
        out.push('\n');
        out.push_str(line);
    }

    if let Some(body) = body {
        out.push_str("\n\n");
        // 仅当 body 像 urlencoded(单行、含 `=`、不像 JSON/XML)才标记。
        let looks_form = !body.contains('\n')
            && body.contains('=')
            && !body.trim_start().starts_with(['{', '[', '<']);
        if looks_form {
            out.push_str(&mark_urlencoded(body));
        } else {
            out.push_str(body);
        }
    }

    out
}

/// 标记请求行 `METHOD TARGET VERSION` 中 TARGET 的查询串值。
fn mark_request_line(line: &str) -> String {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return line.to_string();
    }
    let method = parts[0];
    let target = parts[1];
    let marked_target = match target.split_once('?') {
        Some((path, query)) => {
            // 把 `#fragment` 留在外面不动。
            let (query, frag) = match query.split_once('#') {
                Some((q, f)) => (q, Some(f)),
                None => (query, None),
            };
            let mut t = format!("{path}?{}", mark_urlencoded(query));
            if let Some(f) = frag {
                t.push('#');
                t.push_str(f);
            }
            t
        }
        None => target.to_string(),
    };
    match parts.get(2) {
        Some(version) => format!("{method} {marked_target} {version}"),
        None => format!("{method} {marked_target}"),
    }
}

/// 把 `a=1&b=2&flag` 的每个非空 value 包成 `a=§1§&b=§2§&flag`。
fn mark_urlencoded(seg: &str) -> String {
    seg.split('&')
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) if !v.is_empty() => format!("{k}={MARKER}{v}{MARKER}"),
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// 若请求带 `Content-Length` 头,改写为实际 body 长度(载荷改变 body 后避免长度不符)。
pub(crate) fn fix_content_length(req: &mut ReplayRequest) {
    let len = req.body.len();
    for (k, v) in req.headers.iter_mut() {
        if k.eq_ignore_ascii_case("content-length") {
            *v = len.to_string();
        }
    }
}

/// 结果行是否命中 grep 关键字(扫状态行 + 响应头 + body 前 32KB)。
fn result_matches(r: &AttackResult, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let Some(f) = &r.flow else {
        return false;
    };
    let mut hay = format!("HTTP {} ", f.status);
    for (k, v) in &f.resp_headers {
        hay.push_str(k);
        hay.push_str(": ");
        hay.push_str(v);
        hay.push('\n');
    }
    if hay.contains(needle) {
        return true;
    }
    let cap = f.resp_body.len().min(32 * 1024);
    String::from_utf8_lossy(&f.resp_body[..cap]).contains(needle)
}

// ── 行为(回写 ScryApp)──────────────────────────────────────────

impl ScryApp {
    /// 从一条流灌入爆破页(目标 + 自动标记参数的模板),清空上轮结果。
    pub fn fill_intruder_from_flow(&mut self, flow: &HttpFlow, cx: &mut Context<Self>) {
        let target = target_string(flow);
        let raw = auto_mark(&render_raw_request(flow));
        self.it_target.update(cx, |s, cx| s.set_text(target, cx));
        self.it_req.update(cx, |s, cx| s.set_text(raw, cx));
        self.it_results.clear();
        self.it_selected = None;
        self.it_progress = None;
    }

    /// 「自动标记参数」:对当前模板跑 [`auto_mark`]。
    pub fn auto_mark_request(&mut self, cx: &mut Context<Self>) {
        let raw = self.it_req.read(cx).text().to_string();
        let marked = auto_mark(&raw);
        self.it_req.update(cx, |s, cx| s.set_text(marked, cx));
        cx.notify();
    }

    /// 「清除标记」:去掉所有 `§`,还原原始请求。
    pub fn clear_markers(&mut self, cx: &mut Context<Self>) {
        let raw = self.it_req.read(cx).text().to_string();
        let cleaned = Template::parse(&raw).original();
        self.it_req.update(cx, |s, cx| s.set_text(cleaned, cx));
        cx.notify();
    }

    /// 清空结果表。
    pub fn clear_attack_results(&mut self, cx: &mut Context<Self>) {
        self.it_results.clear();
        self.it_selected = None;
        self.it_progress = None;
        cx.notify();
    }

    /// 从各输入框读出载荷生成配置(拥有所有权的串,供构造 [`GenSpec`])。
    fn gen_texts(
        &self,
        cx: &Context<Self>,
    ) -> (PayloadKind, String, String, String, String, u16, String, String) {
        (
            self.it_src,
            self.it_payloads.read(cx).text().to_string(),
            self.it_num.read(cx).text().to_string(),
            self.it_charset.read(cx).text().to_string(),
            self.it_len.read(cx).text().to_string(),
            self.it_proc_mask,
            self.it_prefix.read(cx).text().to_string(),
            self.it_suffix.read(cx).text().to_string(),
        )
    }

    /// 当前配置下的基础载荷条数(未封顶;界面预估用)。
    pub(crate) fn it_payload_count(&self, cx: &Context<Self>) -> usize {
        let (kind, list, num, charset, len, mask, prefix, suffix) = self.gen_texts(cx);
        GenSpec {
            kind,
            list: &list,
            numbers: &num,
            charset: &charset,
            lengths: &len,
            mask,
            prefix: &prefix,
            suffix: &suffix,
        }
        .base_count()
    }

    /// 物化当前配置的载荷(上限 `cap`)。
    pub(crate) fn it_generate(&self, cx: &Context<Self>, cap: usize) -> Vec<String> {
        let (kind, list, num, charset, len, mask, prefix, suffix) = self.gen_texts(cx);
        GenSpec {
            kind,
            list: &list,
            numbers: &num,
            charset: &charset,
            lengths: &len,
            mask,
            prefix: &prefix,
            suffix: &suffix,
        }
        .generate(cap)
    }

    /// 物化当前配置的「每注入点载荷块」(上限 `cap`)。
    pub(crate) fn it_blocks(&self, cx: &Context<Self>, cap: usize) -> Vec<Vec<String>> {
        let (kind, list, num, charset, len, mask, prefix, suffix) = self.gen_texts(cx);
        GenSpec {
            kind,
            list: &list,
            numbers: &num,
            charset: &charset,
            lengths: &len,
            mask,
            prefix: &prefix,
            suffix: &suffix,
        }
        .generate_blocks(cap)
    }

    /// 设置结果排序键。
    pub fn set_sort(&mut self, sort: SortBy, cx: &mut Context<Self>) {
        self.it_sort = sort;
        cx.notify();
    }

    /// 切换结果排序升 / 降序。
    pub fn toggle_sort_dir(&mut self, cx: &mut Context<Self>) {
        self.it_sort_desc = !self.it_sort_desc;
        cx.notify();
    }

    /// 设置并发发包数。
    pub fn set_concurrency(&mut self, n: usize, cx: &mut Context<Self>) {
        self.it_concurrency = n.max(1);
        cx.notify();
    }

    /// 切换载荷来源(列表 / 数字 / 暴破)。
    pub fn set_payload_kind(&mut self, kind: PayloadKind, cx: &mut Context<Self>) {
        self.it_src = kind;
        cx.notify();
    }

    /// 开 / 关一个载荷处理器。
    pub fn toggle_proc(&mut self, op: ProcOp, cx: &mut Context<Self>) {
        self.it_proc_mask ^= op.bit();
        cx.notify();
    }

    /// 把结果导出为 CSV(落 `~/.scry/intruder-<ts>.csv`)。
    pub fn export_results(&mut self, cx: &mut Context<Self>) {
        if self.it_results.is_empty() {
            return;
        }
        let csv = results_to_csv(&self.it_results);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = scry_ca::default_ca_dir().join(format!("intruder-{ts}.csv"));
        match std::fs::write(&path, csv) {
            Ok(_) => {
                let msg = if self.lang.is_zh() {
                    format!("已导出 {} 条 → {}", self.it_results.len(), path.display())
                } else {
                    format!("Exported {} rows → {}", self.it_results.len(), path.display())
                };
                self.show_toast(msg, cx);
            }
            Err(e) => {
                let msg = if self.lang.is_zh() {
                    format!("导出失败:{e}")
                } else {
                    format!("Export failed: {e}")
                };
                self.show_toast(msg, cx);
            }
        }
    }

    /// 开始爆破:解析模板 + 载荷 → 生成并预解析所有请求 → 后台串行发包,结果流式回填。
    pub fn start_attack(&mut self, cx: &mut Context<Self>) {
        if self.it_busy {
            return;
        }
        let target = self.it_target.read(cx).text().to_string();
        let raw = self.it_req.read(cx).text().to_string();
        let blocks = self.it_blocks(cx, GEN_CAP);

        let tmpl = Template::parse(&raw);
        if tmpl.position_count() == 0 {
            self.it_progress = Some(
                self.lang
                    .t("No injection positions — mark some with §…§ or Auto-mark")
                    .to_string(),
            );
            cx.notify();
            return;
        }
        if blocks.iter().all(|b| b.is_empty()) {
            self.it_progress = Some(self.lang.t("No payloads generated — check payload source").to_string());
            cx.notify();
            return;
        }

        let jobs = build_jobs(&tmpl, &blocks, self.it_mode, ATTACK_CAP);

        // 预解析每条作业的请求文本(一次性校验;任一失败即整体中止并报错)。
        let mut reqs: Vec<(String, Option<usize>, ReplayRequest)> = Vec::with_capacity(jobs.len());
        for job in &jobs {
            let text = tmpl.render(&job.values);
            match parse_raw_request(&target, &text) {
                Ok(mut req) => {
                    fix_content_length(&mut req);
                    reqs.push((job.label.clone(), job.position, req));
                }
                Err(e) => {
                    let prefix = if self.lang.is_zh() {
                        "请求解析失败:"
                    } else {
                        "Request parse failed: "
                    };
                    self.it_progress = Some(format!("{prefix}{e}"));
                    cx.notify();
                    return;
                }
            }
        }
        if reqs.is_empty() {
            return;
        }

        let total = reqs.len();
        self.it_total = total;
        self.it_results.clear();
        self.it_selected = None;
        self.it_busy = true;
        self.it_progress = Some(format!("0 / {total}"));

        let up = self.upstream_proxy(cx);
        let concurrency = self.it_concurrency.max(1);
        let throttle = self
            .it_throttle
            .read(cx)
            .text()
            .trim()
            .parse::<u64>()
            .unwrap_or(0);
        let (tx, rx) = mpsc::channel::<AttackResult>();
        self.it_rx = Some(rx);
        cx.notify();

        // 后台:临时 current-thread runtime 上用 buffer_unordered 并发发包(并发=1 即串行),
        // 每条完成即经通道流式回传;throttle 在每条请求前加延迟做限速。
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
                    let stream = futures::stream::iter(reqs.into_iter().enumerate())
                        .map(|(idx, (label, position, req))| {
                            let cfg = cfg.clone();
                            async move {
                                if throttle > 0 {
                                    tokio::time::sleep(Duration::from_millis(throttle)).await;
                                }
                                match replay::send(&req, &cfg).await {
                                    Ok(flow) => AttackResult {
                                        idx,
                                        payload: label,
                                        position,
                                        flow: Some(flow),
                                        error: None,
                                    },
                                    Err(e) => AttackResult {
                                        idx,
                                        payload: label,
                                        position,
                                        flow: None,
                                        error: Some(format!("{e:#}")),
                                    },
                                }
                            }
                        })
                        .buffer_unordered(concurrency);
                    futures::pin_mut!(stream);
                    while let Some(result) = stream.next().await {
                        // 接收端已丢弃(用户点了停止)→ 结束发包。
                        if tx.send(result).is_err() {
                            break;
                        }
                    }
                });
            })
            .detach();

        // 前台轮询:把陆续到达的结果排进表;全部到齐即收尾。
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(120))
                    .await;
                let keep_going = this.update(cx, |this, cx| {
                    this.drain_attack_results();
                    cx.notify();
                    this.it_busy
                });
                match keep_going {
                    Ok(true) => continue,
                    _ => break,
                }
            }
        })
        .detach();
    }

    /// 停止爆破:丢弃接收端(后台下次 send 失败即退出),停在已到结果。
    pub fn stop_attack(&mut self, cx: &mut Context<Self>) {
        if !self.it_busy {
            return;
        }
        self.it_busy = false;
        self.it_rx = None;
        let stopped = if self.lang.is_zh() { "(已停止)" } else { " (stopped)" };
        self.it_progress = Some(format!(
            "{} / {}{stopped}",
            self.it_results.len(),
            self.it_total
        ));
        cx.notify();
    }

    /// 把通道里已到的结果排进表,更新进度;到齐则收尾(置默认选中)。
    fn drain_attack_results(&mut self) {
        let Some(rx) = &self.it_rx else {
            return;
        };
        let mut got = false;
        while let Ok(r) = rx.try_recv() {
            self.it_results.push(r);
            got = true;
        }
        let total = self.it_total;
        let done = total > 0 && self.it_results.len() >= total;
        if got || done {
            self.it_progress = Some(format!("{} / {}", self.it_results.len(), total));
        }
        if done {
            self.it_busy = false;
            self.it_rx = None;
            if self.it_selected.is_none() && !self.it_results.is_empty() {
                self.it_selected = Some(0);
            }
        }
    }

    // ── 爆破页 UI ────────────────────────────────────────────────

    /// 爆破页主体(左:配置;右:结果 + 响应)。
    pub fn intruder_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let positions = Template::parse(self.it_req.read(cx).text()).position_count();
        let payload_n = self.it_payload_count(cx);
        let est = attack_total(self.it_mode, positions, payload_n);

        let toolbar = self.intruder_toolbar(positions, est, cx);
        let left = self.intruder_config(positions, payload_n, cx);
        let right = self.intruder_results(cx);

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
                    .flex_1()
                    .min_h(px(0.0))
                    .flex()
                    .gap(t.space.md)
                    .child(left)
                    .child(right),
            )
            .bg(c.background)
    }

    /// 顶部工具条:攻击模式 + 预估总数 + 开始/停止 + 进度 + grep。
    fn intruder_toolbar(
        &self,
        positions: usize,
        est: usize,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let modes = AttackMode::ALL;
        let mode_idx = modes.iter().position(|m| *m == self.it_mode).unwrap_or(0);
        let view = cx.entity();
        let mode_seg = Segmented::new("it-mode")
            .items(modes.map(|m| self.lang.t(m.label())))
            .selected(mode_idx)
            .on_select(move |i, _e, _w, app| {
                view.update(app, |this, cx| {
                    this.it_mode = modes[i];
                    cx.notify();
                });
            });

        // 并发数 + 限速(攻击参数)。
        let conc_opts = [1usize, 5, 10, 20];
        let conc_idx = conc_opts
            .iter()
            .position(|n| *n == self.it_concurrency)
            .unwrap_or(0);
        let view_c = cx.entity();
        let conc_seg = Segmented::new("it-conc")
            .items(conc_opts.map(|n| SharedString::from(n.to_string())))
            .selected(conc_idx)
            .on_select(move |i, _e, _w, app| {
                view_c.update(app, |this, cx| this.set_concurrency(conc_opts[i], cx));
            });
        let conc_group = div()
            .flex()
            .items_center()
            .gap(px(4.0))
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("Threads")),
            )
            .child(conc_seg);
        let throttle_group = div()
            .flex()
            .items_center()
            .gap(px(4.0))
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("Throttle ms")),
            )
            .child(div().w(px(52.0)).child(self.it_throttle.clone()));

        // 预估总数(超封顶时标注)。
        let total_text = if est > ATTACK_CAP {
            if self.lang.is_zh() {
                format!("{}:{ATTACK_CAP}+(已封顶)", self.lang.t("Total requests"))
            } else {
                format!("{}: {ATTACK_CAP}+ (capped)", self.lang.t("Total requests"))
            }
        } else {
            format!("{}: {est}", self.lang.t("Total requests"))
        };

        let action = if self.it_busy {
            Button::new("it-stop", self.lang.t("Stop"))
                .danger()
                .size(ButtonSize::Sm)
                .icon(IconName::Box)
                .on_click(cx.listener(|this, _e, _w, cx| this.stop_attack(cx)))
        } else {
            Button::new("it-start", self.lang.t("Start attack"))
                .variant(ButtonVariant::Primary)
                .size(ButtonSize::Sm)
                .icon(IconName::Zap)
                .on_click(cx.listener(|this, _e, _w, cx| this.start_attack(cx)))
        };

        let mut status = div().flex().items_center().gap(t.space.md);
        status = status.child(
            div()
                .text_size(t.font_size.xs)
                .text_color(if positions == 0 { c.warning } else { c.text_muted })
                .child(total_text),
        );
        if let Some(prog) = &self.it_progress {
            status = status.child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(if self.it_busy { c.warning } else { c.text_muted })
                    .child(prog.clone()),
            );
        }

        // grep 关键字(右侧)。
        let grep = div()
            .flex()
            .items_center()
            .gap(px(6.0))
            .w(px(240.0))
            .flex_shrink_0()
            .child(Icon::new(IconName::Filter).size(px(15.0)).color(c.text_subtle))
            .child(div().flex_1().min_w(px(0.0)).child(self.it_match.clone()));

        // 有结果时显示「导出 CSV / 清空」。
        let export = (!self.it_results.is_empty()).then(|| {
            Button::new("it-export", self.lang.t("Export CSV"))
                .subtle()
                .size(ButtonSize::Sm)
                .icon(IconName::Download)
                .on_click(cx.listener(|this, _e, _w, cx| this.export_results(cx)))
        });
        let clear = (!self.it_results.is_empty()).then(|| {
            Button::new("it-clear", self.lang.t("Clear"))
                .subtle()
                .size(ButtonSize::Sm)
                .icon(IconName::Trash)
                .on_click(cx.listener(|this, _e, _w, cx| this.clear_attack_results(cx)))
        });

        div()
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
                    .child(mode_seg)
                    .child(conc_group)
                    .child(throttle_group)
                    .child(action)
                    .child(status),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .children(export)
                    .children(clear)
                    .child(grep),
            )
    }

    /// 左侧配置:目标 + 请求模板(可编辑)+ 载荷(可编辑)。
    fn intruder_config(
        &self,
        positions: usize,
        payload_n: usize,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        // 目标行。
        let target_row = div()
            .flex()
            .items_center()
            .gap(t.space.sm)
            .flex_shrink_0()
            .child(
                div()
                    .flex_shrink_0()
                    .text_size(t.font_size.sm)
                    .text_color(c.text_muted)
                    .child(self.lang.t("Target")),
            )
            .child(div().flex_1().min_w(px(0.0)).child(self.it_target.clone()));

        // 请求模板面板(标题 + 自动标记 / 清除 + 注入点计数 + 可编辑区)。
        let pos_pill = div()
            .flex_shrink_0()
            .px(t.space.sm)
            .py(px(1.0))
            .rounded(t.radius.full)
            .bg(c.accent.opacity(0.16))
            .border_1()
            .border_color(c.accent.opacity(0.32))
            .text_size(t.font_size.xs)
            .text_color(c.accent)
            .child(if self.lang.is_zh() {
                format!("{positions} 个标记点")
            } else {
                format!("{positions} positions")
            });

        // 请求模板 Pretty(高亮只读)/ Raw(可编辑、放注入点)切换。
        let rq_views = [MsgView::Pretty, MsgView::Raw];
        let rq_idx = rq_views.iter().position(|m| *m == self.it_req_view).unwrap_or(0);
        let view_rq = cx.entity();
        let req_seg = Segmented::new("it-req-view")
            .items(rq_views.map(|m| self.lang.t(m.label())))
            .selected(rq_idx)
            .on_select(move |i, _e, _w, app| {
                view_rq.update(app, |this, cx| {
                    this.it_req_view = rq_views[i];
                    cx.notify();
                });
            });

        let req_header = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.sm)
            .flex_shrink_0()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .child(
                        PanelTitle::new(self.lang.t("Request template"))
                            .hint(self.lang.t("mark injection points with §…§"))
                            .mono(),
                    )
                    .child(pos_pill),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .child(
                        Button::new("it-automark", self.lang.t("Auto-mark params"))
                            .ghost()
                            .size(ButtonSize::Sm)
                            .icon(IconName::Tag)
                            .on_click(cx.listener(|this, _e, _w, cx| this.auto_mark_request(cx))),
                    )
                    .child(
                        Button::new("it-clearmark", self.lang.t("Clear markers"))
                            .subtle()
                            .size(ButtonSize::Sm)
                            .icon(IconName::Trash)
                            .on_click(cx.listener(|this, _e, _w, cx| this.clear_markers(cx))),
                    )
                    .child(req_seg),
            );

        let req_body: AnyElement = if self.it_req_view == MsgView::Raw {
            div()
                .id("it-req-scroll")
                .flex_1()
                .min_h(px(0.0))
                .overflow_y_scroll()
                .child(self.it_req.clone())
                .into_any_element()
        } else {
            let raw = self.it_req.read(cx).text().to_string();
            CodeView::new("it-req-code")
                .lines(crate::highlight::request_lines(&raw, 400, self.lang, c))
                .fill()
                .into_any_element()
        };

        let req_panel = div()
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
            .child(req_header)
            .child(divider(c))
            .child(req_body);

        let pl_panel = self.intruder_payloads(payload_n, cx);

        div()
            .w(px(520.0))
            .flex_shrink_0()
            .flex()
            .flex_col()
            .gap(t.space.md)
            .min_h(px(0.0))
            .child(target_row)
            .child(req_panel)
            .child(pl_panel)
    }

    /// 载荷面板:来源选择(列表 / 数字 / 字符集暴破)+ 处理器 + 实时预览。
    fn intruder_payloads(&self, payload_n: usize, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        // 来源分段选择。
        let kinds = PayloadKind::ALL;
        let kind_idx = kinds.iter().position(|k| *k == self.it_src).unwrap_or(0);
        let view = cx.entity();
        let kind_seg = Segmented::new("it-src")
            .items(kinds.map(|k| self.lang.t(k.label())))
            .selected(kind_idx)
            .on_select(move |i, _e, _w, app| {
                view.update(app, |this, cx| this.set_payload_kind(kinds[i], cx));
            });

        let pl_header = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.sm)
            .flex_shrink_0()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .child(
                        div()
                            .text_size(t.font_size.sm)
                            .text_color(c.text)
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(self.lang.t("Payloads")),
                    )
                    .child(kind_seg),
            )
            .child(
                div()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(if self.lang.is_zh() {
                        format!("{payload_n} 条")
                    } else {
                        format!("{payload_n} items")
                    }),
            );

        // 按来源切换的输入区。
        let body: AnyElement = match self.it_src {
            PayloadKind::List => div()
                .id("it-pl-scroll")
                .flex_1()
                .min_h(px(0.0))
                .overflow_y_scroll()
                .child(self.it_payloads.clone())
                .into_any_element(),
            PayloadKind::Numbers => div()
                .flex_1()
                .min_h(px(0.0))
                .flex()
                .flex_col()
                .gap(t.space.sm)
                .child(field_row(self.lang.t("Range"), self.it_num.clone(), t, c))
                .child(
                    div()
                        .text_size(t.font_size.xs)
                        .text_color(c.text_subtle)
                        .child(self.lang.t("from-to[:step] — e.g. 1-9999 or 0-100:5")),
                )
                .into_any_element(),
            PayloadKind::Brute => div()
                .flex_1()
                .min_h(px(0.0))
                .flex()
                .flex_col()
                .gap(t.space.sm)
                .child(field_row(self.lang.t("Charset"), self.it_charset.clone(), t, c))
                .child(field_row(self.lang.t("Length"), self.it_len.clone(), t, c))
                .child(
                    div()
                        .text_size(t.font_size.xs)
                        .text_color(c.text_subtle)
                        .child(self.lang.t("charset × length min-max — careful: combinations explode")),
                )
                .into_any_element(),
        };

        // 处理器:前后缀 + 编解码 / 哈希开关。
        let mut proc_chips = Vec::new();
        for op in ProcOp::ALL {
            let active = self.it_proc_mask & op.bit() != 0;
            proc_chips.push(
                Chip::new(SharedString::from(format!("it-proc-{}", op.label())), op.label())
                    .active(active)
                    .on_click(cx.listener(move |this, _e, _w, cx| this.toggle_proc(op, cx)))
                    .into_any_element(),
            );
        }
        let procs = div()
            .flex_shrink_0()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .child(field_row(self.lang.t("Prefix"), self.it_prefix.clone(), t, c))
                    .child(field_row(self.lang.t("Suffix"), self.it_suffix.clone(), t, c)),
            )
            .child(div().flex().flex_wrap().gap(px(4.0)).children(proc_chips));

        // 实时预览:样例(已施加处理器)。
        let samples = self.it_generate(cx, 3);
        let sample_text = if samples.is_empty() {
            "—".to_string()
        } else {
            samples.join("   ")
        };
        let preview = div()
            .flex_shrink_0()
            .flex()
            .items_center()
            .gap(px(6.0))
            .px(t.space.sm)
            .py(px(4.0))
            .rounded(t.radius.md)
            .bg(c.glass)
            .border_1()
            .border_color(c.glass_border)
            .child(
                div()
                    .flex_shrink_0()
                    .text_size(t.font_size.xs)
                    .text_color(c.text_subtle)
                    .child(self.lang.t("Preview")),
            )
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .font_family(MONO)
                    .text_size(t.font_size.xs)
                    .text_color(c.text_muted)
                    .truncate()
                    .child(sample_text),
            );

        div()
            .h(px(300.0))
            .flex_shrink_0()
            .flex()
            .flex_col()
            .gap(t.space.sm)
            .p(t.space.sm)
            .rounded(t.radius.lg)
            .bg(c.surface)
            .border_1()
            .border_color(c.border)
            .child(pl_header)
            .child(divider(c))
            .child(body)
            .child(procs)
            .child(preview)
    }

    /// 右侧:排序 / 提取控制 + 结果表 + 选中结果的响应面板。
    fn intruder_results(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let grep = self.it_match.read(cx).text().trim().to_string();
        let has_grep = !grep.is_empty();

        // Grep-Extract:编译一次正则,供所有行复用(非法正则 → 列显示「—」)。
        let extract_src = self.it_extract.read(cx).text().trim().to_string();
        let has_extract = !extract_src.is_empty();
        let extract_re = if has_extract {
            Regex::new(&extract_src).ok()
        } else {
            None
        };

        let mut columns = vec![
            Column::fixed("#", px(52.0)).end(),
            Column::flex(self.lang.t("Payload"), 1.0),
            Column::fixed(self.lang.t("Pos"), px(56.0)).center(),
            Column::fixed(self.lang.t("Status"), px(74.0)).center(),
            Column::fixed(self.lang.t("Length"), px(86.0)).end(),
            Column::fixed(self.lang.t("Time(ms)"), px(82.0)).end(),
        ];
        if has_grep {
            columns.push(Column::fixed(self.lang.t("Match"), px(66.0)).center());
        }
        if has_extract {
            columns.push(Column::flex(self.lang.t("Extract"), 0.8));
        }

        let selected = self.it_selected;
        let footer = {
            let n = self.it_results.len();
            match selected.and_then(|i| self.it_results.get(i)) {
                Some(r) if self.lang.is_zh() => format!("已选 #{} · 共 {} 条", r.idx + 1, n),
                Some(r) => format!("Selected #{} · {} results", r.idx + 1, n),
                None if self.lang.is_zh() => format!("共 {n} 条结果"),
                None => format!("{n} results"),
            }
        };

        let table_block: AnyElement = if self.it_results.is_empty() {
            let (text, icon) = if Template::parse(self.it_req.read(cx).text()).position_count() == 0 {
                (
                    self.lang
                        .t("No injection positions — mark some with §…§ or Auto-mark"),
                    IconName::Tag,
                )
            } else if self.it_payload_count(cx) == 0 {
                (self.lang.t("Add payloads (one per line) to start"), IconName::Layers)
            } else {
                (
                    self.lang.t("Configure positions & payloads, then Start attack"),
                    IconName::Zap,
                )
            };
            EmptyState::new(text).icon(icon).into_any_element()
        } else {
            // 长度异常基线:有响应且长度不止一种时,偏离「最常见长度」的行标警告色。
            let modal = modal_length(&self.it_results);
            let varied = {
                let mut it = self
                    .it_results
                    .iter()
                    .filter(|r| r.flow.is_some())
                    .map(|r| r.resp_len());
                match it.next() {
                    Some(first) => it.any(|l| l != first),
                    None => false,
                }
            };
            let order = sorted_indices(&self.it_results, self.it_sort, self.it_sort_desc);

            let mut table = Table::new(columns)
                .selection(SelectionMode::Single)
                .row_height(px(32.0))
                .fill()
                .footer_note(footer);
            for i in order {
                let r = &self.it_results[i];
                let (stext, scol) = status_cell(r, c);
                let pos_label = match r.position {
                    Some(p) => (p + 1).to_string(),
                    None => "—".to_string(),
                };
                let len_outlier = varied && r.flow.is_some() && Some(r.resp_len()) != modal;
                let mut row = Row::new()
                    .selected(selected == Some(i))
                    .on_select(cx.listener(move |this, _e, _w, cx| {
                        this.it_selected = Some(i);
                        cx.notify();
                    }))
                    .text(format!("{}", r.idx + 1))
                    .text(r.payload.clone())
                    .muted(pos_label)
                    .cell(Badge::new(stext, scol));
                row = if len_outlier {
                    row.cell(
                        div()
                            .w_full()
                            .flex()
                            .justify_end()
                            .text_color(c.warning)
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(human_len(r.resp_len())),
                    )
                } else {
                    row.text(human_len(r.resp_len()))
                };
                row = row.text(r.ms().to_string());
                if has_grep {
                    if result_matches(r, &grep) {
                        row = row.cell(Badge::new("✓", c.success));
                    } else {
                        row = row.muted("");
                    }
                }
                if has_extract {
                    let val = r
                        .flow
                        .as_ref()
                        .zip(extract_re.as_ref())
                        .and_then(|(f, re)| extract_value(f, re));
                    row = match val {
                        Some(v) => row.text(v),
                        None => row.muted("—"),
                    };
                }
                table = table.row(row);
            }
            table.into_any_element()
        };

        let controls = self.intruder_result_controls(cx);
        let response = self.intruder_response(cx);

        div()
            .flex_1()
            .min_w(px(0.0))
            .flex()
            .flex_col()
            .gap(t.space.md)
            .min_h(px(0.0))
            .child(controls)
            .child(table_block)
            .child(response)
    }

    /// 结果区控制行:排序键 + 升降序 + Grep-Extract 正则。
    fn intruder_result_controls(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let sorts = SortBy::ALL;
        let sidx = sorts.iter().position(|s| *s == self.it_sort).unwrap_or(0);
        let view = cx.entity();
        let sort_seg = Segmented::new("it-sort")
            .items(sorts.map(|s| self.lang.t(s.label())))
            .selected(sidx)
            .on_select(move |i, _e, _w, app| {
                view.update(app, |this, cx| this.set_sort(sorts[i], cx));
            });
        let dir = Button::new("it-sortdir", if self.it_sort_desc { "↓" } else { "↑" })
            .ghost()
            .size(ButtonSize::Sm)
            .on_click(cx.listener(|this, _e, _w, cx| this.toggle_sort_dir(cx)));

        let extract = div()
            .flex()
            .items_center()
            .gap(px(6.0))
            .flex_1()
            .min_w(px(0.0))
            .child(Icon::new(IconName::Tag).size(px(15.0)).color(c.text_subtle))
            .child(div().flex_1().min_w(px(0.0)).child(self.it_extract.clone()));

        div()
            .flex()
            .items_center()
            .gap(t.space.md)
            .flex_shrink_0()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .child(
                        div()
                            .text_size(t.font_size.xs)
                            .text_color(c.text_subtle)
                            .child(self.lang.t("Sort")),
                    )
                    .child(sort_seg)
                    .child(dir),
            )
            .child(extract)
    }

    /// 把选中结果的响应同步进只读可选中高亮查看器(签名不变则跳过)。由 `render`(Intruder 页可见时)调用。
    pub fn sync_intruder_views(&mut self, cx: &mut Context<Self>) {
        let c = cx.theme().colors;
        let dark = cx.theme().mode.is_dark();
        let built = {
            let sel = self.it_selected.and_then(|i| self.it_results.get(i));
            let flow = sel.and_then(|r| r.flow.as_ref());
            let err = sel.and_then(|r| r.error.as_deref());
            let sig = resp_view_sig(dark, self.it_resp_view, flow, err);
            if sig == self.it_resp_sig {
                None
            } else {
                Some((sig, build_resp_view(self.lang, self.it_resp_view, flow, err, c)))
            }
        };
        if let Some((sig, (text, hl))) = built {
            let input = self.it_resp_input.clone();
            input.update(cx, |s, cx| {
                s.set_text(text, cx);
                s.set_highlights(hl, cx);
            });
            self.it_resp_sig = sig;
        }
    }

    /// 选中结果的响应面板(只读**可选中高亮**查看器 + 视图切换;复用 Proxy 报文渲染路径)。
    fn intruder_response(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let c = cx.theme().colors;
        let t = cx.theme().tokens;

        let sel = self.it_selected.and_then(|i| self.it_results.get(i));
        let sel_err = sel.and_then(|r| r.error.as_deref());
        let sel_flow = sel.and_then(|r| r.flow.as_ref());

        let summary = if sel_err.is_some() {
            (self.lang.t("Failed").to_string(), c.danger)
        } else if let Some(f) = sel_flow {
            (
                format!(
                    "{} · {} · {} ms",
                    f.status,
                    human_len(f.resp_len()),
                    f.duration_ms
                ),
                status_color(f.status, c),
            )
        } else {
            (self.lang.t("read-only").to_string(), c.text_subtle)
        };

        let has_flow = sel_flow.is_some();
        let rp_views = [MsgView::Pretty, MsgView::Raw, MsgView::Hex, MsgView::Render];
        let rv_idx = rp_views.iter().position(|m| *m == self.it_resp_view).unwrap_or(0);
        let view = cx.entity();
        let resp_seg = Segmented::new("it-resp-view")
            .items(rp_views.map(|m| self.lang.t(m.label())))
            .selected(rv_idx)
            .on_select(move |i, _e, _w, app| {
                view.update(app, |this, cx| {
                    this.it_resp_view = rp_views[i];
                    cx.notify();
                });
            });

        let header = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(t.space.sm)
            .flex_shrink_0()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(t.space.sm)
                    .child(
                        div()
                            .text_size(t.font_size.sm)
                            .text_color(c.text)
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(self.lang.t("Response")),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(6.0))
                            .px(t.space.sm)
                            .py(px(2.0))
                            .rounded(t.radius.full)
                            .bg(c.glass)
                            .border_1()
                            .border_color(c.glass_border)
                            .child(StatusDot::new(summary.1).size(px(7.0)))
                            .child(
                                div()
                                    .text_size(t.font_size.xs)
                                    .text_color(c.text_muted)
                                    .child(summary.0),
                            ),
                    ),
            )
            .when(has_flow, |d| d.child(resp_seg));

        // 响应(含错误)走只读可选中高亮查看器:选中 + Cmd/Ctrl+C + 右键复制;文本/高亮由 sync_intruder_views 灌入。
        let body: AnyElement = if sel_flow.is_none() && sel_err.is_none() {
            div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .child(
                    div()
                        .text_size(t.font_size.sm)
                        .text_color(c.text_subtle)
                        .child(self.lang.t("Select a result to view the response")),
                )
                .into_any_element()
        } else if self.it_resp_view == MsgView::Render && sel_err.is_none() {
            // 渲染视图:图片直接预览(复用代理响应预览),非文本框。
            self.response_preview(sel_flow, cx)
        } else {
            div()
                .id("it-resp-scroll")
                .flex_1()
                .min_h(px(0.0))
                .overflow_y_scroll()
                .on_mouse_down(
                    MouseButton::Right,
                    cx.listener(|this, _e, _w, cx| {
                        let inp = this.it_resp_input.clone();
                        this.copy_from_input(inp, cx);
                    }),
                )
                .child(self.it_resp_input.clone())
                .into_any_element()
        };

        div()
            .h(px(248.0))
            .flex_shrink_0()
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
}

// ── 小构件(自由函数)─────────────────────────────────────────────

/// 结果状态单元格文案 + 取色(错误 → ERR 红;无响应 → —)。
fn status_cell(r: &AttackResult, c: ThemeColors) -> (String, Hsla) {
    if r.error.is_some() {
        return ("ERR".to_string(), c.danger);
    }
    let s = r.status();
    if s == 0 {
        ("—".to_string(), c.text_muted)
    } else {
        (s.to_string(), status_color(s, c))
    }
}

/// 一行「标签 + 输入框」(生成器配置用)。
fn field_row(
    label: impl Into<SharedString>,
    input: Entity<InputState>,
    t: Tokens,
    c: ThemeColors,
) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .gap(t.space.sm)
        .flex_1()
        .min_w(px(0.0))
        .child(
            div()
                .flex_shrink_0()
                .text_size(t.font_size.xs)
                .text_color(c.text_muted)
                .child(label.into()),
        )
        .child(div().flex_1().min_w(px(0.0)).child(input))
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AttackMode;

    #[test]
    fn template_parses_balanced_markers() {
        let tmpl = Template::parse("GET /u?id=§1§&p=§2§ HTTP/1.1");
        assert_eq!(tmpl.position_count(), 2);
        assert_eq!(tmpl.originals(), &["1".to_string(), "2".to_string()]);
        assert_eq!(
            tmpl.render(&["A".to_string(), "B".to_string()]),
            "GET /u?id=A&p=B HTTP/1.1"
        );
        // 还原 = 原始(去标记)。
        assert_eq!(tmpl.original(), "GET /u?id=1&p=2 HTTP/1.1");
    }

    #[test]
    fn template_handles_no_and_dangling_markers() {
        let none = Template::parse("GET / HTTP/1.1");
        assert_eq!(none.position_count(), 0);
        assert_eq!(none.render(&[]), "GET / HTTP/1.1");

        // 落单开标记 → 当普通文本,不丢字符、不算注入点。
        let dangling = Template::parse("a§bc");
        assert_eq!(dangling.position_count(), 0);
        assert_eq!(dangling.original(), "a§bc");
    }

    #[test]
    fn auto_mark_query_and_form_body() {
        let raw = "POST /login?next=/home HTTP/1.1\nHost: h\nContent-Type: application/x-www-form-urlencoded\n\nuser=admin&pass=secret";
        let marked = auto_mark(raw);
        assert!(marked.contains("next=§/home§"));
        assert!(marked.contains("user=§admin§"));
        assert!(marked.contains("pass=§secret§"));
        // 标记后解析应得 3 个注入点。
        assert_eq!(Template::parse(&marked).position_count(), 3);
    }

    #[test]
    fn auto_mark_leaves_json_body_untouched() {
        let raw = "POST /api HTTP/1.1\nHost: h\nContent-Type: application/json\n\n{\"u\":\"a\"}";
        let marked = auto_mark(raw);
        assert!(!marked.contains(MARKER));
        assert_eq!(Template::parse(&marked).position_count(), 0);
    }

    #[test]
    fn build_jobs_sniper_counts_and_positions() {
        let tmpl = Template::parse("/x?a=§1§&b=§2§");
        let payloads = vec!["p".to_string(), "q".to_string(), "r".to_string()];
        let jobs = build_jobs(&tmpl, std::slice::from_ref(&payloads), AttackMode::Sniper, ATTACK_CAP);
        // 2 个位置 × 3 个载荷 = 6。
        assert_eq!(jobs.len(), 6);
        // 第一组只动位置 0,位置 1 保持原值。
        assert_eq!(jobs[0].values, vec!["p".to_string(), "2".to_string()]);
        assert_eq!(jobs[0].position, Some(0));
        // 第四组动位置 1,位置 0 保持原值。
        assert_eq!(jobs[3].values, vec!["1".to_string(), "p".to_string()]);
        assert_eq!(jobs[3].position, Some(1));
    }

    #[test]
    fn build_jobs_battering_ram_fills_all_positions() {
        let tmpl = Template::parse("/x?a=§1§&b=§2§");
        let payloads = vec!["p".to_string(), "q".to_string()];
        let jobs = build_jobs(&tmpl, std::slice::from_ref(&payloads), AttackMode::BatteringRam, ATTACK_CAP);
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].values, vec!["p".to_string(), "p".to_string()]);
        assert_eq!(jobs[1].values, vec!["q".to_string(), "q".to_string()]);
    }

    #[test]
    fn build_jobs_cluster_bomb_is_cartesian_and_capped() {
        let tmpl = Template::parse("/x?a=§1§&b=§2§");
        let payloads = vec!["p".to_string(), "q".to_string()];
        let jobs = build_jobs(&tmpl, std::slice::from_ref(&payloads), AttackMode::ClusterBomb, ATTACK_CAP);
        // 2^2 = 4 种组合。
        assert_eq!(jobs.len(), 4);
        let combos: Vec<Vec<String>> = jobs.iter().map(|j| j.values.clone()).collect();
        assert!(combos.contains(&vec!["p".to_string(), "p".to_string()]));
        assert!(combos.contains(&vec!["p".to_string(), "q".to_string()]));
        assert!(combos.contains(&vec!["q".to_string(), "p".to_string()]));
        assert!(combos.contains(&vec!["q".to_string(), "q".to_string()]));

        // 封顶生效。
        let capped = build_jobs(&tmpl, std::slice::from_ref(&payloads), AttackMode::ClusterBomb, 3);
        assert_eq!(capped.len(), 3);
    }

    #[test]
    fn build_jobs_cluster_bomb_per_position_blocks() {
        let tmpl = Template::parse("/x?a=§1§&b=§2§");
        // 注入点 1 用 [p,q],注入点 2 用 [9]。
        let blocks = vec![
            vec!["p".to_string(), "q".to_string()],
            vec!["9".to_string()],
        ];
        let jobs = build_jobs(&tmpl, &blocks, AttackMode::ClusterBomb, ATTACK_CAP);
        let combos: Vec<Vec<String>> = jobs.iter().map(|j| j.values.clone()).collect();
        assert_eq!(combos.len(), 2); // 2 × 1
        assert!(combos.contains(&vec!["p".to_string(), "9".to_string()]));
        assert!(combos.contains(&vec!["q".to_string(), "9".to_string()]));
    }

    #[test]
    fn attack_total_estimates() {
        assert_eq!(attack_total(AttackMode::Sniper, 2, 3), 6);
        assert_eq!(attack_total(AttackMode::BatteringRam, 2, 3), 3);
        assert_eq!(attack_total(AttackMode::ClusterBomb, 3, 4), 64);
        assert_eq!(attack_total(AttackMode::Sniper, 0, 3), 0);
    }

    #[test]
    fn fix_content_length_rewrites_existing_header() {
        let mut req = ReplayRequest {
            method: "POST".into(),
            scheme: "https".into(),
            host: "h".into(),
            port: 443,
            path: "/".into(),
            headers: vec![("Content-Length".into(), "0".into())],
            body: b"abcde".to_vec(),
        };
        fix_content_length(&mut req);
        assert_eq!(
            req.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .map(|(_, v)| v.as_str()),
            Some("5")
        );
    }

    #[test]
    fn list_payloads_and_blocks_split() {
        // 无分隔 → 单块,跳过空行。
        let text = "a\n\n  \nb\nc\n";
        assert_eq!(list_payloads(text), vec!["a", "b", "c"]);
        assert_eq!(split_payload_blocks(text).len(), 1);

        // `---` 分隔 → 多块(每注入点一块);扁平化跨块。
        let multi = "a\nb\n---\nx\ny\n";
        let blocks = split_payload_blocks(multi);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], vec!["a", "b"]);
        assert_eq!(blocks[1], vec!["x", "y"]);
        assert_eq!(list_payloads(multi), vec!["a", "b", "x", "y"]);
    }

    #[test]
    fn extract_value_pulls_capture_group() {
        let flow = HttpFlow::request("GET", "https", "h", 443, "/", vec![], vec![])
            .with_response(
                200,
                vec![],
                b"<html>token=deadbeef99; rest</html>".to_vec(),
                5,
            );
        let re = Regex::new("token=([0-9a-f]+)").unwrap();
        assert_eq!(extract_value(&flow, &re), Some("deadbeef99".to_string()));
        // 无捕获组 → 返回整体匹配。
        let re2 = Regex::new("token=[0-9a-f]+").unwrap();
        assert_eq!(extract_value(&flow, &re2), Some("token=deadbeef99".to_string()));
        // 不匹配 → None。
        assert_eq!(extract_value(&flow, &Regex::new("nope=(\\d+)").unwrap()), None);
    }

    #[test]
    fn sorted_indices_orders_by_key_and_dir() {
        let results = vec![
            result_with_len(0, "a", 300, 200), // idx0
            result_with_len(1, "b", 100, 404), // idx1
            result_with_len(2, "c", 200, 500), // idx2
        ];
        // 按长度升序:100,200,300 → 行 1,2,0。
        assert_eq!(sorted_indices(&results, SortBy::Length, false), vec![1, 2, 0]);
        // 降序反转。
        assert_eq!(sorted_indices(&results, SortBy::Length, true), vec![0, 2, 1]);
        // 默认按发出顺序。
        assert_eq!(sorted_indices(&results, SortBy::Order, false), vec![0, 1, 2]);
        // 按状态升序:200,404,500 → 0,1,2。
        assert_eq!(sorted_indices(&results, SortBy::Status, false), vec![0, 1, 2]);
    }

    #[test]
    fn num_range_parse_count_and_gen() {
        assert_eq!(parse_num_range("1-5"), Some((1, 5, 1)));
        assert_eq!(parse_num_range("0-100:5"), Some((0, 100, 5)));
        assert_eq!(parse_num_range("7"), Some((7, 7, 1)));
        assert_eq!(parse_num_range("1-5:0"), None); // 步长 0 非法
        assert_eq!(parse_num_range(""), None);

        assert_eq!(num_range_count(1, 5, 1), 5);
        assert_eq!(num_range_count(0, 100, 5), 21);
        assert_eq!(num_range_count(5, 1, 1), 0); // 步长方向与区间不符

        assert_eq!(gen_numbers(1, 5, 2, 100), vec!["1", "3", "5"]);
        assert_eq!(gen_numbers(5, 1, -2, 100), vec!["5", "3", "1"]);
        assert_eq!(gen_numbers(1, 100, 1, 3).len(), 3); // cap 生效
    }

    #[test]
    fn brute_parse_count_and_gen() {
        assert_eq!(parse_len_range("1-3"), Some((1, 3)));
        assert_eq!(parse_len_range("2"), Some((2, 2)));
        assert_eq!(unique_chars("aab bc"), vec!['a', 'b', 'c']); // 去重 + 去空白

        assert_eq!(brute_count(2, 1, 2), 2 + 4); // 2^1 + 2^2
        assert_eq!(
            gen_brute(&['a', 'b'], 1, 2, 100),
            vec!["a", "b", "aa", "ab", "ba", "bb"]
        );
        assert_eq!(gen_brute(&['a', 'b'], 1, 3, 3).len(), 3); // cap 生效
    }

    #[test]
    fn apply_procs_order_and_affix() {
        // 仅前后缀。
        assert_eq!(apply_procs("x", 0, "p_", "_s"), "p_x_s");
        // URL 编码 / Base64 / 大写 / MD5。
        assert_eq!(apply_procs("a b", ProcOp::UrlEncode.bit(), "", ""), "a%20b");
        assert_eq!(apply_procs("Man", ProcOp::Base64.bit(), "", ""), "TWFu");
        assert_eq!(apply_procs("abc", ProcOp::Upper.bit(), "", ""), "ABC");
        assert_eq!(
            apply_procs("abc", ProcOp::Md5.bit(), "", ""),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        // 处理 + 前后缀:base64 后包前后缀。
        assert_eq!(apply_procs("Man", ProcOp::Base64.bit(), "x", "y"), "xTWFuy");
    }

    #[allow(clippy::too_many_arguments)]
    fn spec<'a>(
        kind: PayloadKind,
        list: &'a str,
        numbers: &'a str,
        charset: &'a str,
        lengths: &'a str,
        mask: u16,
        prefix: &'a str,
        suffix: &'a str,
    ) -> GenSpec<'a> {
        GenSpec {
            kind,
            list,
            numbers,
            charset,
            lengths,
            mask,
            prefix,
            suffix,
        }
    }

    #[test]
    fn genspec_generates_each_kind() {
        let list = spec(PayloadKind::List, "a\nb\n\nc", "", "", "", 0, "", "");
        assert_eq!(list.base_count(), 3);
        assert_eq!(list.generate(100), vec!["a", "b", "c"]);

        let nums = spec(PayloadKind::Numbers, "", "1-3", "", "", 0, "", "");
        assert_eq!(nums.base_count(), 3);
        assert_eq!(nums.generate(100), vec!["1", "2", "3"]);

        let brute = spec(PayloadKind::Brute, "", "", "ab", "2", 0, "", "");
        assert_eq!(brute.base_count(), 4);
        assert_eq!(brute.generate(100), vec!["aa", "ab", "ba", "bb"]);

        // 处理器:数字 + 前缀 + base64。
        let proc = spec(PayloadKind::Numbers, "", "1-2", "", "", ProcOp::Base64.bit(), "id=", "");
        assert_eq!(
            proc.generate(100),
            vec![
                format!("id={}", scry_codec::base64_encode("1")),
                format!("id={}", scry_codec::base64_encode("2")),
            ]
        );
    }

    fn result_with_len(idx: usize, payload: &str, body_len: usize, status: u16) -> AttackResult {
        let flow = HttpFlow::request("GET", "https", "h", 443, "/", vec![], vec![])
            .with_response(status, vec![], vec![b'x'; body_len], 10);
        AttackResult {
            idx,
            payload: payload.to_string(),
            position: None,
            flow: Some(flow),
            error: None,
        }
    }

    #[test]
    fn csv_escapes_and_modal_length_outlier() {
        let results = vec![
            result_with_len(0, "a,b", 100, 200),
            result_with_len(1, "x", 100, 200),
            result_with_len(2, "y", 555, 200),
        ];
        let csv = results_to_csv(&results);
        assert!(csv.starts_with("idx,payload,position,status,length,ms,error\n"));
        assert!(csv.contains("\"a,b\"")); // 含逗号的字段被引号包裹
        // 100 出现两次 → 基线长度;555 是异常。
        assert_eq!(modal_length(&results), Some(100));
    }
}
