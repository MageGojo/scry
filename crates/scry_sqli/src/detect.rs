//! 命中判定 + 响应相似度 + 外带数据解析(全部纯函数)。

use std::collections::HashMap;

use scry_core::HttpFlow;

use crate::dialect::Dbms;
use crate::EXFIL_MARK;

/// 布尔盲注:判「真」页面与原始页面的相似度下限。
pub const BOOL_SIM_HIGH: f64 = 0.95;
/// 布尔盲注:真 / 假页面相对原始的相似度差至少这么大才算可区分。
pub const BOOL_SIM_GAP: f64 = 0.05;
/// 相似度计算时单边最多取的字符数(防超大响应体拖慢)。
const SIM_CAP: usize = 200_000;

/// 一个用于判定的精简响应视图(状态码 + 解码后文本)。
#[derive(Clone, Debug)]
pub struct RespView {
    pub status: u16,
    pub body: String,
}

impl RespView {
    /// 从流里取出(响应体按 Content-Encoding / charset 解码成文本)。
    pub fn of(flow: &HttpFlow) -> Self {
        let body = if flow.resp_body.is_empty() {
            String::new()
        } else {
            scry_decode::display_text(&flow.resp_headers, &flow.resp_body)
        };
        RespView {
            status: flow.status,
            body,
        }
    }
}

/// 在(解码后的)响应文本里识别数据库报错特征 → 命中则返回对应 [`Dbms`]。
/// 调用方需先确认该特征**不在基线响应里**(避免把页面本就有的字样当注入)。
pub fn match_error_dbms(text: &str) -> Option<Dbms> {
    let low = text.to_ascii_lowercase();
    Dbms::ALL
        .into_iter()
        .find(|d| d.error_signatures().iter().any(|s| low.contains(s)))
}

/// 两段文本的相似度 ∈ [0,1](字符二元组 Dice 系数;O(n),适合大响应体)。
pub fn similarity(a: &str, b: &str) -> f64 {
    if a == b {
        return 1.0;
    }
    let ma = bigrams(a);
    let mb = bigrams(b);
    if ma.is_empty() || mb.is_empty() {
        return 0.0;
    }
    let total_a: i64 = ma.values().map(|v| *v as i64).sum();
    let total_b: i64 = mb.values().map(|v| *v as i64).sum();
    let mut inter: i64 = 0;
    for (k, va) in &ma {
        if let Some(vb) = mb.get(k) {
            inter += (*va).min(*vb) as i64;
        }
    }
    2.0 * inter as f64 / (total_a + total_b) as f64
}

/// 字符二元组计数(取前 [`SIM_CAP`] 个字符)。
fn bigrams(s: &str) -> HashMap<(char, char), u32> {
    let chars: Vec<char> = s.chars().take(SIM_CAP).collect();
    let mut m = HashMap::new();
    for w in chars.windows(2) {
        *m.entry((w[0], w[1])).or_insert(0) += 1;
    }
    m
}

/// 布尔盲注判定:恒真页面接近原始、恒假页面明显偏离即判可注入。
///
/// 强信号优先:真页状态码 = 原始、假页状态码 ≠ 原始(且假页有响应)直接成立;
/// 否则比相似度:`sim(原始,真) ≥ HIGH` 且 `sim(原始,真) − sim(原始,假) ≥ GAP`。
pub fn judge_boolean(base: &RespView, truthy: &RespView, falsy: &RespView) -> bool {
    if truthy.status == 0 || falsy.status == 0 {
        return false;
    }
    if truthy.status == base.status && falsy.status != base.status {
        return true;
    }
    let st = similarity(&base.body, &truthy.body);
    let sf = similarity(&base.body, &falsy.body);
    st >= BOOL_SIM_HIGH && (st - sf) >= BOOL_SIM_GAP
}

/// 时间盲注判定(只看绝对耗时):响应耗时 ≥ 期望睡眠的 80%。
pub fn judge_time(secs: u32, elapsed_ms: u64) -> bool {
    elapsed_ms >= (secs as u64) * 1000 * 8 / 10
}

/// 时间盲注判定(带基线,抗网络抖动 / 慢端点):相对基线多出的耗时 ≥ 期望的 70%,
/// 且绝对耗时 ≥ 期望的 80%。
pub fn judge_time_delta(secs: u32, baseline_ms: u64, elapsed_ms: u64) -> bool {
    let need = (secs as u64) * 1000;
    elapsed_ms.saturating_sub(baseline_ms) >= need * 7 / 10 && elapsed_ms >= need * 8 / 10
}

/// 从响应文本里切出被 [`EXFIL_MARK`] 两侧包裹的外带结果(报错回显 / 联合查询列)。
pub fn parse_exfil(text: &str) -> Option<String> {
    let m = EXFIL_MARK;
    let start = text.find(m)? + m.len();
    let rest = &text[start..];
    let end = rest.find(m)?;
    let val = &rest[..end];
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rv(status: u16, body: &str) -> RespView {
        RespView {
            status,
            body: body.to_string(),
        }
    }

    #[test]
    fn fingerprints_each_dbms_error() {
        assert_eq!(
            match_error_dbms("You have an error in your SQL syntax; check ..."),
            Some(Dbms::MySql)
        );
        assert_eq!(
            match_error_dbms("ERROR: syntax error at or near \"'\""),
            Some(Dbms::PostgreSql)
        );
        assert_eq!(
            match_error_dbms("Unclosed quotation mark after the character string"),
            Some(Dbms::MsSql)
        );
        assert_eq!(match_error_dbms("ORA-00933: SQL command not properly ended"), Some(Dbms::Oracle));
        assert_eq!(match_error_dbms("SQLITE_ERROR: near \"'\": syntax error"), Some(Dbms::Sqlite));
        assert_eq!(match_error_dbms("just a normal page"), None);
    }

    #[test]
    fn similarity_bounds() {
        assert_eq!(similarity("hello world", "hello world"), 1.0);
        assert!(similarity("the quick brown fox", "the quick brown box") > 0.7);
        assert!(similarity("aaaaaa", "zzzzzz") < 0.1);
        assert_eq!(similarity("", ""), 1.0);
        assert_eq!(similarity("abc", ""), 0.0);
    }

    #[test]
    fn boolean_judged_by_similarity() {
        let base = rv(200, "Welcome admin, here are your 12 orders. <table>...lots of rows...</table>");
        // 真页几乎等于原始,假页是「没有结果」的短页 → 可区分。
        let truthy = base.clone();
        let falsy = rv(200, "No results found.");
        assert!(judge_boolean(&base, &truthy, &falsy));
        // 真假页都等于原始 → 不可区分。
        assert!(!judge_boolean(&base, &base.clone(), &base.clone()));
    }

    #[test]
    fn boolean_judged_by_status_code() {
        let base = rv(200, "ok");
        let truthy = rv(200, "ok");
        let falsy = rv(500, "Internal Server Error");
        assert!(judge_boolean(&base, &truthy, &falsy));
        // 无响应不判定。
        assert!(!judge_boolean(&base, &rv(0, ""), &falsy));
    }

    #[test]
    fn time_judgement() {
        assert!(judge_time(5, 4200));
        assert!(!judge_time(5, 1000));
        assert!(judge_time_delta(5, 200, 5300));
        // 端点本就慢(基线 5s),注入也 5s → 增量不够 → 不判定。
        assert!(!judge_time_delta(5, 5000, 5300));
    }

    #[test]
    fn parse_exfil_between_markers() {
        let text = "XPATH syntax error: '~qScRyQ8.0.32-MariaDBqScRyQ'";
        assert_eq!(parse_exfil(text).as_deref(), Some("8.0.32-MariaDB"));
        // 只有一个标记 → 不猜。
        assert_eq!(parse_exfil("noise qScRyQ partial"), None);
        assert_eq!(parse_exfil("nothing here"), None);
    }
}
