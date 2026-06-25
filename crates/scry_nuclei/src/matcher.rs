//! matcher 求值:把一个 [`Matcher`] 应用到响应 [`RespData`] 上判命中。

use crate::dsl::{self, DslContext};
use crate::template::{Matcher, MatcherKind, Part};
use crate::RespData;
use regex::RegexBuilder;

/// 把响应按 `part` 投影成可搜索文本。
pub(crate) fn part_text(part: Part, resp: &RespData) -> String {
    match part {
        Part::Body => String::from_utf8_lossy(resp.body).into_owned(),
        Part::Header => header_text(resp),
        Part::All => format!("{}\n{}", header_text(resp), String::from_utf8_lossy(resp.body)),
    }
}

/// 全部响应头拼成 `Key: Value\n` 文本。
pub(crate) fn header_text(resp: &RespData) -> String {
    let mut s = String::new();
    for (k, v) in resp.headers {
        s.push_str(k);
        s.push_str(": ");
        s.push_str(v);
        s.push('\n');
    }
    s
}

/// 把响应按 `part` 投影成原始字节(binary matcher 用)。
fn part_bytes(part: Part, resp: &RespData) -> Vec<u8> {
    match part {
        Part::Body => resp.body.to_vec(),
        Part::Header => header_text(resp).into_bytes(),
        Part::All => {
            let mut b = header_text(resp).into_bytes();
            b.push(b'\n');
            b.extend_from_slice(resp.body);
            b
        }
    }
}

/// 单个 matcher 是否命中(已处理 `negative` 取反)。
pub fn matcher_matches(m: &Matcher, resp: &RespData) -> bool {
    let raw = match &m.kind {
        MatcherKind::Status(codes) => codes.contains(&resp.status),
        MatcherKind::Size(sizes) => sizes.contains(&resp.body.len()),
        MatcherKind::Word(words) => {
            let mut hay = part_text(m.part, resp);
            let needles: Vec<String> = if m.case_insensitive {
                hay = hay.to_lowercase();
                words.iter().map(|w| w.to_lowercase()).collect()
            } else {
                words.clone()
            };
            combine(m.condition, needles.iter().map(|w| hay.contains(w)))
        }
        MatcherKind::Regex(patterns) => {
            let hay = part_text(m.part, resp);
            combine(
                m.condition,
                patterns.iter().map(|p| {
                    RegexBuilder::new(p)
                        .case_insensitive(m.case_insensitive)
                        .size_limit(1 << 20)
                        .build()
                        .map(|re| re.is_match(&hay))
                        .unwrap_or(false)
                }),
            )
        }
        MatcherKind::Binary(bins) => {
            let hay = part_bytes(m.part, resp);
            combine(m.condition, bins.iter().map(|b| contains_bytes(&hay, b)))
        }
        MatcherKind::Dsl(exprs) => {
            // dsl 的多表达式按 condition 组合;part 对 dsl 无意义(表达式自取 body/header)。
            let (body, headers) = dsl_strings(resp);
            let ctx = DslContext {
                status_code: resp.status as i64,
                content_length: resp.body.len() as i64,
                body: &body,
                all_headers: &headers,
                duration: resp.duration_ms as i64,
            };
            combine(m.condition, exprs.iter().map(|e| dsl::eval_bool(e, &ctx)))
        }
    };
    raw ^ m.negative
}

/// matcher 展示名(`name` 优先,否则类型)。
pub fn matcher_label(m: &Matcher) -> String {
    if let Some(n) = &m.name {
        return n.clone();
    }
    match &m.kind {
        MatcherKind::Word(_) => "word",
        MatcherKind::Regex(_) => "regex",
        MatcherKind::Status(_) => "status",
        MatcherKind::Size(_) => "size",
        MatcherKind::Dsl(_) => "dsl",
        MatcherKind::Binary(_) => "binary",
    }
    .to_string()
}

/// 按 and/or 组合一组布尔(空 = false)。
fn combine(cond: crate::template::Condition, mut it: impl Iterator<Item = bool>) -> bool {
    use crate::template::Condition;
    match cond {
        Condition::And => it.all(|x| x),     // 空 → true;但调用方保证非空
        Condition::Or => it.any(|x| x),
    }
}

/// 子串字节扫描(binary matcher)。
fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

/// 由响应取出 dsl 求值所需的文本(body 文本 + 全部头文本);调用方持有后构造 [`DslContext`]。
pub(crate) fn dsl_strings(resp: &RespData) -> (String, String) {
    (
        String::from_utf8_lossy(resp.body).into_owned(),
        header_text(resp),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::{parse_template, Condition};
    use crate::RespData;

    fn resp<'a>(status: u16, headers: &'a [(String, String)], body: &'a str) -> RespData<'a> {
        RespData::new(status, headers, body.as_bytes(), 10)
    }

    fn word_matcher(words: &[&str], cond: Condition, neg: bool, ci: bool) -> Matcher {
        Matcher {
            kind: MatcherKind::Word(words.iter().map(|s| s.to_string()).collect()),
            part: Part::Body,
            condition: cond,
            negative: neg,
            case_insensitive: ci,
            name: None,
        }
    }

    #[test]
    fn word_and_or() {
        let r = resp(200, &[], "alpha beta gamma");
        assert!(matcher_matches(
            &word_matcher(&["alpha", "beta"], Condition::And, false, false),
            &r
        ));
        assert!(!matcher_matches(
            &word_matcher(&["alpha", "zzz"], Condition::And, false, false),
            &r
        ));
        assert!(matcher_matches(
            &word_matcher(&["zzz", "gamma"], Condition::Or, false, false),
            &r
        ));
    }

    #[test]
    fn case_insensitive_and_negative() {
        let r = resp(200, &[], "Hello World");
        assert!(matcher_matches(
            &word_matcher(&["hello"], Condition::Or, false, true),
            &r
        ));
        // negative:body 不含 "missing" → 命中。
        assert!(matcher_matches(
            &word_matcher(&["missing"], Condition::Or, true, false),
            &r
        ));
    }

    #[test]
    fn status_size_regex_binary() {
        let headers = vec![("Server".to_string(), "nginx/1.21".to_string())];
        let r = resp(200, &headers, "id=12345");
        let status = Matcher {
            kind: MatcherKind::Status(vec![200, 301]),
            part: Part::Body,
            condition: Condition::Or,
            negative: false,
            case_insensitive: false,
            name: None,
        };
        assert!(matcher_matches(&status, &r));
        let size = Matcher {
            kind: MatcherKind::Size(vec![8]),
            ..status.clone()
        };
        assert!(matcher_matches(&size, &r));
        let rx = Matcher {
            kind: MatcherKind::Regex(vec!["id=[0-9]+".to_string()]),
            ..status.clone()
        };
        assert!(matcher_matches(&rx, &r));
        // header part regex.
        let hrx = Matcher {
            kind: MatcherKind::Regex(vec!["nginx".to_string()]),
            part: Part::Header,
            ..status.clone()
        };
        assert!(matcher_matches(&hrx, &r));
        let bin = Matcher {
            kind: MatcherKind::Binary(vec![b"id=".to_vec()]),
            ..status
        };
        assert!(matcher_matches(&bin, &r));
    }

    #[test]
    fn dsl_matcher() {
        let r = resp(200, &[], "version = 1.2.3");
        let t = parse_template(
            "id: t\ninfo:\n  name: t\nhttp:\n  - path: [\"{{BaseURL}}/\"]\n    matchers:\n      - type: dsl\n        dsl:\n          - \"status_code == 200 && contains(body, \\\"version\\\")\"\n",
        )
        .unwrap();
        assert!(matcher_matches(&t.requests[0].matchers[0], &r));
    }
}
