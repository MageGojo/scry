//! extractor 求值:命中后从响应里抽取证据(regex 捕获组 / 响应头 kval / dsl)。

use crate::dsl::{self, DslContext};
use crate::matcher::{dsl_strings, part_text};
use crate::template::{Extractor, ExtractorKind};
use crate::RespData;
use regex::Regex;

/// 每个 extractor 最多抽取的值数(防爆量)。
const EXTRACT_CAP: usize = 8;

/// 运行一个 extractor,返回抽到的值(去重、有上限)。
pub fn extract(e: &Extractor, resp: &RespData) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    match &e.kind {
        ExtractorKind::Regex { patterns, group } => {
            let hay = part_text(e.part, resp);
            for p in patterns {
                let Ok(re) = Regex::new(p) else {
                    continue;
                };
                for caps in re.captures_iter(&hay) {
                    let val = caps
                        .get(*group)
                        .or_else(|| caps.get(0))
                        .map(|m| m.as_str().to_string());
                    if let Some(v) = val {
                        push_unique(&mut out, v);
                        if out.len() >= EXTRACT_CAP {
                            return out;
                        }
                    }
                }
            }
        }
        ExtractorKind::Kval(keys) => {
            for key in keys {
                if let Some(v) = header_lookup(resp, key) {
                    push_unique(&mut out, v);
                }
            }
        }
        ExtractorKind::Dsl(exprs) => {
            let (body, headers) = dsl_strings(resp);
            let ctx = DslContext {
                status_code: resp.status as i64,
                content_length: resp.body.len() as i64,
                body: &body,
                all_headers: &headers,
                duration: resp.duration_ms as i64,
            };
            for ex in exprs {
                if let Some(v) = dsl::eval(ex, &ctx) {
                    let s = v.to_text();
                    if !s.is_empty() {
                        push_unique(&mut out, s);
                    }
                }
            }
        }
    }
    out
}

/// extractor 的展示名(name 优先,否则类型)。
pub fn extractor_label(e: &Extractor) -> String {
    if let Some(n) = &e.name {
        return n.clone();
    }
    match &e.kind {
        ExtractorKind::Regex { .. } => "regex".into(),
        ExtractorKind::Kval(_) => "kval".into(),
        ExtractorKind::Dsl(_) => "dsl".into(),
    }
}

/// 大小写不敏感、`-`/`_` 容错地取响应头值(kval 用)。
fn header_lookup(resp: &RespData, key: &str) -> Option<String> {
    let want = normalize_key(key);
    resp.headers
        .iter()
        .find(|(k, _)| normalize_key(k) == want)
        .map(|(_, v)| v.clone())
}

fn normalize_key(k: &str) -> String {
    k.trim().to_ascii_lowercase().replace('_', "-")
}

fn push_unique(out: &mut Vec<String>, v: String) {
    if !out.contains(&v) {
        out.push(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::Part;
    use crate::RespData;

    fn resp<'a>(headers: &'a [(String, String)], body: &'a str) -> RespData<'a> {
        RespData::new(200, headers, body.as_bytes(), 5)
    }

    #[test]
    fn regex_group_extraction() {
        let e = Extractor {
            kind: ExtractorKind::Regex {
                patterns: vec!["version = ([0-9.]+)".to_string()],
                group: 1,
            },
            part: Part::Body,
            name: Some("ver".into()),
        };
        let r = resp(&[], "app version = 4.5.6 ok");
        assert_eq!(extract(&e, &r), vec!["4.5.6".to_string()]);
        assert_eq!(extractor_label(&e), "ver");
    }

    #[test]
    fn kval_header_lookup() {
        let e = Extractor {
            kind: ExtractorKind::Kval(vec!["x_powered_by".into(), "server".into()]),
            part: Part::Header,
            name: None,
        };
        let headers = vec![
            ("Server".to_string(), "nginx".to_string()),
            ("X-Powered-By".to_string(), "PHP/8.1".to_string()),
        ];
        let r = resp(&headers, "");
        let got = extract(&e, &r);
        assert!(got.contains(&"PHP/8.1".to_string()));
        assert!(got.contains(&"nginx".to_string()));
    }
}
