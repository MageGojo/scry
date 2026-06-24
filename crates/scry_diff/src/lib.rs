//! Scry 比较器内核(对标 Burp Comparer):对两段文本做 **LCS diff**,产出可着色的
//! 线性片段序列(相同 / 新增 / 删除)+ 统计与相似度。纯函数、零 IO,便于单测与复用。
//!
//! 不变量:`spans` 顺序拼接时,
//! - 跳过 [`ChangeTag::Insert`] 还原出 A;
//! - 跳过 [`ChangeTag::Delete`] 还原出 B。

/// diff 的对比粒度。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Granularity {
    /// 按行(含行尾换行)。适合比较报文 / 配置。
    Line,
    /// 按词(空白与非空白交替成段)。适合比较句子 / 头部值。
    Word,
    /// 按字符(Unicode 标量)。最细,适合短串。
    Char,
}

impl Granularity {
    pub const ALL: [Granularity; 3] = [Granularity::Line, Granularity::Word, Granularity::Char];

    /// 英文标签(UI 经 i18n 表转中文)。
    pub fn label(self) -> &'static str {
        match self {
            Granularity::Line => "Lines",
            Granularity::Word => "Words",
            Granularity::Char => "Chars",
        }
    }
}

/// 一个片段的变化类型。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChangeTag {
    /// 两侧相同。
    Equal,
    /// 仅出现在 B(新增)。
    Insert,
    /// 仅出现在 A(删除)。
    Delete,
}

/// 一段连续的、同一变化类型的文本。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Span {
    pub tag: ChangeTag,
    pub text: String,
}

/// diff 结果。
#[derive(Clone, PartialEq, Debug)]
pub struct DiffReport {
    /// 线性片段序列(供 inline 着色渲染)。
    pub spans: Vec<Span>,
    /// 相同的 token 数。
    pub equal_tokens: usize,
    /// 新增(仅 B)的 token 数。
    pub inserted_tokens: usize,
    /// 删除(仅 A)的 token 数。
    pub deleted_tokens: usize,
    /// 相似度(Dice 系数,0..=1):`2*equal / (len_a + len_b)`。
    pub similarity: f64,
    /// 两段是否完全相同。
    pub identical: bool,
}

/// DP 表上限(token_a × token_b);超出则退化为「整段删除 + 整段新增」避免占用过多内存。
const MAX_CELLS: usize = 4_000_000;

/// 对 `a`、`b` 按粒度 `g` 求 diff。
pub fn diff(a: &str, b: &str, g: Granularity) -> DiffReport {
    let ta = tokenize(a, g);
    let tb = tokenize(b, g);
    let (la, lb) = (ta.len(), tb.len());

    if a == b {
        let mut spans = Vec::new();
        if !a.is_empty() {
            spans.push(Span {
                tag: ChangeTag::Equal,
                text: a.to_string(),
            });
        }
        return DiffReport {
            spans,
            equal_tokens: la,
            inserted_tokens: 0,
            deleted_tokens: 0,
            similarity: 1.0,
            identical: true,
        };
    }

    // 输入过大:不跑 O(n*m) DP,退化为整段替换。
    if la.saturating_mul(lb) > MAX_CELLS {
        let mut spans = Vec::new();
        if !a.is_empty() {
            spans.push(Span {
                tag: ChangeTag::Delete,
                text: a.to_string(),
            });
        }
        if !b.is_empty() {
            spans.push(Span {
                tag: ChangeTag::Insert,
                text: b.to_string(),
            });
        }
        return DiffReport {
            spans,
            equal_tokens: 0,
            inserted_tokens: lb,
            deleted_tokens: la,
            similarity: 0.0,
            identical: false,
        };
    }

    // dp[i][j] = LCS(ta[i..], tb[j..]) 的长度。
    let mut dp = vec![vec![0usize; lb + 1]; la + 1];
    for i in (0..la).rev() {
        for j in (0..lb).rev() {
            dp[i][j] = if ta[i] == tb[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }

    // 回溯生成操作序列。
    let mut raw: Vec<(ChangeTag, &str)> = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    let (mut equal, mut ins, mut del) = (0usize, 0usize, 0usize);
    while i < la && j < lb {
        if ta[i] == tb[j] {
            raw.push((ChangeTag::Equal, ta[i]));
            equal += 1;
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            raw.push((ChangeTag::Delete, ta[i]));
            del += 1;
            i += 1;
        } else {
            raw.push((ChangeTag::Insert, tb[j]));
            ins += 1;
            j += 1;
        }
    }
    while i < la {
        raw.push((ChangeTag::Delete, ta[i]));
        del += 1;
        i += 1;
    }
    while j < lb {
        raw.push((ChangeTag::Insert, tb[j]));
        ins += 1;
        j += 1;
    }

    // 合并相邻同类型片段。
    let mut spans: Vec<Span> = Vec::new();
    for (tag, text) in raw {
        if let Some(last) = spans.last_mut() {
            if last.tag == tag {
                last.text.push_str(text);
                continue;
            }
        }
        spans.push(Span {
            tag,
            text: text.to_string(),
        });
    }

    let similarity = if la + lb == 0 {
        1.0
    } else {
        2.0 * equal as f64 / (la + lb) as f64
    };

    DiffReport {
        spans,
        equal_tokens: equal,
        inserted_tokens: ins,
        deleted_tokens: del,
        similarity,
        identical: false,
    }
}

/// 按粒度切词,返回的切片顺序拼接 == 原文(保证可还原)。
fn tokenize(s: &str, g: Granularity) -> Vec<&str> {
    match g {
        Granularity::Char => {
            let mut v = Vec::with_capacity(s.len());
            let mut idx = 0;
            for ch in s.chars() {
                let len = ch.len_utf8();
                v.push(&s[idx..idx + len]);
                idx += len;
            }
            v
        }
        Granularity::Word => tokenize_words(s),
        Granularity::Line => tokenize_lines(s),
    }
}

/// 词级切分:空白段与非空白段交替,各成一个 token。
fn tokenize_words(s: &str) -> Vec<&str> {
    let mut v = Vec::new();
    let mut start = 0usize;
    let mut cur_ws: Option<bool> = None;
    let mut end = 0usize;
    for (i, ch) in s.char_indices() {
        let ws = ch.is_whitespace();
        match cur_ws {
            None => {
                cur_ws = Some(ws);
                start = i;
            }
            Some(prev) if prev != ws => {
                v.push(&s[start..i]);
                start = i;
                cur_ws = Some(ws);
            }
            _ => {}
        }
        end = i + ch.len_utf8();
    }
    if cur_ws.is_some() {
        v.push(&s[start..end]);
    }
    v
}

/// 行级切分:每行包含其末尾换行符;最后一行若无换行则为剩余部分。
fn tokenize_lines(s: &str) -> Vec<&str> {
    let mut v = Vec::new();
    let mut start = 0usize;
    for (i, &b) in s.as_bytes().iter().enumerate() {
        if b == b'\n' {
            v.push(&s[start..=i]);
            start = i + 1;
        }
    }
    if start < s.len() {
        v.push(&s[start..]);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 还原不变量:跳过 Insert == A;跳过 Delete == B。
    fn assert_reconstructs(a: &str, b: &str, r: &DiffReport) {
        let from_a: String = r
            .spans
            .iter()
            .filter(|s| s.tag != ChangeTag::Insert)
            .map(|s| s.text.as_str())
            .collect();
        let from_b: String = r
            .spans
            .iter()
            .filter(|s| s.tag != ChangeTag::Delete)
            .map(|s| s.text.as_str())
            .collect();
        assert_eq!(from_a, a, "skip-insert should rebuild A");
        assert_eq!(from_b, b, "skip-delete should rebuild B");
    }

    #[test]
    fn identical() {
        let r = diff("same text", "same text", Granularity::Char);
        assert!(r.identical);
        assert_eq!(r.similarity, 1.0);
        assert_eq!(r.inserted_tokens, 0);
        assert_eq!(r.deleted_tokens, 0);
        assert!(r.spans.iter().all(|s| s.tag == ChangeTag::Equal));
    }

    #[test]
    fn pure_insert() {
        let r = diff("ab", "abc", Granularity::Char);
        assert_eq!(r.deleted_tokens, 0);
        assert_eq!(r.inserted_tokens, 1);
        assert_reconstructs("ab", "abc", &r);
    }

    #[test]
    fn pure_delete() {
        let r = diff("abc", "ab", Granularity::Char);
        assert_eq!(r.inserted_tokens, 0);
        assert_eq!(r.deleted_tokens, 1);
        assert_reconstructs("abc", "ab", &r);
    }

    #[test]
    fn word_diff_reconstructs() {
        let a = "the quick brown fox";
        let b = "the slow brown fox";
        let r = diff(a, b, Granularity::Word);
        assert!(!r.identical);
        assert!(r.equal_tokens > 0);
        assert_reconstructs(a, b, &r);
        // "the ", "brown", " ", "fox" 等保持相同;"quick"→"slow" 是一删一增。
        assert!(r.deleted_tokens >= 1 && r.inserted_tokens >= 1);
    }

    #[test]
    fn line_diff_reconstructs() {
        let a = "alpha\nbeta\ngamma\n";
        let b = "alpha\nBETA\ngamma\n";
        let r = diff(a, b, Granularity::Line);
        assert_reconstructs(a, b, &r);
        assert!(r.similarity > 0.0 && r.similarity < 1.0);
    }

    #[test]
    fn unicode_char_diff() {
        let a = "你好世界";
        let b = "你好地球";
        let r = diff(a, b, Granularity::Char);
        assert_reconstructs(a, b, &r);
        assert_eq!(r.equal_tokens, 2); // 「你」「好」
    }

    #[test]
    fn similarity_bounds() {
        let r = diff("abcdef", "abcxyz", Granularity::Char);
        assert!(r.similarity > 0.0 && r.similarity < 1.0);
        // 3 个相同(abc),各 6 token:2*3/(6+6)=0.5。
        assert!((r.similarity - 0.5).abs() < 1e-9);
    }

    #[test]
    fn empty_inputs() {
        let r = diff("", "hello", Granularity::Char);
        assert_eq!(r.deleted_tokens, 0);
        assert_eq!(r.inserted_tokens, 5);
        assert_reconstructs("", "hello", &r);

        let r2 = diff("", "", Granularity::Char);
        assert!(r2.identical);
        assert!(r2.spans.is_empty());
    }
}
