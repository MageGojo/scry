//! 随机性分析内核:把一批令牌(字符串样本)做字符级 / 比特级香农熵估计 + FIPS 自检,
//! 产出 [`SequencerReport`]。全部纯函数、可单测。

use std::collections::HashSet;

use crate::fips::{self, FIPS_BITS};
use crate::types::{FipsReport, PositionEntropy, Quality, SequencerReport};

/// 报告里最多保留多少个「字符位置熵」用于可视化(总熵仍按全长求和)。
const MAX_POSITIONS: usize = 256;

/// 从多行文本解析令牌:逐行 trim、丢弃空行。
pub fn parse_tokens(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect()
}

/// 香农熵 H = −Σ pᵢ·log2(pᵢ)(单位 bit)。`counts` 为各符号出现次数。
pub fn shannon_entropy(counts: &[usize]) -> f64 {
    let total: usize = counts.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let n = total as f64;
    let mut h = 0.0;
    for &c in counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

/// 各**字符位置**的香农熵(令牌不等长时,靠后位置只统计拥有该位的样本)。
fn char_position_entropy(tokens: &[&[u8]], max_len: usize) -> Vec<PositionEntropy> {
    let mut out = Vec::with_capacity(max_len.min(MAX_POSITIONS));
    for i in 0..max_len {
        let mut counts = [0usize; 256];
        let mut samples = 0usize;
        for t in tokens {
            if let Some(&b) = t.get(i) {
                counts[b as usize] += 1;
                samples += 1;
            }
        }
        let bits = shannon_entropy(&counts);
        if i < MAX_POSITIONS {
            out.push(PositionEntropy {
                index: i,
                bits,
                samples,
            });
        }
    }
    out
}

/// 字符级总熵 = Σ 各字符位置香农熵(对全长求和,不受可视化裁剪影响)。
fn char_entropy_total(tokens: &[&[u8]], max_len: usize) -> f64 {
    let mut total = 0.0;
    for i in 0..max_len {
        let mut counts = [0usize; 256];
        for t in tokens {
            if let Some(&b) = t.get(i) {
                counts[b as usize] += 1;
            }
        }
        total += shannon_entropy(&counts);
    }
    total
}

/// 比特级总熵 = Σ 各比特位置香农熵(MSB-first 展开每个字节)。
fn bit_entropy_total(tokens: &[&[u8]], max_len: usize) -> f64 {
    let max_bits = max_len * 8;
    let mut total = 0.0;
    for j in 0..max_bits {
        let byte_idx = j / 8;
        let bit_idx = 7 - (j % 8);
        let mut ones = 0usize;
        let mut samples = 0usize;
        for t in tokens {
            if let Some(&b) = t.get(byte_idx) {
                samples += 1;
                if (b >> bit_idx) & 1 == 1 {
                    ones += 1;
                }
            }
        }
        total += shannon_entropy(&[samples - ones, ones]);
    }
    total
}

/// 由「字符级有效熵」+ 是否有重复样本定级。重复样本(碰撞)直接判为 [`Quality::Poor`]。
pub fn grade(char_entropy_bits: f64, has_duplicates: bool) -> Quality {
    if has_duplicates {
        return Quality::Poor;
    }
    if char_entropy_bits >= 128.0 {
        Quality::Excellent
    } else if char_entropy_bits >= 80.0 {
        Quality::Strong
    } else if char_entropy_bits >= 48.0 {
        Quality::Reasonable
    } else if char_entropy_bits >= 20.0 {
        Quality::Weak
    } else {
        Quality::Poor
    }
}

/// 把令牌字节展开成「每元素 0/1」的比特流(MSB-first),供 FIPS 使用。
fn expand_bits(tokens: &[&[u8]]) -> Vec<u8> {
    let total_bytes: usize = tokens.iter().map(|t| t.len()).sum();
    let mut bits = Vec::with_capacity(total_bytes * 8);
    for t in tokens {
        for &b in *t {
            for k in (0..8).rev() {
                bits.push((b >> k) & 1);
            }
        }
    }
    bits
}

/// 主分析:对一批令牌产出完整报告。空集 / 单样本也安全返回(指标为 0)。
pub fn analyze(tokens: &[String]) -> SequencerReport {
    let bytes: Vec<&[u8]> = tokens.iter().map(|s| s.as_bytes()).collect();
    let sample_count = bytes.len();
    let unique_count = tokens.iter().collect::<HashSet<_>>().len();
    let min_len = bytes.iter().map(|t| t.len()).min().unwrap_or(0);
    let max_len = bytes.iter().map(|t| t.len()).max().unwrap_or(0);

    let char_positions = char_position_entropy(&bytes, max_len);
    let char_entropy_bits = char_entropy_total(&bytes, max_len);
    let bit_entropy_bits = bit_entropy_total(&bytes, max_len);
    let mean_char_bits = if max_len > 0 {
        char_entropy_bits / max_len as f64
    } else {
        0.0
    };

    let total_ones: usize = bytes
        .iter()
        .flat_map(|t| t.iter())
        .map(|b| b.count_ones() as usize)
        .sum();
    let total_bits: usize = bytes.iter().map(|t| t.len() * 8).sum();
    let one_ratio = if total_bits > 0 {
        total_ones as f64 / total_bits as f64
    } else {
        0.0
    };

    let has_duplicates = unique_count < sample_count;
    let quality = grade(char_entropy_bits, has_duplicates);

    // FIPS:够 20000 bit 才评估(经典阈值按该长度标定)。
    let fips = if total_bits >= FIPS_BITS {
        let stream = expand_bits(&bytes);
        FipsReport {
            total_bits,
            evaluated: true,
            tests: fips::run_fips(&stream),
        }
    } else {
        FipsReport {
            total_bits,
            evaluated: false,
            tests: Vec::new(),
        }
    };

    SequencerReport {
        sample_count,
        unique_count,
        min_len,
        max_len,
        char_entropy_bits,
        bit_entropy_bits,
        mean_char_bits,
        one_ratio,
        quality,
        char_positions,
        fips,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tokens_trims_and_skips_blanks() {
        let v = parse_tokens("  a \n\n b\nc  \n   \n");
        assert_eq!(v, vec!["a", "b", "c"]);
    }

    #[test]
    fn shannon_basic() {
        assert_eq!(shannon_entropy(&[0]), 0.0);
        assert_eq!(shannon_entropy(&[5]), 0.0); // 单符号 → 0
        assert_eq!(shannon_entropy(&[5, 5]), 1.0); // 两等概 → 1 bit
        assert_eq!(shannon_entropy(&[1, 1, 1, 1]), 2.0); // 四等概 → 2 bit
    }

    #[test]
    fn fixed_column_has_zero_entropy() {
        // 所有令牌首字符都是 'A' → 该位置熵 0。
        let toks = vec!["A1".to_string(), "A2".to_string(), "A3".to_string()];
        let r = analyze(&toks);
        assert_eq!(r.char_positions[0].bits, 0.0);
        assert!(r.char_positions[1].bits > 0.0);
    }

    #[test]
    fn duplicates_force_poor() {
        let toks = vec!["abcd".to_string(), "abcd".to_string(), "wxyz".to_string()];
        let r = analyze(&toks);
        assert!(r.has_duplicates());
        assert_eq!(r.quality, Quality::Poor);
    }

    #[test]
    fn grade_thresholds() {
        assert_eq!(grade(200.0, false), Quality::Excellent);
        assert_eq!(grade(128.0, false), Quality::Excellent);
        assert_eq!(grade(100.0, false), Quality::Strong);
        assert_eq!(grade(60.0, false), Quality::Reasonable);
        assert_eq!(grade(30.0, false), Quality::Weak);
        assert_eq!(grade(10.0, false), Quality::Poor);
        assert_eq!(grade(200.0, true), Quality::Poor); // 有重复 → 一票否决
    }

    #[test]
    fn empty_input_is_safe() {
        let r = analyze(&[]);
        assert_eq!(r.sample_count, 0);
        assert_eq!(r.char_entropy_bits, 0.0);
        assert_eq!(r.quality, Quality::Poor);
        assert!(!r.fips.evaluated);
    }

    #[test]
    fn bit_entropy_alternating_bytes() {
        // 字节 0x00 与 0xFF:每个比特位置 0/1 各半 → 每位 1 bit,单字节共 8 bit。
        let a = [0u8];
        let b = [255u8];
        let refs: Vec<&[u8]> = vec![&a, &b];
        assert!((bit_entropy_total(&refs, 1) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn high_entropy_set_grades_well_and_runs_fips() {
        // 确定性 xorshift 生成 200 个 16 字节随机令牌(原始字节,非文本编码)。
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut toks = Vec::new();
        for _ in 0..200 {
            let mut s = String::new();
            for _ in 0..16 {
                // 取低字节,映射到 base64 字符集(可见、且每字符 ~6 bit)。
                let v = (next() & 0x3f) as u8;
                let ch = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[v as usize];
                s.push(ch as char);
            }
            toks.push(s);
        }
        let r = analyze(&toks);
        assert!(!r.has_duplicates());
        // 16 字符 × ~6 bit ≈ 96 bit → 至少 Reasonable。
        assert!(r.char_entropy_bits > 80.0, "got {}", r.char_entropy_bits);
        assert!(r.quality >= Quality::Strong);
        // 200×16=3200 字节 = 25600 bit ≥ 20000 → FIPS 已评估。
        assert!(r.fips.evaluated);
        assert_eq!(r.fips.tests.len(), 4);
    }
}
