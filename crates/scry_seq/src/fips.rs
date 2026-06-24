//! FIPS 140-2 上电随机性自检(四项:Monobit / Poker / Runs / Long Run)。
//!
//! 经典阈值按**恰好 20000 bit** 的序列标定,故 [`run_fips`] 要求至少 20000 bit,取前 20000 bit 评估。
//! 输入为「每元素 0/1」的比特切片(由 [`crate::analyze`] 把令牌字节展开 MSB-first 得到)。
//!
//! 注意:这是对**原始字节流**的严格检验,对 ASCII 文本令牌(如 base62 / hex)会因编码结构
//! (例如每个 ASCII 字节最高位恒为 0)而触发 Monobit 失败 —— 这属于编码特征,不代表令牌不安全;
//! 令牌真实强度以「字符级有效熵」为准。

use crate::types::FipsTest;

/// 经典 FIPS 序列长度(bit)。
pub const FIPS_BITS: usize = 20_000;

/// 跑四项 FIPS 自检(调用方需保证 `bits.len() >= FIPS_BITS`;仅取前 20000 bit)。
pub fn run_fips(bits: &[u8]) -> Vec<FipsTest> {
    let b = &bits[..FIPS_BITS];
    vec![monobit(b), poker(b), runs(b), long_run(b)]
}

/// ① Monobit:置 1 的比特数应落在 (9725, 10275)。
fn monobit(b: &[u8]) -> FipsTest {
    let ones = b.iter().filter(|&&x| x == 1).count();
    FipsTest {
        name: "Monobit",
        passed: ones > 9725 && ones < 10275,
        detail: format!("ones={ones} (9726–10274)"),
    }
}

/// ② Poker:5000 段 4-bit,X = (16/5000)·Σf² − 5000 应落在 (2.16, 46.17)。
fn poker(b: &[u8]) -> FipsTest {
    let mut freq = [0usize; 16];
    for chunk in b.chunks_exact(4) {
        let v = ((chunk[0] << 3) | (chunk[1] << 2) | (chunk[2] << 1) | chunk[3]) as usize;
        freq[v] += 1;
    }
    let sum_sq: usize = freq.iter().map(|&f| f * f).sum();
    let x = (16.0 / 5000.0) * sum_sq as f64 - 5000.0;
    FipsTest {
        name: "Poker",
        passed: x > 2.16 && x < 46.17,
        detail: format!("X={x:.2} (2.16–46.17)"),
    }
}

/// 把 0/1 比特流压成「(值, 连续长度)」的游程序列。
fn run_lengths(b: &[u8]) -> Vec<(u8, usize)> {
    let mut out = Vec::new();
    if b.is_empty() {
        return out;
    }
    let mut cur = b[0];
    let mut len = 1usize;
    for &x in &b[1..] {
        if x == cur {
            len += 1;
        } else {
            out.push((cur, len));
            cur = x;
            len = 1;
        }
    }
    out.push((cur, len));
    out
}

/// 各长度游程数量区间(下标 0..5 对应长度 1..5 与「6 及以上」)。
const RUN_INTERVALS: [(usize, usize); 6] = [
    (2315, 2685),
    (1114, 1386),
    (527, 723),
    (240, 384),
    (103, 209),
    (103, 209),
];

/// ③ Runs:长度 1..6(6 含以上)的 0-游程与 1-游程数量都须落在各自区间(共 12 项)。
fn runs(b: &[u8]) -> FipsTest {
    // cnt[值][长度桶]。
    let mut cnt = [[0usize; 6]; 2];
    for (v, l) in run_lengths(b) {
        let bucket = l.min(6) - 1;
        cnt[v as usize][bucket] += 1;
    }
    let mut passed = true;
    for polarity in cnt.iter() {
        for (k, &c) in polarity.iter().enumerate() {
            let (lo, hi) = RUN_INTERVALS[k];
            if c < lo || c > hi {
                passed = false;
            }
        }
    }
    FipsTest {
        name: "Runs",
        passed,
        detail: format!(
            "len1 0/1={}/{}, len6+ 0/1={}/{}",
            cnt[0][0], cnt[1][0], cnt[0][5], cnt[1][5]
        ),
    }
}

/// ④ Long Run:不得出现长度 ≥ 26 的游程。
fn long_run(b: &[u8]) -> FipsTest {
    let max_run = run_lengths(b).iter().map(|(_, l)| *l).max().unwrap_or(0);
    FipsTest {
        name: "Long run",
        passed: max_run < 26,
        detail: format!("max run={max_run} (<26)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 全 0 序列:Monobit 必败(0 个 1),且出现一个超长游程 → Long run 必败。
    #[test]
    fn all_zero_fails_monobit_and_long_run() {
        let bits = vec![0u8; FIPS_BITS];
        let r = run_fips(&bits);
        let mono = r.iter().find(|t| t.name == "Monobit").unwrap();
        let lr = r.iter().find(|t| t.name == "Long run").unwrap();
        assert!(!mono.passed);
        assert!(!lr.passed);
    }

    /// 严格交替 0101…:Monobit 恰好平衡(10000 个 1)→ 通过;但游程全是长度 1 → Runs 失败。
    #[test]
    fn alternating_passes_monobit_fails_runs() {
        let bits: Vec<u8> = (0..FIPS_BITS).map(|i| (i % 2) as u8).collect();
        let r = run_fips(&bits);
        let mono = r.iter().find(|t| t.name == "Monobit").unwrap();
        let runs_t = r.iter().find(|t| t.name == "Runs").unwrap();
        assert!(mono.passed, "{}", mono.detail);
        assert!(!runs_t.passed);
    }

    /// 长游程检测:前 30 个 1 接交替序列 → Long run 失败。
    #[test]
    fn detects_long_run() {
        let mut bits = vec![1u8; 30];
        bits.extend((0..FIPS_BITS).map(|i| (i % 2) as u8));
        let lr = long_run(&bits[..FIPS_BITS]);
        assert!(!lr.passed);
    }

    #[test]
    fn run_lengths_basic() {
        // 1 1 0 1 1 1 → (1,2)(0,1)(1,3)
        let v = run_lengths(&[1, 1, 0, 1, 1, 1]);
        assert_eq!(v, vec![(1, 2), (0, 1), (1, 3)]);
    }
}
