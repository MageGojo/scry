//! 序列器分析的共享类型:随机性质量等级 [`Quality`]、单位置熵 [`PositionEntropy`]、
//! FIPS 自检项 [`FipsTest`] 与整份报告 [`SequencerReport`]。

use serde::Serialize;

/// 令牌随机性的总体评级(按「字符级有效熵」+ 是否有重复样本判定)。
///
/// 对标 Burp Sequencer 的 extremely poor / poor / reasonable / good / excellent 五档。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Quality {
    /// 差:有效熵过低或样本里出现重复(令牌可碰撞 / 可预测)。
    Poor,
    /// 弱。
    Weak,
    /// 尚可。
    Reasonable,
    /// 强。
    Strong,
    /// 极强(≈128 bit 及以上,等价一枚高强度随机令牌)。
    Excellent,
}

impl Quality {
    /// 英文标签(i18n key;界面用 `lang.t()` 翻译)。
    pub fn label(self) -> &'static str {
        match self {
            Quality::Poor => "Poor",
            Quality::Weak => "Weak",
            Quality::Reasonable => "Reasonable",
            Quality::Strong => "Strong",
            Quality::Excellent => "Excellent",
        }
    }
}

/// 某一个「位置」上的香农熵(字符位置或比特位置共用)。
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct PositionEntropy {
    /// 位置下标(从 0 起)。
    pub index: usize,
    /// 该位置的香农熵(bit)。字符位置上限 8(单字节),比特位置上限 1。
    pub bits: f64,
    /// 拥有该位置的样本数(令牌不等长时,靠后的位置样本更少)。
    pub samples: usize,
}

/// 一项 FIPS 140-2 上电自检的结果。
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FipsTest {
    /// 测试名(英文 key)。
    pub name: &'static str,
    /// 是否通过。
    pub passed: bool,
    /// 数值证据(如 `ones=10031 (9725–10275)`)。
    pub detail: String,
}

/// FIPS 140-2 自检小节。经典阈值按**恰好 20000 bit** 标定,故样本不足时不评估。
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FipsReport {
    /// 参与拼接的总比特数(= Σ 令牌字节数 × 8)。
    pub total_bits: usize,
    /// 是否达到 20000 bit 并实际跑了四项测试。
    pub evaluated: bool,
    /// 四项测试结果(`evaluated == false` 时为空)。
    pub tests: Vec<FipsTest>,
}

impl FipsReport {
    /// 是否四项全过(未评估时返回 false)。
    pub fn all_passed(&self) -> bool {
        self.evaluated && self.tests.iter().all(|t| t.passed)
    }
}

/// 整份序列器分析报告。
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SequencerReport {
    /// 样本(令牌)总数。
    pub sample_count: usize,
    /// 去重后的唯一样本数(`< sample_count` 即存在重复 → 严重问题)。
    pub unique_count: usize,
    /// 最短 / 最长样本字节长度。
    pub min_len: usize,
    pub max_len: usize,
    /// **字符级**有效熵(各字符位置香农熵之和,bit)—— 头条指标,驱动 [`Quality`]。
    pub char_entropy_bits: f64,
    /// **比特级**有效熵(各比特位置香农熵之和,bit)—— 对文本编码更敏感的下界估计。
    pub bit_entropy_bits: f64,
    /// 每字符位置的平均熵 = `char_entropy_bits / max_len`。
    pub mean_char_bits: f64,
    /// 总体 0/1 平衡:置 1 的比特占比(理想 0.5)。
    pub one_ratio: f64,
    /// 总体评级。
    pub quality: Quality,
    /// 每字符位置的熵(可视化用;最多保留前若干位)。
    pub char_positions: Vec<PositionEntropy>,
    /// FIPS 140-2 自检。
    pub fips: FipsReport,
}

impl SequencerReport {
    /// 是否存在重复样本。
    pub fn has_duplicates(&self) -> bool {
        self.unique_count < self.sample_count
    }
}
