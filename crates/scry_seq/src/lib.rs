//! Scry 序列器内核 —— 令牌随机性 / 熵分析的**纯函数内核**(对标 Burp Sequencer)。
//!
//! 设计与 `scry_scan` / `scry_analyze` / `scry_decode` 一致:只读、无 IO、可单测。
//! 由 UI(`scry_app::sequencer`)粘贴 / 加载令牌样本后调用 [`analyze`],把报告渲染成图表。
//!
//! 模块:
//! - [`types`]:[`Quality`] 评级 + [`PositionEntropy`] + [`FipsReport`] + [`SequencerReport`]。
//! - [`analyze`]:[`parse_tokens`] 解析 + [`shannon_entropy`] + [`analyze`] 主入口。
//! - [`fips`]:FIPS 140-2 四项上电自检(Monobit / Poker / Runs / Long Run)。

pub mod analyze;
pub mod fips;
pub mod types;

pub use analyze::{analyze, grade, parse_tokens, shannon_entropy};
pub use fips::FIPS_BITS;
pub use types::{FipsReport, FipsTest, PositionEntropy, Quality, SequencerReport};
