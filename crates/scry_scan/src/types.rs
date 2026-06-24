//! 扫描结果的共享类型:严重度 [`Severity`] 与发现项 [`Finding`]。

use serde::{Deserialize, Serialize};

/// 漏洞 / 问题严重度(由低到高;`Ord` 用于排序)。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// 英文标签(i18n key;界面用 `lang.t()` 翻译)。
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }

    /// 全部严重度(由高到低,供分组统计 / 渲染顺序)。
    pub const ALL_DESC: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
}

/// 一条扫描发现。`title` 为英文 key(界面 `lang.t()` 翻译),`detail` 为已组好的中性证据串。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// 规则稳定 id(去重 / 过滤用),如 `missing-hsts`。
    pub rule_id: &'static str,
    /// 规则标题(英文 key)。
    pub title: &'static str,
    pub severity: Severity,
    /// 命中的目标 URL。
    pub url: String,
    /// 证据 / 说明(命中点、缺失项等)。
    pub detail: String,
}

impl Finding {
    pub fn new(
        rule_id: &'static str,
        title: &'static str,
        severity: Severity,
        url: String,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            rule_id,
            title,
            severity,
            url,
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_low_to_high() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
}
