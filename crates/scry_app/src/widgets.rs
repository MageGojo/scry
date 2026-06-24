//! 无状态展示小构件。
//!
//! **通用件已反哺进 `mage_ui`**(`Divider` / `SectionLabel` / `CountPill` / `Stat`);此处保留**同签名薄壳**
//! 委托过去,使各面板调用点零改动。仅 scry 专属的 [`tls_cell`] 留在本地。

use mage_ui::prelude::*;

/// 一条全宽细分割线(委托 [`mage_ui::Divider`])。
pub fn divider(_c: ThemeColors) -> impl IntoElement {
    Divider::new()
}

/// 分组小标题(委托 [`mage_ui::SectionLabel`])。
pub fn section_label(
    text: impl Into<SharedString>,
    _c: ThemeColors,
    _t: Tokens,
) -> impl IntoElement {
    SectionLabel::new(text)
}

/// 计数小药丸(委托 [`mage_ui::CountPill`])。
pub fn count_pill(n: usize, color: Hsla, _t: Tokens) -> impl IntoElement {
    CountPill::new(n).color(color)
}

/// TLS 列单元格:https 显示绿点 + 版本号,http 显示弱化短横。
pub fn tls_cell(is_https: bool, c: ThemeColors, t: Tokens) -> impl IntoElement {
    let (color, label) = if is_https {
        (c.success, "1.3")
    } else {
        (c.text_subtle, "—")
    };
    div()
        .flex()
        .items_center()
        .gap(px(5.0))
        .child(StatusDot::new(color).size(px(7.0)))
        .child(
            div()
                .text_size(t.font_size.xs)
                .text_color(color)
                .child(label),
        )
}

/// 一个键值小卡(横排:小标题 + 主值);委托 [`mage_ui::Stat`]。
pub fn stat(
    label: impl Into<SharedString>,
    value: impl Into<SharedString>,
    color: Hsla,
    _c: ThemeColors,
    _t: Tokens,
) -> impl IntoElement {
    Stat::new(label, value).color(color)
}
