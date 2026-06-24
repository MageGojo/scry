//! Scry 分析层 —— 针对 [`scry_core::HttpFlow`] 的**纯函数**分析辅助,不碰 IO / 存储 / 网络。
//!
//! 供 `scry_app`(详情区 / history 过滤 / 复制为 curl)与未来的扫描 / Repeater 编辑复用。
//! 设计与 `scry_decode` 一致:**只读、纯函数、可单测**;需要解压 / charset 的地方复用 `scry_decode`。
//!
//! 模块:
//! - [`params`]:URL 查询参数、`x-www-form-urlencoded` 表单、Cookie 提取(均已百分号解码)。
//! - [`summary`]:把一条流压成 [`summary::FlowSummary`](history 表 / 快速浏览用)。
//! - [`filter`]:[`filter::FlowFilter`] 过滤条件 + 全文搜索(url/头/解码后 body)。
//! - [`curl`]:把请求导出为可执行的 `curl` 命令([`curl::to_curl`])。
//! - [`codegen`]:把请求导出为各语言代码片段(curl / Python / JS fetch / JS XHR)。

pub mod codegen;
pub mod curl;
pub mod filter;
pub mod params;
pub mod summary;

pub use codegen::CodeLang;
pub use curl::to_curl;
pub use filter::{filter_flows, flow_contains, FlowFilter};
pub use params::{
    form_params, parse_query, parse_urlencoded, percent_decode, request_cookies,
    response_set_cookies, Kv,
};
pub use summary::FlowSummary;
