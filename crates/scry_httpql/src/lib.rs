//! Scry **HTTPQL** —— 对捕获流量的查询语言(对标 [Caido](https://docs.caido.io/) 的 HTTPQL)。
//!
//! 把代理历史的搜索从「子串匹配」升级为**按字段的结构化查询**:
//!
//! ```text
//! req.method.eq:"GET" AND resp.status.gte:400 AND req.host.cont:"api"
//! resp.status.eq:500 OR resp.status.eq:502
//! req.path.cont:"/admin" AND NOT req.ext.eq:"js"
//! "password"                      # 裸串 = 全文搜索
//! ```
//!
//! 语法:
//! - **字段子句** `<字段路径>.<操作符>:<值>`,如 `req.method.eq:"GET"`、`resp.status.gt:400`。
//! - **全文项**:裸词或带引号串(在 URL/方法/头/体里找)。
//! - **布尔**:`AND` / `OR` / `NOT` + 括号 `( )`;相邻项默认 `AND`(大小写不敏感关键字)。
//!
//! 设计与项目其它引擎一致:**纯函数、可单测**;由 app 层把每条 [`scry_core::HttpFlow`] 投影成
//! [`FlowFields`] 后调用 [`Query::matches`]。解析失败返回 [`Err`],调用方可回退到子串搜索。

mod eval;
mod parse;

pub use parse::{parse, ParseError, Query};

/// 一条流投影出的可查询字段(由 app 层从 `HttpFlow` 构造;body 类走 `searchable`)。
#[derive(Debug, Clone, Copy)]
pub struct FlowFields<'a> {
    pub method: &'a str,
    pub host: &'a str,
    /// 路径 + 查询串。
    pub path: &'a str,
    pub url: &'a str,
    /// 路径扩展名(无则空)。
    pub ext: &'a str,
    pub port: u16,
    pub status: u16,
    pub req_len: usize,
    pub resp_len: usize,
    /// 响应 `Content-Type`。
    pub mime: &'a str,
    /// 请求头拼接文本(`Key: Value\n`)。
    pub req_headers: &'a str,
    /// 响应头拼接文本。
    pub resp_headers: &'a str,
    /// 组合的**小写**可搜索文本(URL + 头 + 解码 body 截断);全文项与 body 子句走它。
    pub searchable: &'a str,
}

/// 可查询字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Method,
    Host,
    Path,
    Url,
    Ext,
    Port,
    Status,
    ReqLen,
    RespLen,
    Mime,
    ReqHeaders,
    RespHeaders,
    ReqBody,
    RespBody,
}

impl Field {
    /// 是否数值字段(用于 gt/lt/eq 的数值比较)。
    pub fn is_numeric(self) -> bool {
        matches!(self, Field::Port | Field::Status | Field::ReqLen | Field::RespLen)
    }

    /// 由「字段路径」(去掉操作符段)解析,如 `req.method` / `status`。
    pub fn resolve(path: &str) -> Option<Field> {
        match path.to_ascii_lowercase().as_str() {
            "req.method" | "method" | "verb" => Some(Field::Method),
            "req.host" | "host" => Some(Field::Host),
            "req.path" | "path" | "req.query" => Some(Field::Path),
            "req.url" | "url" => Some(Field::Url),
            "req.ext" | "ext" | "req.extension" => Some(Field::Ext),
            "req.port" | "port" => Some(Field::Port),
            "req.len" | "req.length" => Some(Field::ReqLen),
            "req.body" => Some(Field::ReqBody),
            "req.headers" | "req.header" | "req.raw" => Some(Field::ReqHeaders),
            "resp.status" | "status" | "resp.code" | "code" => Some(Field::Status),
            "resp.len" | "len" | "resp.length" => Some(Field::RespLen),
            "resp.body" => Some(Field::RespBody),
            "resp.headers" | "resp.header" | "resp.raw" => Some(Field::RespHeaders),
            "resp.mime" | "mime" | "resp.type" | "resp.content_type" => Some(Field::Mime),
            _ => None,
        }
    }
}

/// 比较操作符。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Cont,
    NCont,
    Regex,
    Gt,
    Lt,
    Gte,
    Lte,
    Like,
}

impl Op {
    /// 由操作符段解析(如 `eq` / `cont` / `gte`);非操作符返回 `None`。
    pub fn resolve(s: &str) -> Option<Op> {
        match s.to_ascii_lowercase().as_str() {
            "eq" => Some(Op::Eq),
            "ne" | "neq" => Some(Op::Ne),
            "cont" | "contains" => Some(Op::Cont),
            "ncont" | "not_cont" | "ncontains" => Some(Op::NCont),
            "regex" | "re" | "matches" => Some(Op::Regex),
            "gt" => Some(Op::Gt),
            "lt" => Some(Op::Lt),
            "gte" | "ge" => Some(Op::Gte),
            "lte" | "le" => Some(Op::Lte),
            "like" => Some(Op::Like),
            _ => None,
        }
    }
}

/// 一个字段子句:`field op value`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clause {
    pub field: Field,
    pub op: Op,
    pub value: String,
}

/// 查询 AST。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Clause(Clause),
    /// 全文项(在 `searchable` 里找)。
    FullText(String),
}

impl Expr {
    /// AST 中是否含字段子句(否则纯全文 → 调用方可走更快的子串路径)。
    pub fn has_clauses(&self) -> bool {
        match self {
            Expr::Clause(_) => true,
            Expr::FullText(_) => false,
            Expr::Not(e) => e.has_clauses(),
            Expr::And(a, b) | Expr::Or(a, b) => a.has_clauses() || b.has_clauses(),
        }
    }
}
