//! nuclei DSL 表达式求值器(紧凑子集)。
//!
//! 实现递归下降解析 + 求值,覆盖模板里最常见的 `dsl` 写法(matcher 与 extractor 共用)。
//! 设计原则:**绝不 panic**——词法 / 语法 / 求值任何一步失败都返回 `None`(matcher 判否、
//! extractor 取空),让不支持的表达式安全降级,而非拖垮整批扫描。
//!
//! 支持:
//! - 字面量:整数、单/双引号字符串、`true` / `false`。
//! - 上下文标识符:`status_code`、`content_length`、`body`、`header` / `all_headers`、`duration`。
//! - 函数:`len` / `contains` / `icontains` / `tolower` / `toupper` / `trim` /
//!   `startswith` / `endswith` / `regex(pattern, input)`。
//! - 运算符:`!` `&&` `||` `==` `!=` `>` `<` `>=` `<=` `+`(数值相加 / 字符串相连),以及 `()` 分组。

use regex::Regex;

/// DSL 求值上下文(由当前响应投影而来)。
#[derive(Debug, Clone)]
pub struct DslContext<'a> {
    pub status_code: i64,
    pub content_length: i64,
    pub body: &'a str,
    pub all_headers: &'a str,
    pub duration: i64,
}

/// DSL 求值结果值。
#[derive(Debug, Clone, PartialEq)]
pub enum DslValue {
    Int(i64),
    Str(String),
    Bool(bool),
}

impl DslValue {
    pub fn to_bool(&self) -> bool {
        match self {
            DslValue::Bool(b) => *b,
            DslValue::Int(i) => *i != 0,
            DslValue::Str(s) => !s.is_empty(),
        }
    }
    pub fn to_int(&self) -> i64 {
        match self {
            DslValue::Int(i) => *i,
            DslValue::Bool(b) => i64::from(*b),
            DslValue::Str(s) => s.trim().parse::<i64>().unwrap_or(0),
        }
    }
    pub fn to_text(&self) -> String {
        match self {
            DslValue::Int(i) => i.to_string(),
            DslValue::Bool(b) => b.to_string(),
            DslValue::Str(s) => s.clone(),
        }
    }
}

/// 求值整条 DSL 表达式;返回 `None` 表示无法求值(视为不命中)。
pub fn eval(expr: &str, ctx: &DslContext) -> Option<DslValue> {
    let tokens = lex(expr)?;
    let mut p = Parser { tokens, pos: 0, ctx };
    let v = p.parse_or()?;
    // 必须把 token 吃完才算合法,残留则判失败(避免半截表达式误命中)。
    if p.pos != p.tokens.len() {
        return None;
    }
    Some(v)
}

/// 把表达式当作布尔条件求值(matcher 用);无法求值 = `false`。
pub fn eval_bool(expr: &str, ctx: &DslContext) -> bool {
    eval(expr, ctx).map(|v| v.to_bool()).unwrap_or(false)
}

// ───────────────────────── 词法 ─────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Int(i64),
    Str(String),
    Ident(String),
    LParen,
    RParen,
    Comma,
    Not,
    And,
    Or,
    Eq,
    Ne,
    Ge,
    Le,
    Gt,
    Lt,
    Plus,
}

fn lex(s: &str) -> Option<Vec<Tok>> {
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            ',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            '+' => {
                out.push(Tok::Plus);
                i += 1;
            }
            '!' => {
                if i + 1 < b.len() && b[i + 1] == '=' {
                    out.push(Tok::Ne);
                    i += 2;
                } else {
                    out.push(Tok::Not);
                    i += 1;
                }
            }
            '=' => {
                if i + 1 < b.len() && b[i + 1] == '=' {
                    out.push(Tok::Eq);
                    i += 2;
                } else {
                    return None; // 单个 '=' 非法
                }
            }
            '>' => {
                if i + 1 < b.len() && b[i + 1] == '=' {
                    out.push(Tok::Ge);
                    i += 2;
                } else {
                    out.push(Tok::Gt);
                    i += 1;
                }
            }
            '<' => {
                if i + 1 < b.len() && b[i + 1] == '=' {
                    out.push(Tok::Le);
                    i += 2;
                } else {
                    out.push(Tok::Lt);
                    i += 1;
                }
            }
            '&' => {
                if i + 1 < b.len() && b[i + 1] == '&' {
                    out.push(Tok::And);
                    i += 2;
                } else {
                    return None;
                }
            }
            '|' => {
                if i + 1 < b.len() && b[i + 1] == '|' {
                    out.push(Tok::Or);
                    i += 2;
                } else {
                    return None;
                }
            }
            '"' | '\'' => {
                let quote = c;
                i += 1;
                let mut buf = String::new();
                let mut closed = false;
                while i < b.len() {
                    let ch = b[i];
                    if ch == '\\' && i + 1 < b.len() {
                        // 转义:\" \' \\ \n \t \r,其余原样保留下一个字符。
                        let n = b[i + 1];
                        buf.push(match n {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            other => other,
                        });
                        i += 2;
                        continue;
                    }
                    if ch == quote {
                        closed = true;
                        i += 1;
                        break;
                    }
                    buf.push(ch);
                    i += 1;
                }
                if !closed {
                    return None;
                }
                out.push(Tok::Str(buf));
            }
            d if d.is_ascii_digit() => {
                let start = i;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                let num: String = b[start..i].iter().collect();
                out.push(Tok::Int(num.parse().ok()?));
            }
            a if a.is_alphabetic() || a == '_' => {
                let start = i;
                while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_') {
                    i += 1;
                }
                let id: String = b[start..i].iter().collect();
                out.push(Tok::Ident(id));
            }
            _ => return None, // 不认识的字符 → 整体放弃(安全降级)
        }
    }
    Some(out)
}

// ───────────────────────── 语法 + 求值 ─────────────────────────

struct Parser<'a> {
    tokens: Vec<Tok>,
    pos: usize,
    ctx: &'a DslContext<'a>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }
    fn bump(&mut self) -> Option<Tok> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_or(&mut self) -> Option<DslValue> {
        let mut left = self.parse_and()?;
        while self.eat(&Tok::Or) {
            let right = self.parse_and()?;
            left = DslValue::Bool(left.to_bool() || right.to_bool());
        }
        Some(left)
    }

    fn parse_and(&mut self) -> Option<DslValue> {
        let mut left = self.parse_not()?;
        while self.eat(&Tok::And) {
            let right = self.parse_not()?;
            left = DslValue::Bool(left.to_bool() && right.to_bool());
        }
        Some(left)
    }

    fn parse_not(&mut self) -> Option<DslValue> {
        if self.eat(&Tok::Not) {
            let v = self.parse_not()?;
            return Some(DslValue::Bool(!v.to_bool()));
        }
        self.parse_cmp()
    }

    fn parse_cmp(&mut self) -> Option<DslValue> {
        let left = self.parse_add()?;
        let op = match self.peek() {
            Some(Tok::Eq) => Tok::Eq,
            Some(Tok::Ne) => Tok::Ne,
            Some(Tok::Ge) => Tok::Ge,
            Some(Tok::Le) => Tok::Le,
            Some(Tok::Gt) => Tok::Gt,
            Some(Tok::Lt) => Tok::Lt,
            _ => return Some(left),
        };
        self.pos += 1;
        let right = self.parse_add()?;
        let res = match op {
            Tok::Eq => values_eq(&left, &right),
            Tok::Ne => !values_eq(&left, &right),
            Tok::Ge => left.to_int() >= right.to_int(),
            Tok::Le => left.to_int() <= right.to_int(),
            Tok::Gt => left.to_int() > right.to_int(),
            Tok::Lt => left.to_int() < right.to_int(),
            _ => unreachable!(),
        };
        Some(DslValue::Bool(res))
    }

    fn parse_add(&mut self) -> Option<DslValue> {
        let mut left = self.parse_primary()?;
        while self.eat(&Tok::Plus) {
            let right = self.parse_primary()?;
            left = match (&left, &right) {
                (DslValue::Int(a), DslValue::Int(b)) => DslValue::Int(a + b),
                _ => DslValue::Str(format!("{}{}", left.to_text(), right.to_text())),
            };
        }
        Some(left)
    }

    fn parse_primary(&mut self) -> Option<DslValue> {
        match self.bump()? {
            Tok::Int(i) => Some(DslValue::Int(i)),
            Tok::Str(s) => Some(DslValue::Str(s)),
            Tok::LParen => {
                let v = self.parse_or()?;
                if !self.eat(&Tok::RParen) {
                    return None;
                }
                Some(v)
            }
            Tok::Ident(name) => {
                if self.eat(&Tok::LParen) {
                    let mut args = Vec::new();
                    if !self.eat(&Tok::RParen) {
                        loop {
                            args.push(self.parse_or()?);
                            if self.eat(&Tok::RParen) {
                                break;
                            }
                            if !self.eat(&Tok::Comma) {
                                return None;
                            }
                        }
                    }
                    self.call(&name, args)
                } else {
                    self.ident(&name)
                }
            }
            _ => None,
        }
    }

    /// 上下文标识符 / 关键字字面量。
    fn ident(&self, name: &str) -> Option<DslValue> {
        match name {
            "true" => Some(DslValue::Bool(true)),
            "false" => Some(DslValue::Bool(false)),
            "status_code" => Some(DslValue::Int(self.ctx.status_code)),
            "content_length" => Some(DslValue::Int(self.ctx.content_length)),
            "duration" => Some(DslValue::Int(self.ctx.duration)),
            "body" => Some(DslValue::Str(self.ctx.body.to_string())),
            "header" | "all_headers" => Some(DslValue::Str(self.ctx.all_headers.to_string())),
            // 未知标识符 → 当作空串(常见于 interactsh 等不支持的占位)。
            _ => Some(DslValue::Str(String::new())),
        }
    }

    /// 函数调用。
    fn call(&self, name: &str, args: Vec<DslValue>) -> Option<DslValue> {
        let s0 = || args.first().map(|v| v.to_text()).unwrap_or_default();
        let s1 = || args.get(1).map(|v| v.to_text()).unwrap_or_default();
        match name {
            "len" => Some(DslValue::Int(s0().chars().count() as i64)),
            "tolower" => Some(DslValue::Str(s0().to_lowercase())),
            "toupper" => Some(DslValue::Str(s0().to_uppercase())),
            "trim" => Some(DslValue::Str(s0().trim().to_string())),
            "contains" => Some(DslValue::Bool(s0().contains(&s1()))),
            "icontains" => Some(DslValue::Bool(
                s0().to_lowercase().contains(&s1().to_lowercase()),
            )),
            "startswith" => Some(DslValue::Bool(s0().starts_with(&s1()))),
            "endswith" => Some(DslValue::Bool(s0().ends_with(&s1()))),
            // regex(pattern, input):pattern 在 arg0,input 在 arg1。
            "regex" => {
                let re = Regex::new(&s0()).ok()?;
                Some(DslValue::Bool(re.is_match(&s1())))
            }
            // 不支持的函数 → 放弃求值(整条 dsl 判否)。
            _ => None,
        }
    }
}

/// 相等比较:同为数值则按数值;否则按文本。
fn values_eq(a: &DslValue, b: &DslValue) -> bool {
    match (a, b) {
        (DslValue::Int(_), DslValue::Int(_)) => a.to_int() == b.to_int(),
        (DslValue::Bool(x), DslValue::Bool(y)) => x == y,
        _ => a.to_text() == b.to_text(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> DslContext<'static> {
        DslContext {
            status_code: 200,
            content_length: 1234,
            body: "Hello World, version = 1.2.3",
            all_headers: "Server: nginx\nContent-Type: text/html",
            duration: 42,
        }
    }

    #[test]
    fn literals_and_arithmetic() {
        let c = ctx();
        assert_eq!(eval("1+2", &c), Some(DslValue::Int(3)));
        assert_eq!(eval("\"a\"+\"b\"", &c), Some(DslValue::Str("ab".into())));
        assert_eq!(eval("true", &c), Some(DslValue::Bool(true)));
    }

    #[test]
    fn comparisons_and_context() {
        let c = ctx();
        assert!(eval_bool("status_code == 200", &c));
        assert!(!eval_bool("status_code == 404", &c));
        assert!(eval_bool("content_length > 1000", &c));
        assert!(eval_bool("status_code >= 200 && status_code < 300", &c));
        assert!(eval_bool("duration < 100", &c));
    }

    #[test]
    fn functions() {
        let c = ctx();
        assert!(eval_bool("contains(body, \"version\")", &c));
        assert!(!eval_bool("contains(body, \"missing\")", &c));
        assert!(eval_bool("icontains(body, \"WORLD\")", &c));
        assert!(eval_bool("len(body) > 5", &c));
        assert!(eval_bool("startswith(body, \"Hello\")", &c));
        assert!(eval_bool("regex(\"version = [0-9.]+\", body)", &c));
        assert!(eval_bool("contains(tolower(header), \"nginx\")", &c));
    }

    #[test]
    fn negation_and_grouping() {
        let c = ctx();
        assert!(eval_bool("!(status_code == 404)", &c));
        assert!(eval_bool("(status_code == 200) || (status_code == 301)", &c));
        assert!(!eval_bool("status_code == 200 && status_code == 301", &c));
    }

    #[test]
    fn malformed_is_none_not_panic() {
        let c = ctx();
        assert_eq!(eval("status_code ==", &c), None);
        assert_eq!(eval("(1 + ", &c), None);
        assert_eq!(eval("md5(body) == \"x\"", &c), None); // 不支持的函数
        assert!(!eval_bool("@#$%", &c)); // 垃圾输入安全降级
    }
}
