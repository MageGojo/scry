//! HTTPQL 词法 + 语法解析(递归下降)。失败返回 [`ParseError`],调用方可回退子串搜索。

use crate::{Clause, Expr, Field, FlowFields, Op};

/// 解析后的查询。
#[derive(Debug, Clone)]
pub struct Query {
    pub expr: Expr,
    has_clauses: bool,
}

impl Query {
    /// AST 是否含字段子句(纯全文 → 调用方可走更快的子串路径)。
    pub fn has_clauses(&self) -> bool {
        self.has_clauses
    }

    /// 对一条流的字段投影求值。
    pub fn matches(&self, ff: &FlowFields) -> bool {
        crate::eval::eval(&self.expr, ff)
    }
}

/// 解析错误。
#[derive(Debug, Clone)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTPQL 解析失败: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

/// 解析一条 HTTPQL 查询。
pub fn parse(s: &str) -> Result<Query, ParseError> {
    let toks = lex(s);
    if toks.is_empty() {
        return Err(ParseError("查询为空".into()));
    }
    let mut p = Parser { toks, pos: 0 };
    let expr = p.parse_or()?;
    if p.pos != p.toks.len() {
        return Err(ParseError("查询尾部有无法解析的内容".into()));
    }
    let has_clauses = expr.has_clauses();
    Ok(Query { expr, has_clauses })
}

// ───────────────────────── 词法 ─────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    LParen,
    RParen,
    Colon,
    Str(String),
    Word(String),
}

fn lex(s: &str) -> Vec<Tok> {
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < chars.len() {
        let c = chars[i];
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
            ':' => {
                out.push(Tok::Colon);
                i += 1;
            }
            '"' | '\'' => {
                let quote = c;
                i += 1;
                let mut buf = String::new();
                while i < chars.len() {
                    let ch = chars[i];
                    if ch == '\\' && i + 1 < chars.len() {
                        buf.push(chars[i + 1]);
                        i += 2;
                        continue;
                    }
                    if ch == quote {
                        i += 1;
                        break;
                    }
                    buf.push(ch);
                    i += 1;
                }
                out.push(Tok::Str(buf));
            }
            _ => {
                let start = i;
                while i < chars.len() {
                    let ch = chars[i];
                    if ch.is_whitespace()
                        || ch == '('
                        || ch == ')'
                        || ch == ':'
                        || ch == '"'
                        || ch == '\''
                    {
                        break;
                    }
                    i += 1;
                }
                out.push(Tok::Word(chars[start..i].iter().collect()));
            }
        }
    }
    out
}

// ───────────────────────── 语法 ─────────────────────────

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn bump(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn is_kw(&self, kw: &str) -> bool {
        matches!(self.peek(), Some(Tok::Word(w)) if w.eq_ignore_ascii_case(kw))
    }

    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_and()?;
        while self.is_kw("or") {
            self.bump();
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_unary()?;
        loop {
            match self.peek() {
                None | Some(Tok::RParen) => break,
                Some(Tok::Word(w)) if w.eq_ignore_ascii_case("or") => break,
                Some(Tok::Word(w)) if w.eq_ignore_ascii_case("and") => {
                    self.bump();
                    let right = self.parse_unary()?;
                    left = Expr::And(Box::new(left), Box::new(right));
                }
                _ => {
                    // 相邻项隐式 AND。
                    let right = self.parse_unary()?;
                    left = Expr::And(Box::new(left), Box::new(right));
                }
            }
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        if self.is_kw("not") {
            self.bump();
            let e = self.parse_unary()?;
            return Ok(Expr::Not(Box::new(e)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        match self.bump() {
            Some(Tok::LParen) => {
                let e = self.parse_or()?;
                match self.bump() {
                    Some(Tok::RParen) => Ok(e),
                    _ => Err(ParseError("缺少右括号 )".into())),
                }
            }
            Some(Tok::Str(s)) => Ok(Expr::FullText(s)),
            Some(Tok::Word(w)) => {
                if self.peek() == Some(&Tok::Colon) {
                    self.bump(); // 吃掉 ':'
                    let value = match self.bump() {
                        Some(Tok::Str(s)) => s,
                        Some(Tok::Word(v)) => v,
                        _ => return Err(ParseError("字段子句缺少值".into())),
                    };
                    Ok(Expr::Clause(build_clause(&w, value)?))
                } else {
                    Ok(Expr::FullText(w))
                }
            }
            Some(Tok::Colon) => Err(ParseError("意外的 :".into())),
            Some(Tok::RParen) => Err(ParseError("意外的 )".into())),
            None => Err(ParseError("查询不完整".into())),
        }
    }
}

/// 由 `<字段路径>.<op>` 词 + 值构造子句;无 op 段时按字段类型取默认(数值 eq / 字符串 cont)。
fn build_clause(word: &str, value: String) -> Result<Clause, ParseError> {
    if let Some((field_path, last)) = word.rsplit_once('.') {
        if let Some(op) = Op::resolve(last) {
            let field = Field::resolve(field_path)
                .ok_or_else(|| ParseError(format!("未知字段:{field_path}")))?;
            return Ok(Clause { field, op, value });
        }
    }
    let field =
        Field::resolve(word).ok_or_else(|| ParseError(format!("未知字段:{word}")))?;
    let op = if field.is_numeric() { Op::Eq } else { Op::Cont };
    Ok(Clause { field, op, value })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clause() {
        let q = parse(r#"req.method.eq:"GET""#).unwrap();
        assert!(q.has_clauses());
        match &q.expr {
            Expr::Clause(c) => {
                assert_eq!(c.field, Field::Method);
                assert_eq!(c.op, Op::Eq);
                assert_eq!(c.value, "GET");
            }
            _ => panic!("expected clause"),
        }
    }

    #[test]
    fn parses_boolean_and_grouping() {
        let q = parse("status.gte:400 AND (req.host.cont:api OR req.path.cont:/admin)").unwrap();
        assert!(q.has_clauses());
        match &q.expr {
            Expr::And(_, b) => assert!(matches!(**b, Expr::Or(_, _))),
            _ => panic!("expected top-level AND"),
        }
    }

    #[test]
    fn implicit_and_between_terms() {
        let q = parse("method.eq:POST status.eq:500").unwrap();
        assert!(matches!(q.expr, Expr::And(_, _)));
    }

    #[test]
    fn fulltext_only_has_no_clauses() {
        let q = parse(r#""password""#).unwrap();
        assert!(!q.has_clauses());
        assert!(matches!(q.expr, Expr::FullText(_)));
        let q2 = parse("admin").unwrap();
        assert!(!q2.has_clauses());
    }

    #[test]
    fn default_ops_by_type() {
        // 数值默认 eq。
        let q = parse("status:200").unwrap();
        match q.expr {
            Expr::Clause(c) => {
                assert_eq!(c.field, Field::Status);
                assert_eq!(c.op, Op::Eq);
            }
            _ => panic!(),
        }
        // 字符串默认 cont。
        let q2 = parse("host:example").unwrap();
        match q2.expr {
            Expr::Clause(c) => assert_eq!(c.op, Op::Cont),
            _ => panic!(),
        }
    }

    #[test]
    fn unknown_field_is_err() {
        assert!(parse("bogus.field.eq:1").is_err());
        assert!(parse("(unbalanced").is_err());
    }
}
