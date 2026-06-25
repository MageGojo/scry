//! HTTPQL 求值:把 [`Expr`] 应用到一条流的 [`FlowFields`] 投影上判命中。

use crate::{Clause, Expr, Field, FlowFields, Op};
use regex::Regex;
use std::borrow::Cow;

pub(crate) fn eval(e: &Expr, ff: &FlowFields) -> bool {
    match e {
        Expr::And(a, b) => eval(a, ff) && eval(b, ff),
        Expr::Or(a, b) => eval(a, ff) || eval(b, ff),
        Expr::Not(x) => !eval(x, ff),
        Expr::FullText(s) => ff.searchable.contains(&s.to_lowercase()),
        Expr::Clause(c) => eval_clause(c, ff),
    }
}

/// 取字段的字符串值(body 类回退到 `searchable`)。
fn field_str<'a>(f: Field, ff: &FlowFields<'a>) -> Cow<'a, str> {
    match f {
        Field::Method => Cow::Borrowed(ff.method),
        Field::Host => Cow::Borrowed(ff.host),
        Field::Path => Cow::Borrowed(ff.path),
        Field::Url => Cow::Borrowed(ff.url),
        Field::Ext => Cow::Borrowed(ff.ext),
        Field::Mime => Cow::Borrowed(ff.mime),
        Field::ReqHeaders => Cow::Borrowed(ff.req_headers),
        Field::RespHeaders => Cow::Borrowed(ff.resp_headers),
        Field::ReqBody | Field::RespBody => Cow::Borrowed(ff.searchable),
        Field::Port => Cow::Owned(ff.port.to_string()),
        Field::Status => Cow::Owned(ff.status.to_string()),
        Field::ReqLen => Cow::Owned(ff.req_len.to_string()),
        Field::RespLen => Cow::Owned(ff.resp_len.to_string()),
    }
}

/// 取数值字段的整数值(非数值字段返回 `None`)。
fn field_num(f: Field, ff: &FlowFields) -> Option<i64> {
    match f {
        Field::Port => Some(ff.port as i64),
        Field::Status => Some(ff.status as i64),
        Field::ReqLen => Some(ff.req_len as i64),
        Field::RespLen => Some(ff.resp_len as i64),
        _ => None,
    }
}

fn eval_clause(c: &Clause, ff: &FlowFields) -> bool {
    match c.op {
        Op::Gt | Op::Lt | Op::Gte | Op::Lte => {
            let (Some(a), Ok(b)) = (field_num(c.field, ff), c.value.trim().parse::<i64>()) else {
                return false;
            };
            match c.op {
                Op::Gt => a > b,
                Op::Lt => a < b,
                Op::Gte => a >= b,
                Op::Lte => a <= b,
                _ => unreachable!(),
            }
        }
        Op::Eq => {
            if let (Some(a), Ok(b)) = (field_num(c.field, ff), c.value.trim().parse::<i64>()) {
                a == b
            } else {
                field_str(c.field, ff).eq_ignore_ascii_case(&c.value)
            }
        }
        Op::Ne => {
            if let (Some(a), Ok(b)) = (field_num(c.field, ff), c.value.trim().parse::<i64>()) {
                a != b
            } else {
                !field_str(c.field, ff).eq_ignore_ascii_case(&c.value)
            }
        }
        Op::Cont | Op::Like => field_str(c.field, ff)
            .to_lowercase()
            .contains(&c.value.to_lowercase()),
        Op::NCont => !field_str(c.field, ff)
            .to_lowercase()
            .contains(&c.value.to_lowercase()),
        Op::Regex => Regex::new(&c.value)
            .map(|re| re.is_match(&field_str(c.field, ff)))
            .unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use crate::{parse, FlowFields};

    fn ff() -> FlowFields<'static> {
        FlowFields {
            method: "POST",
            host: "api.example.com",
            path: "/v1/login?next=/admin",
            url: "https://api.example.com/v1/login?next=/admin",
            ext: "",
            port: 443,
            status: 500,
            req_len: 42,
            resp_len: 1500,
            mime: "application/json",
            req_headers: "Content-Type: application/json\nCookie: a=1\n",
            resp_headers: "Server: nginx\nContent-Type: application/json\n",
            searchable: "https://api.example.com/v1/login\ncontent-type application/json\n{\"error\":\"boom\"}",
        }
    }

    fn m(q: &str) -> bool {
        parse(q).unwrap().matches(&ff())
    }

    #[test]
    fn field_clauses() {
        assert!(m("req.method.eq:POST"));
        assert!(!m("req.method.eq:GET"));
        assert!(m("resp.status.eq:500"));
        assert!(m("resp.status.gte:500"));
        assert!(m("resp.status.gt:400"));
        assert!(!m("resp.status.lt:400"));
        assert!(m("req.host.cont:example"));
        assert!(m("req.path.cont:/admin"));
        assert!(m("resp.mime.cont:json"));
        assert!(m("resp.len.gt:1000"));
        assert!(m("req.port.eq:443"));
    }

    #[test]
    fn boolean_combinations() {
        assert!(m("req.method.eq:POST AND resp.status.eq:500"));
        assert!(!m("req.method.eq:POST AND resp.status.eq:200"));
        assert!(m("resp.status.eq:200 OR resp.status.eq:500"));
        assert!(m("req.method.eq:POST AND NOT req.ext.eq:js"));
        assert!(m("(resp.status.gte:500) OR (req.host.cont:nope)"));
    }

    #[test]
    fn fulltext_and_body() {
        assert!(m("login")); // 全文(searchable 含)
        assert!(m(r#""boom""#)); // 全文带引号
        assert!(!m("notpresentxyz"));
        assert!(m("resp.body.cont:boom")); // body 走 searchable
    }

    #[test]
    fn regex_and_ncont() {
        assert!(m(r#"req.host.regex:"api\.""#));
        assert!(m("req.path.ncont:notthere"));
        assert!(!m("req.path.ncont:login"));
    }
}
