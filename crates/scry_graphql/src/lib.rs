//! Scry GraphQL 支持内核(对标 **Burp / Reqable 的 GraphQL 视图**)—— **纯函数、可单测**。
//!
//! 现代 API 普遍走 GraphQL,单端点 + 自描述 schema。本内核提供工作台需要的几件事:
//! - [`minify`] / [`prettify`]:查询**压缩 / 美化**(轻量词法,字符串字面量内空白保留)。
//! - [`build_request_body`]:把 query + variables(+ operationName)包成标准 POST JSON 体。
//! - [`INTROSPECTION_QUERY`] + [`parse_introspection`]:发 introspection 拉回 schema 并解析成
//!   [`Schema`](类型 → 字段 → 参数),供 UI 做 schema 浏览 / 字段建议。
//!
//! 不做完整 GraphQL 解析 / 校验(那是服务端的事);只做工作台「看懂结构 + 改 + 发」需要的最小子集。

use serde::{Deserialize, Serialize};

/// 标准 GraphQL introspection 查询(精简版:够拉出类型 / 字段 / 参数 / 枚举,不含 directives 细节)。
pub const INTROSPECTION_QUERY: &str = r#"query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args { name type { kind name ofType { kind name ofType { kind name } } } }
        type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
      }
      inputFields { name type { kind name ofType { kind name } } }
      enumValues(includeDeprecated: true) { name }
    }
  }
}"#;

// ───────────────────────── 美化 / 压缩 ─────────────────────────

/// 是否 GraphQL「名字字符」(用于压缩时判断要不要保留分隔空格)。
fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$' || c == '@' || c == '.'
}

/// 压缩查询:去掉一切非必要空白(仅在两个名字字符之间保留单个空格,防 `query Foo` 粘成 `queryFoo`),
/// 字符串字面量内的空白原样保留。
pub fn minify(query: &str) -> String {
    let mut out = String::with_capacity(query.len());
    let mut in_string = false;
    let mut escaped = false;
    let mut pending_space = false;
    let mut last: Option<char> = None;
    for ch in query.chars() {
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
                last = Some('"');
            }
            continue;
        }
        if ch == '"' {
            if pending_space {
                pending_space = false;
            }
            in_string = true;
            out.push(ch);
            last = Some('"');
            continue;
        }
        if ch.is_whitespace() || ch == ',' {
            // 逗号在 GraphQL 是“无意义”分隔符,等同空白。
            if last.is_some() {
                pending_space = true;
            }
            continue;
        }
        if pending_space {
            // 只有「名字字符 紧接 名字字符」才需要留一个空格。
            if matches!(last, Some(l) if is_name_char(l)) && is_name_char(ch) {
                out.push(' ');
            }
            pending_space = false;
        }
        out.push(ch);
        last = Some(ch);
    }
    out
}

/// 美化查询:基于压缩后的 token 流重新缩进(选择集换行缩进,参数 `(...)` 内保持单行)。
pub fn prettify(query: &str) -> String {
    let min = minify(query);
    let mut out = String::with_capacity(min.len() * 2);
    let mut depth: usize = 0;
    let mut paren: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut last_sig: Option<char> = None;
    let indent = |n: usize| "  ".repeat(n);
    for ch in min.chars() {
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => {
                in_string = true;
                out.push(ch);
            }
            '{' => {
                depth += 1;
                out.push_str(" {\n");
                out.push_str(&indent(depth));
            }
            '}' => {
                depth = depth.saturating_sub(1);
                out.push('\n');
                out.push_str(&indent(depth));
                out.push('}');
            }
            '(' => {
                paren += 1;
                out.push(ch);
            }
            ')' => {
                paren = paren.saturating_sub(1);
                out.push(ch);
            }
            ':' => out.push_str(": "),
            ' ' => {
                if paren > 0 {
                    out.push(' ');
                } else {
                    // 选择集里字段以换行分隔。
                    out.push('\n');
                    out.push_str(&indent(depth));
                }
            }
            _ => {
                // 紧跟在 `}` 后的下一个字段:补一个换行,避免 `}field` 粘连。
                if last_sig == Some('}') && is_name_char(ch) {
                    out.push('\n');
                    out.push_str(&indent(depth));
                }
                out.push(ch);
            }
        }
        if !ch.is_whitespace() {
            last_sig = Some(ch);
        }
    }
    out.trim().to_string()
}

// ───────────────────────── 请求体构造 ─────────────────────────

/// 把 query + variables(JSON 文本)+ 可选 operationName 包成 POST JSON 体。
///
/// `variables` 解析失败(或空)则省略该字段;`operation` 为空则省略。返回紧凑 JSON 字符串。
pub fn build_request_body(query: &str, variables: &str, operation: Option<&str>) -> String {
    let mut map = serde_json::Map::new();
    map.insert("query".into(), serde_json::Value::String(query.to_string()));
    let vt = variables.trim();
    if !vt.is_empty() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(vt) {
            map.insert("variables".into(), v);
        }
    }
    if let Some(op) = operation {
        if !op.trim().is_empty() {
            map.insert("operationName".into(), serde_json::Value::String(op.to_string()));
        }
    }
    serde_json::Value::Object(map).to_string()
}

// ───────────────────────── Schema(introspection 解析)─────────────────────────

/// 一个字段的参数(名 + 类型串)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgInfo {
    pub name: String,
    pub type_name: String,
}

/// 一个字段(名 + 返回类型串 + 参数 + 描述)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldInfo {
    pub name: String,
    pub type_name: String,
    pub args: Vec<ArgInfo>,
    pub description: Option<String>,
}

/// 一个类型(名 + kind + 字段)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeInfo {
    pub name: String,
    pub kind: String,
    pub fields: Vec<FieldInfo>,
}

/// 解析出的 schema 概览(根类型名 + 用户定义类型)。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schema {
    pub query_type: Option<String>,
    pub mutation_type: Option<String>,
    pub subscription_type: Option<String>,
    pub types: Vec<TypeInfo>,
}

impl Schema {
    /// 用户定义类型数(已剔除内省 `__` 与标量)。
    pub fn type_count(&self) -> usize {
        self.types.len()
    }
}

/// 把 introspection 的类型引用(嵌套 `ofType`)解析成可读类型串,如 `[User!]!`。
fn type_ref_name(v: &serde_json::Value) -> String {
    let kind = v.get("kind").and_then(|k| k.as_str()).unwrap_or("");
    match kind {
        "NON_NULL" => format!("{}!", type_ref_name(v.get("ofType").unwrap_or(&serde_json::Value::Null))),
        "LIST" => format!("[{}]", type_ref_name(v.get("ofType").unwrap_or(&serde_json::Value::Null))),
        _ => v
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("?")
            .to_string(),
    }
}

/// 解析 introspection 响应(`{"data":{"__schema":…}}` 或裸 `{"__schema":…}`)成 [`Schema`]。
///
/// 跳过内省类型(`__` 前缀)与无字段的标量 / 枚举,只保留 OBJECT / INTERFACE / INPUT_OBJECT 等有字段的类型。
pub fn parse_introspection(json: &str) -> Result<Schema, String> {
    let root: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("响应不是合法 JSON:{e}"))?;
    // 先看有没有 GraphQL 错误。
    if let Some(errs) = root.get("errors").and_then(|e| e.as_array()) {
        if !errs.is_empty() {
            let msg = errs[0]
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("introspection 被拒绝");
            return Err(format!("GraphQL 错误:{msg}"));
        }
    }
    let schema = root
        .pointer("/data/__schema")
        .or_else(|| root.get("__schema"))
        .ok_or("响应里找不到 __schema(introspection 可能被禁用)")?;

    let mut out = Schema {
        query_type: schema
            .pointer("/queryType/name")
            .and_then(|v| v.as_str())
            .map(String::from),
        mutation_type: schema
            .pointer("/mutationType/name")
            .and_then(|v| v.as_str())
            .map(String::from),
        subscription_type: schema
            .pointer("/subscriptionType/name")
            .and_then(|v| v.as_str())
            .map(String::from),
        types: Vec::new(),
    };

    let Some(types) = schema.get("types").and_then(|t| t.as_array()) else {
        return Ok(out);
    };
    for ty in types {
        let name = ty.get("name").and_then(|n| n.as_str()).unwrap_or("");
        if name.is_empty() || name.starts_with("__") {
            continue;
        }
        let kind = ty.get("kind").and_then(|k| k.as_str()).unwrap_or("").to_string();
        let mut fields = Vec::new();
        if let Some(fs) = ty.get("fields").and_then(|f| f.as_array()) {
            for f in fs {
                let fname = f.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                if fname.is_empty() {
                    continue;
                }
                let type_name = f
                    .get("type")
                    .map(type_ref_name)
                    .unwrap_or_else(|| "?".to_string());
                let mut args = Vec::new();
                if let Some(aa) = f.get("args").and_then(|a| a.as_array()) {
                    for a in aa {
                        let an = a.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                        let at = a.get("type").map(type_ref_name).unwrap_or_default();
                        if !an.is_empty() {
                            args.push(ArgInfo { name: an, type_name: at });
                        }
                    }
                }
                let description = f
                    .get("description")
                    .and_then(|d| d.as_str())
                    .filter(|s| !s.is_empty())
                    .map(String::from);
                fields.push(FieldInfo {
                    name: fname,
                    type_name,
                    args,
                    description,
                });
            }
        }
        // 只收有字段的类型(对象 / 接口);标量 / 枚举 / 无字段的略过(UI 浏览意义不大)。
        if !fields.is_empty() {
            out.types.push(TypeInfo { name: name.to_string(), kind, fields });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minify_collapses_whitespace_keeps_string() {
        assert_eq!(minify("{  user  {  name  email  }  }"), "{user{name email}}");
        assert_eq!(
            minify("query Foo {\n  user(id: 5) {\n    name\n  }\n}"),
            "query Foo{user(id:5){name}}"
        );
        // 字符串字面量内空白保留。
        assert_eq!(minify(r#"{ f(q: "a  b") }"#), r#"{f(q:"a  b")}"#);
        // 逗号当空白处理。
        assert_eq!(minify("{ a, b, c }"), "{a b c}");
    }

    #[test]
    fn prettify_roundtrips_through_minify() {
        let q = r#"query Foo($id: ID!) { user(id: $id) { name email posts { title } } }"#;
        // 美化后再压缩,应回到与直接压缩相同的 token 形态(强不变量,不依赖具体缩进)。
        assert_eq!(minify(&prettify(q)), minify(q));
    }

    #[test]
    fn prettify_indents_nested_selections() {
        let p = prettify("{user{name}}");
        assert!(p.contains('\n'), "应有换行: {p}");
        assert!(p.contains("  name"), "应有缩进字段: {p}");
    }

    #[test]
    fn build_body_wraps_query_and_vars() {
        let body = build_request_body("{me{id}}", r#"{"id":5}"#, None);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["query"], "{me{id}}");
        assert_eq!(v["variables"]["id"], 5);
        assert!(v.get("operationName").is_none());

        // 坏 variables 被忽略(只省略该字段,不报错)。
        let body2 = build_request_body("{x}", "not json", Some("Op"));
        let v2: serde_json::Value = serde_json::from_str(&body2).unwrap();
        assert!(v2.get("variables").is_none());
        assert_eq!(v2["operationName"], "Op");
    }

    #[test]
    fn parse_introspection_extracts_types_and_fields() {
        let resp = r#"{
          "data": { "__schema": {
            "queryType": { "name": "Query" },
            "mutationType": { "name": "Mutation" },
            "subscriptionType": null,
            "types": [
              { "kind": "OBJECT", "name": "Query", "fields": [
                { "name": "user", "description": "get a user",
                  "args": [ { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID" } } } ],
                  "type": { "kind": "OBJECT", "name": "User", "ofType": null } }
              ] },
              { "kind": "OBJECT", "name": "User", "fields": [
                { "name": "posts", "description": null, "args": [],
                  "type": { "kind": "LIST", "name": null, "ofType": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "OBJECT", "name": "Post" } } } }
              ] },
              { "kind": "SCALAR", "name": "ID", "fields": null },
              { "kind": "OBJECT", "name": "__Type", "fields": [ { "name": "x", "args": [], "type": { "kind": "SCALAR", "name": "String" } } ] }
            ]
          } }
        }"#;
        let s = parse_introspection(resp).unwrap();
        assert_eq!(s.query_type.as_deref(), Some("Query"));
        assert_eq!(s.mutation_type.as_deref(), Some("Mutation"));
        assert_eq!(s.subscription_type, None);
        // __Type(内省)与 ID(标量无字段)被剔除,留 Query + User。
        assert_eq!(s.type_count(), 2);
        let q = s.types.iter().find(|t| t.name == "Query").unwrap();
        assert_eq!(q.fields[0].name, "user");
        assert_eq!(q.fields[0].type_name, "User");
        assert_eq!(q.fields[0].args[0].name, "id");
        assert_eq!(q.fields[0].args[0].type_name, "ID!");
        let u = s.types.iter().find(|t| t.name == "User").unwrap();
        assert_eq!(u.fields[0].type_name, "[Post!]");
    }

    #[test]
    fn parse_introspection_reports_disabled() {
        let resp = r#"{"errors":[{"message":"introspection disabled"}]}"#;
        assert!(parse_introspection(resp).is_err());
        assert!(parse_introspection("{}").is_err());
    }
}
