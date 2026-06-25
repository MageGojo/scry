//! Scry SQL 注入引擎 —— **sqlmap 式**注入检测与利用的**纯函数内核**。
//!
//! 对标 sqlmap:把一个抓到的请求 + 某个注入点,系统地用四类技术去探测并利用 SQL 注入,
//! 全部做成**只读、可单测**的纯函数;真正发包由 UI runner 复用 [`scry_proxy::replay`] 完成
//! (与扫描器 / 爆破同一条 async 路径)。设计与 `scry_scan` / `scry_decode` 一致。
//!
//! 四类技术(见 [`Technique`]):
//! - **报错型(Error-based)**:注入语法破坏字符,响应直接回显数据库报错 → 既判注入又指纹库类型;
//!   可进一步用 `extractvalue`/`cast`/`convert` 把任意标量(版本 / 用户 / 库名)挤进报错回显。
//! - **布尔盲注(Boolean-based blind)**:同一注入点分别注入恒真 / 恒假条件,比较两次响应相似度,
//!   真接近原始、假明显偏离 → 判定盲注。
//! - **时间盲注(Time-based blind)**:注入让数据库睡眠 N 秒的条件;响应被拖慢 → 判定 + 指纹。
//! - **联合查询(UNION query)**:先定列数,再把 `version()` 等标量并进结果集直接取数。
//!
//! 模块:
//! - [`dialect`] —— 各 DBMS 方言知识库([`Dbms`] 报错特征 / 睡眠注入 / 报错外带模板 / 版本·用户·库表达式)。
//! - [`points`] —— 注入点发现([`injection_points`])与变异请求构造([`build_probe`])。
//! - [`payloads`] —— 边界([`Boundary`])+ 四类技术的载荷生成(纯函数,可单测)。
//! - [`detect`] —— 命中判定([`judge_boolean`] / [`judge_time_delta`] / [`match_error_dbms`])、
//!   响应相似度([`similarity`])与外带数据解析([`parse_exfil`])。
//! - [`dump`] —— 盲注逐字符取数原语 + 库 / 表 / 列 / 行枚举查询 + 二分解码器(sqlmap 式 dump)。

pub mod detect;
pub mod dialect;
pub mod dump;
pub mod payloads;
pub mod points;

pub use detect::{
    judge_boolean, judge_time, judge_time_delta, match_error_dbms, parse_exfil, similarity,
    RespView, BOOL_SIM_GAP, BOOL_SIM_HIGH,
};
pub use dialect::{Dbms, Scalar, TimeInject};
pub use dump::{
    bool_inject, cell_query, char_code_expr, column_name_query, columns_count_query, length_expr,
    rows_count_query, search_byte, search_length, table_name_query, tables_count_query, time_inject,
};
pub use payloads::{
    boolean_tests, error_extract_value, error_probe_values, time_tests, union_inner_value,
    union_tests, union_value, BooleanTest, Boundary, TimeTest, UnionTest, BOUNDARIES, ERROR_PROBES,
    UNION_MAX_COLS,
};
pub use points::{build_probe, injection_points, InjectionPoint, Location};

/// 数据外带标记:把要读取的标量两侧包上它,便于从报错 / 联合查询响应里**精确切出**结果
/// (见 [`dialect::Dbms::wrap_scalar`] 与 [`detect::parse_exfil`])。选用混合大小写 + 字母数字、
/// 极不可能在正常页面里自然出现、且无需 SQL 转义的串。
pub const EXFIL_MARK: &str = "qScRyQ";

/// 检测 / 利用所用的注入技术(对标 sqlmap 的 technique 集合)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Technique {
    /// 报错型(响应直接回显数据库报错)。
    Error,
    /// 布尔盲注(真 / 假条件导致页面可区分的差异)。
    Boolean,
    /// 时间盲注(条件为真时数据库延迟响应)。
    Time,
    /// 联合查询(UNION SELECT 把数据并进结果集)。
    Union,
}

impl Technique {
    pub const ALL: [Technique; 4] = [
        Technique::Error,
        Technique::Boolean,
        Technique::Time,
        Technique::Union,
    ];

    /// 英文标签(界面 `lang.t()` 翻译)。
    pub fn label(self) -> &'static str {
        match self {
            Technique::Error => "Error-based",
            Technique::Boolean => "Boolean-based blind",
            Technique::Time => "Time-based blind",
            Technique::Union => "UNION query",
        }
    }
}
