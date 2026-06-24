# 设计 · SQL 注入引擎(SQLi · sqlmap 式)

> 用户需求:在 scry 里加「渗透框架 / 漏洞利用」类能力(Metasploit / Cobalt Strike / Sliver / sqlmap /
> XSStrike·dalfox / Nikto·Wapiti)。结论:**优先原生内置可原生实现的那一类;C2 框架不适合内置**。本轮选定并落地
> **原生 SQL 注入引擎(对标 sqlmap)**——它最像「漏洞利用工具」、最契合 scry 的 Web/HTTP MITM 定位、且能纯
> Rust 原生实现,不破坏「零环境出包」。

## 1. 为什么选 SQLi(对各工具的可内置性分析)

| 工具 | 类别 | 能否原生内置 scry | 结论 |
| --- | --- | --- | --- |
| Metasploit | 综合渗透 / 漏洞利用框架(Ruby,海量 exploit + Meterpreter) | ✗ 体量巨大、与 Web 代理是另一个物种、Ruby 生态 | 不内置;最多外部进程对接(破坏零环境出包),本轮不做 |
| Cobalt Strike | 商业红队 C2(闭源) | ✗ 闭源、商业、C2 与抓包无关 | 不内置 |
| Sliver | 开源 C2(Go) | ✗ C2/植入物,非 Web 漏洞,跨语言重 | 不内置 |
| **sqlmap** | SQL 注入检测 + 利用 | ✓ 全是「构造载荷 → 发请求 → 比对/计时/解析」,纯 Rust 可写 | **本轮落地** |
| dalfox / XSStrike | XSS | ◐ 可原生(反射/上下文),现有 active 扫描已有反射 XSS 雏形 | 后续可深化 |
| Nikto / Wapiti | Web 服务器 / 通用漏洞扫描 | ✓ 已有:`scry_scan::discovery`(Nikto 式敏感路径)+ `active`(通用) | 已存在,不重复 |

要点:**C2/渗透框架(MSF/CS/Sliver)不适合内置**——它们是后渗透 / 植入物 / 命令控制,与 scry「TLS 终止式
MITM + Web 漏洞」的内核定位是两个物种,且体量巨大 / 闭源 / 跨语言,内置会破坏「双击即用、零环境」目标。
**Web 漏洞专项里,Nikto 已有(discovery)**,**SQLi 是现有 active 扫描(仅报错型)最大的空白**,故选它做深。

## 2. 架构:纯函数内核 `scry_sqli` + UI runner(零侵入)

与 `scry_scan` / `scry_seq` 一致:**引擎纯函数、可单测、不碰网络**;真正发包由 UI runner 复用
`scry_proxy::replay`(后台临时 current-thread runtime 串行驱动 + `mpsc` 流式回填 + 前台 120ms 轮询,
与扫描器 / 爆破同一条 async 路径)。不改 `scry_proxy` 引擎、不碰 `scry_scan`/`scanner.rs`(避免与并发
会话的 Nikto/discovery 撞车)。

### `scry_sqli` 模块
- `dialect.rs` —— `Dbms`(MySQL / PostgreSQL / MSSQL / Oracle / SQLite)方言知识库:报错特征签名、
  睡眠注入(`time_condition`)、报错型外带模板(`error_extract`,extractvalue / cast / convert /
  utl_inaddr)、版本 / 当前用户 / 当前库的标量表达式(`scalar`)、外带标记包裹(`wrap_scalar`)。
- `points.rs` —— 注入点发现(`injection_points`:查询参数 + `x-www-form-urlencoded` 表单字段)与
  变异请求构造(`build_probe`:替换某点的值并百分号编码,body 注入自动修正 `Content-Length`)。
- `payloads.rs` —— 闭合边界 `Boundary`(`'`/数值/`"`/`')`/`)`/`'))` × `-- -` 注释)+ 四类技术载荷:
  报错探测(`error_probe_values`)、布尔盲注真假对(`boolean_tests`,随 nonce 取比较常数)、
  时间盲注(`time_tests`,按方言睡眠,MSSQL 用 `;WAITFOR` 堆叠)、联合查询(`union_tests` /
  `union_value`,列数 × 可显列扫描)、报错外带(`error_extract_value`)。
- `detect.rs` —— 判定:`match_error_dbms`(报错签名指纹)、`similarity`(字符二元组 Dice,O(n))、
  `judge_boolean`(真页≈原始 且 假页偏离 / 状态码差异)、`judge_time_delta`(相对基线增量 ≥ 期望)、
  `parse_exfil`(从响应切出 `EXFIL_MARK` 包裹的外带结果)。`RespView`(状态码 + 解码文本)。
- `lib.rs` —— `Technique`(Error / Boolean / Time / Union)+ `EXFIL_MARK` + 再导出。

## 3. UI runner 的探测流程(`scry_app::sqli`,顺序自适应)

1. **基线**:发送原始请求,记录状态码 / 解码后 body / 耗时(布尔对照 + 时间基准)。
2. **逐注入点**(自动模式取前 12 个,或用户在下拉里点选某一个):
   - **报错型**:逐个追加破坏字符 → 响应出现数据库报错签名(基线无)→ 可注入 + 指纹库类型。
   - **布尔盲注**:每边界发恒真 / 恒假 → `judge_boolean` 真≈原始且假偏离 → 可注入 + 边界。
   - **时间盲注**(未指纹出库时兜底,预算 `TIME_BUDGET=8` 防狂睡):按方言注入睡眠 + 二次确认 → 指纹。
   - 命中即停测其它点(对标 sqlmap 默认行为)。
3. **取数**(已指纹出库才做):
   - **报错外带**(每标量 1 请求,最快):`extractvalue`/`cast`/`convert`/… 把
     `version()`/`current_user`/`database()` 挤进报错回显 → `parse_exfil`。
   - **联合查询兜底**:先探列数 + 可显列(用 Version 标记),再按 `(cols,pos)` 逐标量取数。
4. 全程流式回传:彩色日志行 + 报告快照(可注入 / 注入点 / 库 / 技术 / 边界 / 版本·用户·库)+ 进度;
   可随时停止。

### UI(`Tab::Sqli`,顶栏 + 左栏 Tools 入口 + 代理右键「发送到 SQLi」)
- 工具条:注入点下拉(全部参数 / 各点)+ 时间盲注延时(2/3/5/8s)+ 开始 / 停止 + 进度。
- 左:目标 + 可编辑原始请求(复用 `repeater::parse_raw_request`)。
- 右:结论卡(可注入徽标 + 注入点 / DBMS / 技术 / 边界 + 取到的版本·用户·库,等宽强调色)+ 彩色日志。
- 顶部明确提示:**仅测试你已获授权的目标**。

## 4. 验证
- `scry_sqli`:21 个单测(方言矩阵 / 注入点与编码 / 四类载荷 / 判定 / 外带解析)+ **1 个端到端集成测试**
  (`tests/e2e_error_based.rs`:本地模拟漏洞站点 → 真 `replay::send` → 检测 MySQL + 报错外带取版本),
  `clippy --all-targets` 0 警告。
- `scry_app`:`cargo build` 通过、57 测全过;新增代码 `clippy` 0 警告(仓库里 19 条 dead-code 警告来自
  另一并发会话的 `rules.rs` Match&Replace 半成品,与本功能无关)。

## 5. 后续可深化
- 布尔 / 时间**逐字符外带**(无回显时仍能取数,sqlmap 真正杀手锏;请求量大,需限速 / 进度)。
- 列举库 / 表 / 字段 / 拖列(information_schema)+ 结果表格化展示与导出。
- WAF 绕过 tamper(注释变形 / 大小写 / 内联注释 / 编码)。
- dalfox 式上下文感知 XSS(与现有 active 扫描合流)。
