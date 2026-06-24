# 设计 · XSS 引擎(dalfox 式上下文感知反射型 XSS)

> 接「SQL 注入引擎」之后,用户点名再做 dalfox/XSStrike 这类 XSS。现有 `scry_scan::active` 只有一个
> 朴素「注入 marker 看是否原样回显」的反射检测;本轮做到 dalfox 的精髓:**上下文识别 + 可利用字符
> 探测 + 按上下文针对性合成载荷 + 反射验证**,纯 Rust 原生实现。架构与 `scry_sqli` 完全一致。

## 1. 架构:纯函数内核 `scry_xss` + UI runner

引擎纯函数 / 可单测 / 不碰网络;发包由 UI runner 复用 `scry_proxy::replay`(后台 current-thread runtime
串行 + `mpsc` 流式回填 + 前台 120ms 轮询,与 SQLi / 扫描器 / 爆破同路径)。不改 `scry_proxy`、不碰
`scry_scan`。

### `scry_xss` 模块
- `points.rs` —— 注入点发现(查询参数 + 表单字段)+ `build_probe`(替换值并百分号编码,body 修
  `Content-Length`)。与 `scry_sqli::points` 同款通用原语(各自独立,避免跨域依赖)。
- `context.rs` —— `HtmlContext`(HTML 文本 / 属性单·双·无引号 / `<script>` 字符串内·外 / HTML 注释)
  与 `detect_context`:**轻量 HTML 状态扫描**(跟踪注释 / `<script>` / 标签内 / 属性引号),判断反射点
  落在哪种上下文。不是完整解析器,但对决定逃逸方式足够(dalfox 同思路)。
- `payloads.rs`:
  - `REFLECT_MARK` + `reflections`:注入唯一标记,定位反射点。
  - `canary` + `abusable_chars`:一发"金丝雀"载荷(把 `< > " ' \` ( ) = /` 各用标记包一段)探出哪些
    字符**原样反射**(未被实体编码)→ 决定能否逃逸。
  - `synthesize(ctx, abusable) -> Option<Payload>`:据上下文 + 可用字符**针对性**拼载荷:
    - HTML 文本 / 注释:`<svg/onload=alert(MARK)>`(注释先 `-->` 闭合)。
    - 属性:能逃逸引号 + 尖括号 → `"><svg…>`;尖括号被编码但引号可用 → `" autofocus onfocus=…`(属性内事件)。
    - `<script>` 字符串:`';alert(MARK)//`(反引号模板用 `${alert(MARK)}`);裸 JS:`;alert(MARK)//`。
    - 每个载荷带 `proof`(执行片段),验证时在响应里找它**未被编码**地出现。
    - 没有 `(`/`)` 或无法逃逸当前上下文 → `None`(只识别,不给可执行载荷)。
  - `dom_sinks`:静态扫响应里的危险 DOM sink(`innerHTML`/`document.write`/`eval`/`location.*` 等)→
    DOM 型 XSS 提示(信息性,不代表已确认)。

## 2. UI runner 流程(`scry_app::xss`,`Tab::Xss`)

1. 基线请求 → `dom_sinks` 静态提示。
2. 逐注入点(自动取前 16 个,或下拉点选某点):
   - **反射定位**:注入 `REFLECT_MARK` → 找反射点;不反射则跳过。
   - **上下文识别**:`detect_context` 于首个反射点。
   - **可利用字符**:发金丝雀 → `abusable_chars`。
   - **合成 + 验证**:`synthesize` 出载荷 → 打过去 → 响应含 `proof`(未编码)= **确认可利用**;
     合成不出 / 验证不过 → 记「反射但不可利用(编码 / WAF)」。
3. 每个测过的点产出一张发现卡(可利用红 / 反射但不可利用黄 + 上下文 + 载荷类型 + 合成载荷)+ 彩色日志
   + DOM sink 提示行。代理右键「发送到 XSS」+ 左栏 Tools 入口 + 「仅测授权目标」提示。

## 3. 验证
- `scry_xss`:15 单测(上下文识别六种 / 金丝雀字符存活 / 各上下文载荷合成 / DOM sink)+ **1 端到端
  集成测试**(`tests/e2e_reflected.rs`:本地原样反射站点 → 真 `replay::send` → 反射 + 上下文 + 合成 +
  验证 proof),`clippy --all-targets` 0 警告。
- `scry_app`:`cargo build` 通过、57 测全过,新增代码 clippy 0 警告。

## 4. 深化:更多上下文 + WAF 绕过(多向量)✓

- **上下文识别属性名感知**:`detect_context` 跟踪当前属性名,新增 `HtmlContext::UrlAttribute`(`href`/`src`/
  `action`/`formaction`/`poster`/… → 可用 `javascript:` 伪协议)。
- **`synthesize` 改返回 `Vec<Payload>`(多候选)**:从最可能成功到 WAF 绕过变体——`tag_vectors` 给
  `svg/onload`、`img/onerror`、`details/ontoggle`、**大小写混淆** `sVg OnLoad`;属性上下文「闭引号插标签」+
  「`onfocus` 事件处理器」双路;URL 属性首选 `javascript:` 再兜底属性逃逸;`<script>` 字符串「闭引号 `;alert()//`」/
  「`</script>` 逃出」/反引号「`${}`」。runner 逐候选发包,**首个 `proof` 未编码回显即确认**。

## 5. 深化:DOM / 真执行动态确认(drission 无头 Chrome)✓ — 对标 dalfox `--verify`

- **执行标记** `EXEC_MARK = "13371337"`:`alert(EXEC_MARK)` 既是静态证据子串,又是**可真正执行**的合法 JS
  (数字字面量)。`exec_vectors()` 给一组「加载即自动触发」的通用执行向量(`onload`/`onerror`/`</script>` 逃出 +
  单双引号 JS 闭合;不含需点击的 `javascript:`)。
- **UI 模式切换**:XSS 页加「静态检测 / 浏览器真执行」分段。浏览器模式下(`xss.rs::start_xss_dom`):
  scry 自启无头 Chrome(`launcher::launch_headless_browser_debug`,带 `--proxy-server=8888` + CA SPKI 白名单过
  pinning)→ drission `connect` 接管(独立 OS 线程 + 多线程 runtime,同爬虫模型)→ 对每个**查询注入点**逐个导航
  执行向量,`tokio::join!(tab.get(url), tab.handle_next_dialog(true))` 并发捕获 `Page.dialogOpened`;弹窗消息含
  `EXEC_MARK` = **确认真实执行**。命中即记一条 `Live execution` 发现。子进程归 scry 管,停止 / 完成 / 关软件 kill。
- **价值**:捕获静态反射检测漏掉的情形(载荷在源码里被编码、但经 DOM sink 解码后执行),是「真的弹窗了」的铁证。
- **验证局限**:浏览器执行无法单测(需真实 Chrome);代码路径已编译通过且复用经验证的爬虫范式,**真机弹窗待实拍**。

## 6. 仍可继续
- 存储型 XSS(注入页 A → 取回页 B 验证)、盲打 XSS(需带外回连服务器,桌面工具场景受限)。
- 更多上下文(`<style>` / `srcdoc`)、更多 WAF 绕过编码(实体 / `&#x` / unicode 转义)。
