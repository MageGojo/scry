# 设计 · HTTPQL 查询语言(scry_httpql)

> 第一档 ROI Top4 #4:**SiteMap + HTTPQL 查询语言**(对标 [Caido](https://docs.caido.io/))。
> 两半均已完成:**HTTPQL**(把代理历史搜索从「子串匹配」升级为**按字段的结构化查询**)
> + **SiteMap 树**(host→路径树,按结构浏览,见 §5)。二者互补:一个按字段查询、一个按结构浏览。

## 1. 语法

```text
req.method.eq:"GET" AND resp.status.gt:400 AND req.host.cont:"api"
resp.status.eq:500 OR resp.status.eq:502
req.path.cont:"/admin" AND NOT req.ext.eq:"js"
"password"                       # 裸串 / 裸词 = 全文搜索
```

- **字段子句** `<字段路径>.<操作符>:<值>`。
- **全文项**:裸词或带引号串(在 URL/方法/头/体里找)。
- **布尔**:`AND` / `OR` / `NOT` + 括号 `( )`;**相邻项默认 AND**(关键字大小写不敏感)。
- **值**:带引号串(可含空格/特殊字符)或裸值;数值字段比较自动按整数。

### 字段(命名空间可省的常用别名)
| 字段 | 别名 | 类型 |
|---|---|---|
| `req.method` | `method` `verb` | 串 |
| `req.host` | `host` | 串 |
| `req.path` | `path` `req.query` | 串 |
| `req.url` | `url` | 串 |
| `req.ext` | `ext` | 串 |
| `req.port` | `port` | 数 |
| `req.len` | | 数 |
| `req.headers` | `req.raw` | 串 |
| `req.body` | | 串(走 searchable) |
| `resp.status` | `status` `code` | 数 |
| `resp.len` | `len` | 数 |
| `resp.mime` | `mime` `resp.type` | 串 |
| `resp.headers` | `resp.raw` | 串 |
| `resp.body` | | 串(走 searchable) |

### 操作符
`eq` `ne` `cont` `ncont` `regex` `gt` `lt` `gte` `lte` `like`(+ 别名 `contains`/`neq`/`ge`/`le`…)。
省略操作符段时:数值字段默认 `eq`,字符串字段默认 `cont`。

## 2. 架构(契合现有范式)

- **纯函数内核 crate `scry_httpql`**(零 IO,可单测):
  - `lib.rs`:`FlowFields`(一条流的字段投影)+ `Field` / `Op` / `Clause` / `Expr` AST + `Field::resolve` / `Op::resolve`。
  - `parse.rs`:词法(`( ) : 串 词`)+ 递归下降语法(or → and(隐式/显式)→ not → primary);解析失败 `Err`。
  - `eval.rs`:`eval(Expr, FlowFields) → bool`,数值/字符串/正则/全文各操作符;body 子句 + 全文走 `searchable`。
- **接入 `proxy.rs` 历史过滤**:
  - 搜索框文本先 `scry_httpql::parse`;**仅当解析成功且含字段子句**(`has_clauses`)时走结构化逐字段匹配,
    否则(纯文本 / 解析失败)**回退原有快路径子串搜索**(`flow_search_text` 的指针缓存,保性能不卡)。
  - 结构化匹配时:method/host/path/url/ext/port/status/len/mime/headers 廉价取自 `HttpFlow`;
    `req.body`/`resp.body`/全文走已缓存的 `searchable`(解码 body 只首次做一次)。
  - 搜索框占位提示更新为 HTTPQL 示例;i18n 全。

## 3. 子集边界(诚实声明)

- `req.body` / `resp.body` 子句近似走「组合 searchable 文本」(不区分请求/响应 body 的精确归属),
  换取零额外解码缓存、不卡顿;精确按 body 归属匹配留后续。
- 未做时间/日期字段、`row`/`note`/`tag` 等 Caido 扩展字段;未做保存的查询(saved queries)。
- ~~SiteMap 树留作下一步~~ → **已完成**,见 §5。

## 4. 验证

- `scry_httpql` 10 单测(子句/布尔/分组/隐式 AND/全文/默认操作符/未知字段报错/数值与字符串比较/正则/ncont)。
- `scry_app` 77 测 + 全 workspace clippy 0(仅上游 `block`)。回退路径保证纯文本搜索行为不变。

## 5. SiteMap 树(Top4 #4 的另一半 · 对标 Burp Target / Caido 站点树)

代理页新增 **Site map** 子页签(`HistTab::SiteMap`,排在 HTTP History / WebSocket 之后),
把抓到的流量按 **host → 路径段** 组织成可展开树;与 HTTPQL 互补——一个**按结构浏览**、一个**按字段查询**。

- **纯函数内核 `sitemap::build_site_tree(&[HttpFlow]) -> Vec<SiteNode>`**(可单测):
  按 `host` 分组 → 路径段 `Trie`(`BTreeMap` 保证字典序稳定);query/fragment 在建树时剥离
  (`/search?q=1` 与 `/search?q=2` 归同一节点)。每个 `SiteNode` 带 `count`(子树请求数)、
  `endpoint`(是否有请求**精确**命中此路径)、`subtree_idxs`(子树下全部请求在 `flows` 的下标)。
- **UI(`sitemap_panel`)**:左侧树(折叠箭头 + host=Globe / 端点=Tag / 纯容器=Folder 图标 + 计数),
  点节点选中并展开/折叠;右侧列出选中子树下的请求(方法 / 状态 / 路径,时间倒序封顶 300 行),
  点请求一键发到 Repeater。
- **与 HTTPQL 联动**:右侧头部「在历史中查询」按钮 → `SiteNode::httpql_query()` 生成
  `req.host.eq:"host"`(host 根)或 `req.host.eq:"host" AND req.path.cont:"/seg…"`(路径节点),
  写入搜索框并切回 HTTP History——即从「结构浏览」一键钻取到「字段过滤」。

**子集边界**:树按精确 host 分组(非 eTLD+1 归并,与左栏「网站分类」不同粒度);右侧请求列表静态渲染封顶
300 行(超大子树不虚拟化);节点右键菜单(加 scope / 扫描子树)留后续。

**验证**:`sitemap` 4 单测(建树 host/路径层级、query 剥离、空流量、`httpql_query` 生成)+
`scry_app` 81 测全过 + clippy 0(仅上游 `block`)。
