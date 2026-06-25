# 设计 · nuclei YAML 模板引擎(scry_nuclei)

> 第一档 ROI 缺口 #4:**nuclei 式 YAML 模板引擎**。杠杆最大——一次实现引擎,即可白嫖
> 社区 [`projectdiscovery/nuclei-templates`](https://github.com/projectdiscovery/nuclei-templates)
> 上的几千个检测模板(CVE / 暴露 / 错误配置 / 默认口令 / 指纹…),不必逐个手写规则。

## 1. 目标与边界

**目标**:解析 nuclei **HTTP 模板的实用子集**,对一个目标(`scheme://host[:port]`)运行,
复用现有 `scry_proxy::replay` 发包,用 matchers 判命中、用 extractors 抽证据,产出发现列表。

**契合现有架构**(与 SQLi / XSS / 越权 同范式):
- **纯函数内核 crate `scry_nuclei`**:模板解析 + 变量插值 + 请求构造 + matcher/extractor/DSL 求值,
  零 IO、零网络、可单测。
- **`scry_app/src/nuclei.rs` runner**:后台临时 current-thread tokio runtime 串行 `replay::send`
  + `mpsc` 流式回传 + 前台 120ms 轮询(完全对齐 `authz.rs`/`sqli.rs`)。
- **`Tab::Nuclei` 页**:目标 + 模板源(内置 / 目录)+ 严重度/标签过滤 → 运行 → 发现卡 + 日志。

**明确不做(子集边界,诚实声明)**:
- 多请求**跨响应关联**(`req-condition`、`{{status_code_1}}` 引用上一个响应)——每个 request 块独立求值。
- `dns` / `tcp` / `ssl` / `file` / `headless`(浏览器)/ `code`(执行外部程序)/ `flow`(JS 编排)协议。
- 复杂 DSL 辅助函数全集、`payloads` 模糊测试 + `attack`(clusterbomb 等)、`fuzzing`(DAST)。
- `interactsh`/OOB 占位符——OOB 盲注已由 `scry_oob` 单独覆盖;此处 `{{interactsh-url}}` 不解析。
- `variables` 自定义变量 / `helper functions`(`{{rand_base(5)}}` 等)——未知 `{{…}}` 原样保留。

> 子集足以跑通社区里数量最多、价值最高的 **exposures / misconfiguration / technologies /
> http CVE(基于响应特征判定)** 类模板;不支持的模板加载时按「不支持的特性」计数并跳过,绝不让单个
> 模板拖垮整批加载。

## 2. 支持的模板 schema 子集

```yaml
id: git-config                     # 模板唯一 id
info:
  name: Git Config Exposure        # 展示名(发现标题)
  author: pdteam
  severity: medium                 # info | low | medium | high | critical(缺省 info)
  description: ...
  tags: config,git,exposure        # 逗号串或列表
  reference: [ https://... ]

http:                              # 或旧式 `requests:`(两者都吃)
  - method: GET                    # path 形态:method + 模板化 path
    path:
      - "{{BaseURL}}/.git/config"
    headers: { X-Foo: bar }        # 可选
    body: ""                       # 可选
    matchers-condition: and        # and | or(matcher 之间;缺省 or)
    stop-at-first-match: true      # 命中即停该块的后续 path(缺省 false)
    matchers:
      - type: word                 # word | regex | status | size | dsl | binary
        part: body                 # body | header | all(status 隐含;缺省 body)
        words: ["[core]", "repositoryformatversion ="]
        condition: and             # and | or(本 matcher 内多项之间;缺省 or)
        case-insensitive: false
        negative: false
      - type: status
        status: [200]
    extractors:
      - type: regex                # regex | kval | dsl
        part: body
        group: 1
        regex: ["version = (.+)"]
      - type: kval
        kval: ["server"]           # 取响应头
```

**`raw:` 形态**(与 `path:` 互斥):整段原始 HTTP 请求,变量插值后解析:
```yaml
http:
  - raw:
      - |
        GET /actuator/env HTTP/1.1
        Host: {{Hostname}}
        Accept: application/json
```

### 支持的变量(`{{…}}`)
| 变量 | 取值(目标 `https://h:8443/app`) |
|---|---|
| `{{BaseURL}}` / `{{RootURL}}` | `https://h:8443`(根 URL;省略默认端口) |
| `{{Hostname}}` | `h:8443` |
| `{{Host}}` | `h` |
| `{{Port}}` | `8443` |
| `{{Scheme}}` | `https` |
| `{{Path}}` | 目标的基路径(常为空) |

> 单目标场景下 `BaseURL == RootURL`;未知变量原样保留(best-effort)。

## 3. matchers 求值

对每个发出的请求,拿回响应组 `RespData{ status, headers, body, duration_ms }`,逐 matcher 求值,
再按 `matchers-condition`(and/or)汇总。`negative: true` 则结果取反。

- **word**:`part` 文本里是否包含 words;`condition` and/or;`case-insensitive` 时双方小写。
- **regex**:`part` 文本是否匹配任一/全部正则(按 `condition`);正则非法则该项判否(不 panic)。
- **status**:响应状态码 ∈ status 列表。
- **size**:响应体字节数 ∈ size 列表。
- **binary**:`part`(默认 body)原始字节是否包含某十六进制串(子串扫描)。
- **dsl**:见 §5;表达式求值为真即命中。

`part` 文本投影:
- `body` → 响应体(lossy UTF-8);
- `header` → `Key: Value\n` 拼接的全部响应头;
- `all` → 头 + body(状态行 + 头 + 空行 + body)。

## 4. extractors 求值

命中后抽取证据(进发现详情):
- **regex**:对 `part` 文本取第 `group` 个捕获组(group 0 = 整体匹配)。
- **kval**:按名取响应头(`kval: ["server"]` → `Server` 头值;`-`/`_` 容错)。
- **dsl**:对表达式求值,字符串化结果。

## 5. DSL 子集(`dsl.rs`)

实现紧凑的递归下降求值器(`DslValue = Int | Str | Bool`),覆盖模板里最常见的写法;
解析/求值失败一律返回「假 / 空」,绝不 panic。

- **字面量**:整数、单/双引号字符串、`true`/`false`。
- **上下文标识符**:`status_code`、`content_length`、`body`、`header`/`all_headers`、`duration`。
- **函数**:`len`、`contains`、`icontains`、`tolower`、`toupper`、`startswith`、`endswith`、
  `trim`、`regex(pattern, input)`。
- **运算符**:`!`、`&&`、`||`、`==`、`!=`、`>`、`<`、`>=`、`<=`、`+`(数值相加 / 字符串相连)。
- **括号**分组。

> 不支持的函数(如 `md5`、`base64`、`unix_time`…)解析为未知标识 → 该 dsl 项判否。

## 6. 模板加载

- **内置模板**(`builtins.rs`):内嵌约 5 个示例模板(git/.env/phpinfo/.DS_Store/swagger),
  保证零配置即可演示 + 作为单测夹具。
- **目录加载**:runner(`scry_app/nuclei.rs`)递归遍历用户目录(默认 `~/.scry/nuclei-templates`)
  下的 `*.yaml`/`*.yml`,逐个 `scry_nuclei::parse_template` 解析;解析失败/不支持计数跳过。
  按严重度 / 标签过滤。文件遍历属 IO,放在 app 层(crate 保持纯函数)。

## 7. 运行流程(runner)

```
解析目标 → 收集模板(内置 [+ 用户目录]) → 按过滤保留
for template in templates:
  for req_block in template.requests:
    for built in build_block_requests(req_block, target):   # 展开 path/raw + 变量插值
      resp = replay::send(built)                              # 复用上游代理出网
      if req_block.evaluate(resp).matched:
        报告发现(模板名/严重度/命中 URL/matcher 名/提取值)
        if req_block.stop_at_first_match { break }
```

- 总请求预算上限(防失控);可暂停? 先做「停止」(对齐 sqli)。
- 发现去重:`(template_id, url)`。

## 8. UI(`Tab::Nuclei`)

- 工具条:目标输入、模板源(内置 / 目录路径)、严重度过滤下拉、标签过滤、运行/停止、进度。
- 左:模板源配置 + 加载统计(已加载 N · 失败 M)。
- 右:发现列表(复用 `scanner::finding_card` 的视觉,但标题为动态模板名 → 用专用卡)+ 彩色日志。
- 代理右键「发送到 Nuclei」:用该流的根 URL 预填目标。

## 9. 验证

- `scry_nuclei` 单测:YAML 解析(path/raw/各 matcher/extractor)、变量插值、matcher/extractor 求值、DSL。
- 端到端集成测(`tests/`):本地起 mock server,内置模板真 `replay::send` 命中 + 提取。
- `scry_app` build / clippy(0 警告)/ test 全绿。
