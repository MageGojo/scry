# 设计 · scry-mcp(让 AI 调度 scry 的引擎能力)

## 目标
把 scry 的核心能力(读历史 / 重放 / 各类扫描 / 越权 / 编解码)暴露成一个 **MCP 服务**,
让 AI(Cursor / Claude Desktop 等)直接「操作 scry」做渗透自动化:列流量、发请求、跑扫描、
看发现、解码。

## 架构选型(本期:独立 stdio 服务)
- **独立二进制 `scry-mcp`(crate `scry_mcp`)**,走 **MCP stdio 传输 = 行分隔 JSON-RPC 2.0**
  (与现有 `scry_ext_host` 的进程协议同风格:每行一个完整 JSON,stdout 专用于协议、日志走 stderr)。
- **共享同一套引擎 + 同一个历史库**:读 `~/.scry/scry.sqlite`(`scry_storage::Store`),
  主动能力复用 `scry_proxy::replay` / `scry_scan` / `scry_scan::authz` / `scry_codec`——
  **不重复造轮子、与 GUI 用同一份内核**。
- **不抢端口**:本期工具都是「读库 / replay 发包 / 纯函数」,**不**自起 MITM 代理(8888),
  因此与正在运行的 GUI 抓包**互不冲突**,可同时用。
- 出网:读环境变量 `SCRY_UPSTREAM`(如 `socks5://127.0.0.1:8899`)→ 复用 `upstream` 链式出网
  (墙内 / sing-box / QX 后面也能发包)。

> 后续可选(未做):在 GUI 内嵌 HTTP(SSE)MCP 服务,让 AI 直接操控**正在运行的窗口**
> (开抓包 / 切页 / 看实时流量)。本期先做最稳、即插即用的 stdio 版。

## MCP 方法
- `initialize` → 回 `protocolVersion`(回显客户端版本)+ `capabilities.tools` + `serverInfo`。
- `notifications/initialized`(通知,无响应)。
- `ping` → `{}`。
- `tools/list` → 工具清单(name + description + inputSchema)。
- `tools/call` → `{name, arguments}` → `{content:[{type:"text", text}], isError?}`。

## 工具清单(本期 8 个)
| 工具 | 作用 | 关键参数 |
|---|---|---|
| `list_flows` | 列最近抓到的流量(代理历史) | `limit`、`filter`(URL/host 子串) |
| `get_flow` | 看某条流的完整请求 + 响应(解码正文) | `index`(list 序号)或 `url` |
| `send_request` | 重放 / 主动发一个请求(=Repeater) | `url`、`method`、`headers`、`body` |
| `passive_scan` | 对历史流量跑被动规则 | `host`、`limit` |
| `active_scan` | 对 URL / 历史流量发主动探测(SQLi/XSS/路径穿越) | `url` 或 `host`、`limit` |
| `discovery_scan` | Nikto 式敏感文件 / 路径探测 | `url`(目标 origin) |
| `authz_test` | 越权 / 访问控制测试(高/低/匿名多身份重放比对) | `url`、`high_headers`、`low_headers` |
| `decode` | 编解码 / 加解密 / 哈希(智能解码 or 指定变换) | `input`、`transform`、`key`、`iv` |

所有发包工具响应里都带响应状态 / 头 / 解码正文(正文截断 ~4000 字符);扫描类回 findings 数组
(`rule_id/title/severity/url/detail`)。

## 注册(Cursor / Claude Desktop)
先 `cargo build --release -p scry_mcp`(产物 `target/release/scry-mcp`),然后在 MCP 配置里加:
```json
{
  "mcpServers": {
    "scry": {
      "command": "/Users/shcodegojo/Project/scry/target/release/scry-mcp",
      "env": { "SCRY_UPSTREAM": "" }
    }
  }
}
```
- Cursor:`~/.cursor/mcp.json` 同结构(`mcpServers`)。
- 墙内经 sing-box / QX:把 `SCRY_UPSTREAM` 设为本地混合入口(如 `socks5://127.0.0.1:8899`)。

## 安全
主动扫描 / 越权 / 发包都会向目标**真实发包**——只对**已获授权**的目标使用(与 GUI 同一条红线)。
