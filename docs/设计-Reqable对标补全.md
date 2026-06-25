# 设计 · 对标 Reqable 抓包能力补全

> 用户点名补齐 6 项 Reqable 招牌抓包能力(已排除 T1 内置浏览器)。
> 落地顺序按「低风险高价值先行 + 纯函数内核 + 单测 + clippy 0 警告」。

## 范围(用户点名的 6 项)

1. **HAR 导出** —— 把(全部 / 选中)流量导出为标准 `.har`(HTTP Archive 1.2)。
2. **弱网 / 限速模拟(Throttle)** —— 代理转发链路上注入带宽上限 + 固定延迟,模拟 2G/3G/慢速。
3. **Map Local / Map Remote / Mock** —— 在 `rules.rs` 规则系统上扩展三类「重写动作」。
4. **gRPC / Protobuf 解码** —— 无需 `.proto` 的 protobuf wire 格式原始解码器(新模块,纯 Rust)。
5. **响应预览(Render)** —— `proxy.rs` Render 视图实做:图片预览(gpui)+ JSON 折叠树。
6. **HTTP/3 (QUIC) 抓取** —— 架构评估;真 MITM 需新 UDP 接入路径,单独处理 / 诚实定界。

## 各项设计

### 1. HAR 导出
- `har.rs` 新增纯函数 `flows_to_har(flows: &[HttpFlow]) -> String`(序列化 HAR 1.2:
  `log.creator` / `entries[]`,每条含 request/response/timings;二进制 body → `encoding:base64`)。
- `impl ScryApp::export_har_dialog`:`cx.prompt_for_paths`(保存)→ 后台写文件;支持「导出全部」「导出当前会话」。
- 与 import 对称、可单测(导出再导入往返一致)。

### 2. 弱网 / 限速 Throttle
- `ProxyConfig` 加 `throttle: Option<Throttle>`(`down_kbps` / `up_kbps` / `latency_ms`)。
- 纯函数 `Throttle::chunk_delay(bytes) -> Duration`(令牌桶式:按字节数算应耗时)可单测。
- 在 `proxy_plain` 回传客户端、`mitm` 回写两处:发送响应体前 `sleep(latency)`,分块发并按 `chunk_delay` 限速。
- 预设档:Off / GPRS / Regular3G / Good3G / Regular4G / 自定义。设置页(或 Dashboard)开关。

### 3. Map Local / Map Remote / Mock
- `rules.rs` 新增 `enum RewriteAction`(或扩展现有规则):
  - **Map Remote**:命中 URL → 改写目标 `host`/`port`/`scheme`/`path`(请求转发前,改 `flow` 字段)。
  - **Map Local**:命中 URL → 用本地文件内容当响应短路返回(`HookAction::Respond`,content-type 按扩展名猜)。
  - **Mock**:命中 URL → 用内联的 status/headers/body 短路返回。
- 复用现有 `ExtRegistry`(=`ExtensionHost`)的 `on_request` 钩子:Map Remote 改 flow、Map Local/Mock 返 `Respond`。引擎零改。
- 纯函数匹配 + 动作求值可单测;UI 在 Proxy → Options(规则页)新增「Map/Mock」分区。

### 4. gRPC / Protobuf 解码
- 新模块 `scry_codec::protobuf`:纯函数 `decode_protobuf(&[u8]) -> Vec<Field>`(varint / 64-bit / length-delimited / 32-bit
  四种 wire type;length-delimited 递归尝试当嵌套 message,失败回退按字符串 / bytes 展示)。
- 输出可读文本树(`field#N (type): value`)。
- gRPC:识别 `application/grpc`,剥 5 字节 length-prefixed framing(1 字节压缩标志 + 4 字节长度)再喂 protobuf 解码。
- 接进 Decoder 页(新增 Transform::Protobuf)+ 报文 Pretty 视图按 content-type 自动用 protobuf 渲染。

### 5. 响应预览(Render)
- `proxy.rs` Render 视图按 content-type 分流:
  - `image/*` → gpui `img()` 渲染(把 resp_body 写临时文件 / 用 data 源);
  - `text/html` → 暂渲染为「带语义高亮的源码 + 提示」(完整 HTML 渲染需 WebView,超范围);
  - JSON → 折叠树(可展开 / 收起节点)。
- 图片:解码 resp_body(按 content-encoding 解压后)→ 落 `~/.scry/preview/<fingerprint>.<ext>` → `img(path)`。

### 6. HTTP/3 (QUIC) —— 诚实定界
- **现状**:scry 是 HTTP CONNECT 代理;QUIC 走 UDP,无法经 CONNECT 代理。真 MITM 需要:
  - (A) UDP 透明拦截(已删 pf,macOS 抓不到本机自身流量)→ 不走;
  - (B) sing-box/QX 把 UDP 转发给 scry 的 QUIC 监听(quinn 终止 QUIC + 动态证书)→ 工程大;
  - (C) 被动 pcap + TLS keylog 解 QUIC(只读,不能改包)→ 辅助。
- **决策**:先做 (C) 被动方向的占位 / 评估,把主力放在「让浏览器/目标禁 QUIC 回退 TCP」(现状已可抓)。
  真 (B) 列为后续大件,需用户确认投入。

## 落地状态(2026-06-25 · 本轮)

| 功能 | 状态 | 关键实现 |
|---|---|---|
| HAR 导出 | ✅ 完成 | `har.rs` `flows_to_har`(HAR 1.2,二进制体 base64)+ `export_har_dialog`(写 `~/.scry/exports/` 并访达定位)+ Dashboard「导出 HAR」按钮;导出→导入往返单测 |
| 弱网/限速 Throttle | ✅ 完成 | `scry_proxy::throttle`(`Throttle` + `chunk_delay` + `write_throttled` + 7 档预设)接入 `proxy_plain` / `mitm` 回写;设置页下拉档位;3 单测 |
| Map Local/Remote/Mock | ✅ 完成 | `rules.rs` `MapAction`/`CompiledMap`(Remote 经 `ExtensionHost::remap_target` 改连接目标;Local/Mock 经 `HookAction::Respond` 短路);Options 页「Map & Mock」卡 + 持久化;5 单测 |
| gRPC/Protobuf 解码 | ✅ 完成 | `scry_codec::protobuf`(无 schema wire 解码:varint/64/len/32 + 嵌套递归 + gRPC 帧)+ `Transform::ProtobufDecode`(Decoder 页)+ 响应体按 content-type 自动渲染;6 单测 |
| 响应预览 Render | ✅ 完成(图片) | `proxy.rs` `render_preview`:位图 `image/*` 解码落临时文件 + `img()` 直显;HTML/SVG/其它给出说明。JSON 已有 Pretty 高亮(折叠树留作增强) |
| HTTP/3 (QUIC) | ✅ 被动抓取已接线 | QUIC 解密内核抽到独立轻量 crate **`scry_quic`**(`scry_proxy::quic` re-export 兼容):长包/Initial 检测 + RFC 9001 公开盐派生密钥(对 A.1 官方向量)+ 去头保护 + AES-128-GCM 解密 + 重组 CRYPTO + 解析 ClientHello → **SNI/ALPN**(无需私钥,对标 Wireshark)。**`scry_sniff` 接线**:BPF 加 `udp port 443`,客户端 Initial 经 `handle_quic`/`emit_quic` 落一条「加密」h3 流(host=SNI,标注 ALPN,四元组去重)。scry_quic 6 单测 + scry_sniff h3 端到端 1 单测 + `examples/quic_sni.rs` |

### HTTP/3 剩余(诚实定界)
- ~~被动 UDP 抓取接线~~ **✅ 已完成(2026-06-25)**:QUIC 内核抽成独立 crate `scry_quic`;`scry_sniff` BPF 加 `udp port 443`,`parse_segment` 出 UDP 分支,`handle_quic`/`emit_quic` 解客户端 Initial → 历史出 h3 流(SNI/ALPN,四元组去重)。单测端到端验证(自构造 Initial → 落库)。**真机仍待**:Kernel 模式下 sudo BPF + 真实 h3 流量(访问启用 QUIC 的站点)实拍验收。
- **真 h3 MITM(解密改包)**:需 QUIC 终止式代理(quinn + 动态证书)+ UDP 接入路径(sing-box UDP 转发 / NetworkExtension),是大件,待用户确认投入。

## 验证基线
- 每项:对应 crate `cargo test` + `cargo clippy`(0 警告,仅上游 block)。
- 收尾:全 workspace `build` + `clippy --all-targets`(0 警告)+ `test` 全绿。
  本轮新增测试:throttle 3 / map 5 / protobuf 6 / quic 5 / har 4(导出)。
