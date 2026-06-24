# 设计 · WebSocket 抓取 + HTTP/2 内核支持

> 目标:让 scry 的 MITM 内核除了 HTTP/1.1,还能**抓 WebSocket 消息**与**HTTP/2 流量**。
> 当前内核 `scry_proxy::mitm` 只会 HTTP/1.1(`read_message`),遇到 WS / h2 会坏。

## 一、现状与问题(已核实)

- MITM 主路径 `intercept_https`:对客户端用签发叶子证书做 TLS 服务端,对上游做 TLS 客户端,
  `read_message(client,false)` 读一个请求 → 转发 → `read_message(upstream,true)` 读一个响应 → 落盘回传。
  **每连接一请求**模型。
- **WebSocket 必坏**:WS 握手响应是 `101 Switching Protocols`(无 Content-Length / 非 chunked),
  `read_body` 走"读到连接关闭"分支 `while fill(...)`,而 WS 是长连接不关 →
  **阻塞到 `upstream_timeout`(30s)超时,握手响应都回不到客户端**,WS 彻底不可用。
- **HTTP/2 是雷**:`build_client_config`(上游)与 `build_server_config`(客户端)的 ALPN =
  `profile.alpn()`。默认 `Default` 档只 `http/1.1`(所以现在能抓);一旦切 `Chrome` 档提议 `h2`,
  握手协商成 h2 后,`read_message` 仍按 HTTP/1.1 文本解析二进制帧 → **直接崩**。

## 二、WebSocket 抓取设计

### 协议(RFC 6455)
- 握手:客户端 `GET ... Upgrade: websocket / Connection: Upgrade / Sec-WebSocket-Key`;
  服务端 `101 Switching Protocols + Sec-WebSocket-Accept`。之后连接变为**双向帧流**(不再是 HTTP)。
- 帧:`FIN+opcode(1B) | MASK+len7(1B) | [ext len 2/8B] | [mask key 4B] | payload`。
  客户端→服务端帧**必须 mask**,服务端→客户端**不 mask**。opcode:0x0 续帧 / 0x1 文本 / 0x2 二进制 /
  0x8 关闭 / 0x9 ping / 0xA pong。消息可被分片(首帧 opcode + 若干 Continuation,末帧 FIN=1)。

### 内核 `scry_proxy::websocket`(纯逻辑 + 单测)
- `OpCode` / `Frame{fin,opcode,payload}`。
- `FrameDecoder`:增量喂字节 → `next_frame()` 切出完整帧(处理跨 read 半帧、解 mask),数据不足返回 `None`。
- `Assembler`:把帧聚合成**消息**(数据帧按 FIN 聚合分片;control 帧 ping/pong/close 单独成消息)。
- `is_upgrade_request(headers)` / `is_switching_response(status, headers)`:握手识别。

### MITM 集成(`intercept_https`)
1. 读到请求后,若 `is_upgrade_request` → 进入 WS 路径(否则原 HTTP 流程)。
2. **原样**把握手请求转发上游(不能用 `build_origin_request`——它强制 `Connection: close` 且剔 `Connection` 头,会破坏 Upgrade)。
3. 只读上游响应**头**(到 `\r\n\r\n`,不读 body)。落盘握手 `HttpFlow`(GET → 101)。把响应头原样写回客户端。
4. 若状态 = 101 → 进入**双向转发 + 旁路抓取**:
   - `tokio::io::split` 两端,两个方向并发 `pump`。
   - `pump`:`read` 一段字节 → **立即原样写给对端**(字节透传,不等帧完整,零破坏)→ 同一份字节喂 `FrameDecoder`+`Assembler` → 每条完成消息存 `WsMessage` 落盘 + 推 UI。
   - 任一方向 EOF/出错 → 收尾。
5. 非 101(普通响应)→ 回退正常 HTTP 处理。

### 数据模型与存储
- `scry_core::WsMessage{ ts, conn_id, host, path, direction(ClientToServer/ServerToClient), opcode, payload }`。
- `scry_storage`:新表 `ws_messages`(**不去重**,自增 id);`save_ws` / `recent_ws` / `clear` 一并清;
  复用 `Store` 的可选推流通道(新增 `ws_tx`)。
- `conn_id`:握手时分配的递增连接序号(`AtomicI64`),关联同一 WS 连接的所有消息。

### UI(`scry_app` · proxy.rs `WebSocket` tab)
- 现为空架子。改为:WS 消息列表(方向箭头 ▲▼ / opcode 徽标 / host+path / payload 预览 + 时间),
  选中看完整 payload(文本/Hex)。state 加 `ws_msgs` + 推流接收。

## 三、HTTP/2 内核支持

### 策略:两端同协议(免跨协议桥接)
- **调整握手顺序**:CONNECT 后**先连上游 + TLS 握手**拿到上游协商的 ALPN,
  **再用"上游同款协议"作为 server config 的 ALPN 去 accept 客户端** → 两端必然同协议。
- 于是只需实现 **h1↔h1**(现有 `read_message`)与 **h2↔h2**(新增),不必处理 h1↔h2 混搭。
- 指纹伪装语义不变:上游 ALPN 仍由 `tls_profile` 决定(Chrome 提 h2),客户端跟随上游结果。

### h2↔h2(`h2` crate)
- 上游:`h2::client::handshake` → `(SendRequest, Connection)`,spawn connection driver。
- 客户端:`h2::server::handshake` → loop `accept() => (Request<RecvStream>, SendResponse)`。
- 每个 inbound stream spawn 一个任务:聚合 req body → `send_request` 发上游 → await `Response<RecvStream>` →
  聚合 resp body → **落 `HttpFlow`**(每 stream 一条,h2 多路复用=一个 TCP 多条 flow)→ `send_response`+`send_data` 回客户端。
- 钩子:接 `on_request` / `on_flow_complete`(与 h1 路径语义一致)。
- 依赖:`h2` / `http` / `bytes`。

### 兜底(即使 h2 全量未完成也先消雷)
- `build_server_config` 的 ALPN:在 h2 路径就绪前,**只提议 `http/1.1`**(不跟随指纹档),
  保证"切 Chrome 指纹"不再让 HTTPS 抓包崩;指纹档只作用于上游。

## 四、落地顺序
1. `websocket` 内核(帧解析 + 聚合)+ 单测。 ← 地基
2. `scry_core::WsMessage` + `scry_storage` ws 表/CRUD/推流。
3. `mitm` 集成 WS 升级检测 + 双向转发抓取。
4. UI:WebSocket tab 真实展示。
5. HTTP/2:握手顺序调整 + h2↔h2 转发 + 落 flow;先上 ALPN 兜底。
6. 全量 build/clippy/test + 真机冒烟(wss 站点 / h2 站点)。
