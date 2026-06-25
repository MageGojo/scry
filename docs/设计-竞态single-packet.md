# 设计 · 竞态 / single-packet 攻击(Race · 竞品缺口清单 第一档 ②)

> 对标 **Burp Repeater「并行发送组(single-packet attack)」/ Turbo Intruder**。
> 竞态类漏洞(超额提现、优惠券复用、限购击穿、TOCTOU)只有把多个相同请求挤进极小时间窗口才能稳定触发。

## 目标
给一条(可编辑的)请求,**同时**发 N 路完全相同的拷贝,让后端在极小窗口内并发处理,从而暴露竞态。
判定 = 响应**不一致**(状态码或长度不全相同)即疑似命中,需人工确认(竞态偶发)。

## 内核 `scry_proxy::race`(纯函数 judge + async 同步发送,6 单测)
- **两种发送模式 `RaceMode`**:
  - `LastByteSync`(**默认 / single-packet 精髓**):并发建立 N 条连接 → 各自把请求字节**写到只剩最后 1 个字节**
    (服务器已收到几乎完整请求,只差扳机)→ 一道 [`tokio::sync::Barrier`] 等所有连接就绪 → **同时**放出最后那个字节。
    这是 HTTP/1.1 上最可靠的竞态手法(Burp 单包攻击的 h1 等价物)。
  - `Parallel`:预连接后同时发**完整**请求,作为对「拆分/分块敏感」端点的兜底。
- **防死锁**:即使某路连接/握手失败,也仍到 barrier 报到一次(否则其余 N−1 路在 barrier 上死等),失败路记 error。
- **连接抽象 `Conn`**:明文 `TcpStream` / TLS `Box<TlsStream>` 统一手动委托 `AsyncRead`/`AsyncWrite`,以便跨 barrier 持有同一连接;TLS 装箱避免 `large_enum_variant`。
- **复用**:请求字节走 `ReplayRequest::to_wire()`(= `build_origin_request`,强制 `Connection: close`);HTTPS 复用与抓包同一套 `build_client_config` 的 rustls 客户端;读响应复用 `mitm::read_message`;出网经设置页上游 `upstream`。
- **判定 `summarize(&[RaceResult]) -> RaceSummary`**(纯函数):成功/出错计数、状态码分布(按次数降序)、不同 body 长度种类、`diverged`(状态码或长度不全相同)、`window_ms`(最快/最慢响应到达毫秒差 = 同步质量)。
- `RACE_MAX=64` 路上限(防误填打爆目标)。

## UI `scry_app/src/race.rs` + `Tab::Race`(图标 Clock)
- runner 镜像 `authz.rs`:后台**多线程** tokio runtime(worker 数随路数缩放,真并发放扳机)`block_on(run_race)` + `mpsc<RaceMsg>` 流式回传 + 前台 120ms 轮询 `drain_race`。
- 工具条:并发路数 `Segmented`(5/10/20/30/50/64)+ 模式 `Segmented`(最后字节同步 / 并行)+ 并发发送/停止 + 进度。
- 左:目标 + 可编辑原始请求;右:统计卡(徽标:疑似竞态红 / 响应一致绿 + 成功/出错/状态分布/同步窗口)+ 逐路结果表(#idx / 状态徽标 / 长度 / 耗时 /(出错))+ 彩色日志。
- 接线:代理历史右键「发送到竞态」(`fill_race_from_flow`)、左栏 Tools、顶栏页签、i18n 全。

## 诚实定界
- **h1 最后字节同步**已实现(覆盖绝大多数竞态场景);**真 HTTP/2 单包**(单 TCP 包多 stream,withhold 各 stream 的 END_STREAM 再齐放)更精准但要深控 h2 帧时序,**本次未做**,留后续增强。
- 竞态偶发:`diverged` 仅作「疑似」提示,结论需人工复跑确认;finding 不自动入扫描报告(交互式工具语义,与 Repeater 同)。
- 只对**已获授权**的目标使用。

## 验证(全绿)
- `scry_proxy::race` 6 单测:`split_point` 切分、`summarize`(一致/状态分歧/长度分歧/含错误)、**端到端最后字节同步**(本地 server 接 4 路连接 → run_race → 断言 4 路 200 + 服务端收到 4 个完整请求)。
- `scry_proxy` 57 测、`scry_app` 84 测全过;全 workspace `cargo build` + `clippy` **0 警告**(仅上游 `block` future-incompat)。
