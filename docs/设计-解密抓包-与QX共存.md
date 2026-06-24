# 设计:解密 HTTPS 且与 QX 共存(Burp 式「客户端指向 scry」)

> 选定方案。环境:墙内 + Quantumult X(TUN,系统唯一上网出口)。目标:看 HTTPS 明文、**不动系统代理**、
> QX 照常工作。结论:**别在 QX 里做链式分流(会回环),而是像 Burp 那样把"要抓的那个客户端"直接指向 scry**。
>
> 📌 本文是 [`设计-抓包方案重构.md`](设计-抓包方案重构.md) 中 **T1(内置浏览器)/ T4(对接代理客户端)+ 统一回流(upstream)**
> 这条路线的**原理依据**:为何「让客户端指向 scry + scry 上游交回 QX」既能解密又不回环、不抢代理。重构后这套原理仍然成立,
> 只是「让客户端指向 scry」由 scry **自动完成**(内置浏览器 / 托管启动喂参数),不再要用户手动配。

## 为什么不在 QX 里做 `HOST-SUFFIX,目标,scry`(链式)
1. **QX 不支持 PROCESS-NAME**(iOS/macOS 拿不到发起进程)。所以无法把"scry 自己发往真实服务器的上游连接"排除——它会再次命中 `目标→scry` 规则,`QX→scry→QX→scry…` **死循环**。
2. **绑物理网卡绕过 QX 也不行**:墙内 `en1` 直连 example.com/baidu 全超时(`000`),本机只有走 QX 才能出网。所以 scry 的上游**必须**走 QX,这就和第 1 条的回环冲突。
3. 真正能防环的是进程级排除(Surge/Shadowrocket 的 `PROCESS-NAME`)或 Network Extension —— 都不是 QX 能做的。

## 正解:把客户端直接指向 scry(Burp 模型,不抢系统代理)
关键认知:**Burp 抓包也是"让浏览器/客户端指向它"**(浏览器代理设置 / Burp 内置浏览器 / 启动参数),它只是**不改系统代理**而已。同理:
```text
浏览器(代理=127.0.0.1:8888) ──回环──▶ scry MITM 解密 ──默认路由──▶ QX(TUN)──▶ 真实服务器
                                          │ 落盘 + UI 实时显示
```
- 浏览器→scry 是**回环(127.0.0.1)**,不进 QX 的 TUN;
- scry→目标走**默认路由 = QX**(墙内能出网),QX 把它当普通 app 流量正常代理;
- QX **没有** `目标→scry` 规则 → **不回环**;
- **系统代理 / QX 配置一行没动** → 满足"不抢代理",QX 对其它 app 照常。

## 操作步骤
1. **scry**:设置页 → 抓包方式「MITM 代理」→「一键安装信任」装根 CA →「开始抓包」(127.0.0.1:8888)。
2. **把要抓的客户端指向 scry**(任选其一):
   - **Chrome(独立配置,不影响日常)**:
     ```bash
     open -na "Google Chrome" --args --proxy-server="http://127.0.0.1:8888" \
       --user-data-dir="/tmp/scry-chrome"
     ```
   - **Firefox**:设置 → 网络设置 → 手动代理,HTTP/HTTPS 均填 `127.0.0.1:8888`(勾"也用于 HTTPS")。
   - **某个命令行 / SDK**:`export https_proxy=http://127.0.0.1:8888 http_proxy=http://127.0.0.1:8888`,并信任 `~/.scry/ca.pem`。
3. 在该浏览器里访问目标 → scry 的 history 实时出现**解密后的请求/响应**(Pretty 已接 `scry_decode`,gzip/br/chunked 自动解)。
4. 抓完关掉那个浏览器/取消其代理即可,QX 与系统代理始终没动。

## 局限(记录)
- **只抓"指向了 scry 的那个客户端"**。对「不认代理设置、又走系统 TUN 的 App」(很多原生 App),这招盖不到 —— 那种场景才需要 NE / 进程级方案(已评估搁置,见进度表)。对浏览器、curl、绝大多数带代理设置的开发/调试场景,这招够用且最干净。
- HTTPS 有 SSL Pinning 的客户端仍解不开(任何 MITM 都一样)。
- scry 引擎**零改动**:接收 CONNECT + 动态签叶子证书 + 双向握手取明文都已具备(`scry_proxy::mitm`)。已 headless 实证:curl `-x 127.0.0.1:8888` 抓到 HTTP + HTTPS(解密)共 4 条。
