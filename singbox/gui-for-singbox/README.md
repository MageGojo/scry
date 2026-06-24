# Scry 抓包配合插件 · GUI.for.SingBox

> 📌 这是 Scry 抓包方案里的 **T4 · 对接代理客户端**(进阶路径,用于抓「已运行的任意软件」)。
> 整体方案与各路径(T1 内置浏览器 / T2 托管启动 / T3 透明·嗅探 / T4 本路径)见 [`../../docs/设计-抓包方案重构.md`](../../docs/设计-抓包方案重构.md)。
> 想零配置抓网站 / 抓某个程序,优先用 Scry 仪表盘的 T1/T2;本插件适合「整机任意软件都走 sing-box TUN」的场景。

把 **Scry**(本仓库的 MITM 抓包/渗透套件)接进你日常用的 **GUI.for.SingBox**:
开启 TUN 后，任意软件的流量在网络层被 sing-box 接管，**先发给 Scry 解密抓包**，
Scry 解密后经其上游回流，再**按你订阅里选中的节点出网**。

- 保留你**全部订阅节点**，不用手填机场、不改 Chrome、不抢系统代理。
- 原理对标 mitmproxy 的 `--mode=upstream`：Scry 居中解密，上游交回 sing-box 出网。

## 链路

```text
任意软件
  │  (sing-box TUN 在网络层接管)
  ▼
sing-box ──route(tun-in, tcp)──▶ 出站 "scry" (127.0.0.1:8888  Scry MITM 解密 + 落盘)
                                     │  Scry 上游 = SCRY_UPSTREAM
                                     ▼
                             入站 "scry-upstream-in" (mixed 127.0.0.1:8899)
                                     │  按你原有路由(国内直连 / 境外走节点),天然防回环
                                     ▼
                                 你选中的订阅节点 ──▶ 真实服务器
```

## 工作机制（重要 · 为什么不用插件 `on::generate`）

GUI.for.SingBox 的**插件级 `on::generate` 触发器实测会被 GUI 在加载时剔除**——装好后看 `plugins.yaml`，本插件触发器只剩 `on::manual`，`onGenerate` 根本不会执行（这也是早期“一直抓不到包”的真根因）。所以本插件**不靠插件触发器改配置**，而是像官方 `plugin-relay-proxy-helper` 那样：

> 插件**生成一段 `onGenerate(config){...}` 混入脚本**，写进当前配置的「设置 → 混入和脚本 → 脚本操作」(`profile.script.code`)。GUI **每次生成内核配置时必定执行**该脚本——这条路才稳。

脚本在生成配置时往配置里加 3 样东西：
1. 出站 `scry`（http，指向 Scry 的 MITM）；
2. 入站 `scry-upstream-in`（mixed，Scry 解密后的回流口）；
3. 一条路由：**客户端入站**（TUN 模式 `tun-in` / 系统代理模式 `mixed-in`，自动识别并兜底 `tun-in`）的 TCP → `scry`。回流入站 `inbound` 不同，不会命中这条规则 → 天然防回环。

> 不动你的 DNS / fakeip / QUIC-block / 节点分组等任何既有设置；不抓 UDP（http 出站不支持，QUIC 若被 block 应用回退 TCP 正好便于抓包）。脚本**幂等**，可反复覆盖写入不重复。

## 安装

### 方式 A：脚本安装（推荐，会自动写好触发器与配置项）

```bash
# 1) 先【彻底退出】GUI.for.SingBox（运行中改 plugins.yaml 会在退出时被覆盖）
# 2) 执行：
bash scry/singbox/gui-for-singbox/install.sh
# 卸载：bash scry/singbox/gui-for-singbox/install.sh --uninstall
```

脚本做的事：备份 `plugins.yaml` → 复制 `plugin-scry-capture.js` 到 `~/Library/Application Support/GUI.for.SingBox/plugins/` → 把清单条目登记进 `plugins.yaml`（幂等）。

### 方式 B：在 GUI 里手动添加

「插件」页 → 添加 → 类型选 **File**，路径填本仓库的
`scry/singbox/gui-for-singbox/plugin-scry-capture.js` →
触发器勾选 `on::manual`（要自动拉起 Scry 再加 `on::core::started`/`on::core::stopped`；
**不要勾 `on::generate`**——会被 GUI 剔除，且本插件不再依赖它）。
配置项（可选，不填用默认）见下表。

## 配置项（设置页）

| key | 含义 | 默认 |
| --- | --- | --- |
| `MitmAddr` | Scry MITM(http 代理)地址 | `127.0.0.1:8888` |
| `UpstreamPort` | 新增 mixed 入站端口 = Scry 上游回流口 | `8899` |
| `UpstreamScheme` | Scry 上游协议(socks5/http，仅影响提示命令) | `socks5` |
| `CaptureCN` | 是否连国内/直连流量一起抓 | `false`(只抓境外) |
| `TunInbound` | 被接管流量的 TUN 入站 tag | `tun-in` |
| `AutoRun` | 内核启动时自动拉起 Scry(命令行) | `false` |
| `ScryCommand` | AutoRun 用的 `scry_proxy` 绝对路径 | 空 |

## 用法（每次抓包）

1. **写入抓包脚本（只需一次；改了配置项后重做一次）**：右键插件 →「生成抓包脚本并写入配置」（或点运行按钮）
   → 选配置 → 弹窗点「覆盖写入」直接写进该配置；或「复制脚本」后自己粘到该配置「设置 → 混入和脚本 → 脚本操作」。
2. **装根证书**：右键插件 →「安装根证书到系统信任」，按提示在终端执行
   `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.scry/ca.pem`
   （抓任意软件必须，否则目标拒绝 MITM 证书、握手失败）。
3. **启动 Scry**，上游指向本插件入站 `socks5://127.0.0.1:8899`：
   - 图形界面 `scry_app`：`export SCRY_UPSTREAM=socks5://127.0.0.1:8899` 后再启动；
   - 命令行：`scry_proxy proxy --upstream socks5://127.0.0.1:8899`。
   - （右键插件「复制 Scry 启动命令」可直接拿到。）
4. **GUI.for.SingBox 开启 TUN**，(重新)启动内核 —— 生成配置时会执行脚本把流量串进 Scry。
5. 打开任意软件正常用，解密流量会出现在 Scry 里。

## 排错

- **解不开**:证书 pinning(部分大厂自有域名)、微信 MMTLS 等任何 MITM 都解不开，握手秒断属正常。验证链路用非 pinning 站：`curl https://example.com`。
- **抓不到**:确认 ① Scry 在跑且上游 = `socks5://127.0.0.1:8899`；② 根证书已被系统信任(`security verify-cert -c ~/.scry/ca.pem -p ssl` 看到 successful)；③ GUI.for.SingBox 已开 TUN 且内核已重启加载插件。
- **插件没生效/没抓到**:确认 ① 已「生成抓包脚本并写入配置」(打开该配置「脚本操作」应能看到 Scry 脚本)；② 改完(重新)启动内核让脚本生效；③ 用 install.sh 装插件须在 App 退出状态下跑(运行中改 plugins.yaml 会被覆盖)。
- **国内 App 报错**:把 `CaptureCN` 关掉(默认即关)，国内/私网走直连不进 Scry。

## 与既有方案的关系

本目录是「GUI.for.SingBox 专用」的接入方式，保留订阅节点、零配置抓包；
上一级 `scry/singbox/scry-capture.json` 是**独立完整**的 sing-box 配置(需手填机场节点)，
适合直接 `sing-box run` 或不带订阅的场景。两者底层同一套 Scry upstream 能力。
