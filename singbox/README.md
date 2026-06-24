# Scry × sing-box 链式抓包(抓任意软件)

用 **sing-box 的 TUN** 在网络层接管**任意软件**的流量,链式喂给 **scry 做 MITM 解密抓包**,
scry 解密后再把流量交回 sing-box 的机场节点出网。**全程不碰系统代理**;开发时用 sing-box,日常切回圈X(两者 TUN 互斥)。

## 架构

```text
任意软件
  │  (sing-box TUN 在网络层接管,无需任何软件配代理)
  ▼
sing-box ──route: tun-in──▶ outbound "scry" (127.0.0.1:8888)
                                  │  scry MITM 解密 + save-first 落盘
                                  ▼  上游 = SCRY_UPSTREAM
                          scry-upstream-in (mixed 127.0.0.1:8899)
                                  │  route: 此 inbound 直接出网(防回环)
                                  ▼
                              outbound "airport" (你的机场节点) ──▶ 真实服务器
```

为什么 scry 要配「上游」:墙内 scry 解密后**直连出不去**,必须把上游交回 sing-box 的机场节点。
这就是本次给 scry 新增的 **upstream 上游代理**能力(对标 mitmproxy `--mode=upstream`),HTTP CONNECT / SOCKS5 都支持。
一份能力两个客户端通吃:`SCRY_UPSTREAM` 指向 sing-box,或指向 QX 的本地端口都行。

## 前置

1. **scry 根 CA 必须已装进系统信任**(System 钥匙串)。抓任意软件不是内置浏览器,无法用 `--ignore-cert`,
   目标软件会校验证书 → CA 不被信任就握手失败。scry 设置页「一键安装信任」,或:
   ```bash
   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.scry/ca.pem
   security verify-cert -c ~/.scry/ca.pem -p ssl   # 看到 successful 即可
   ```
2. sing-box **>= 1.11**(用到 route `action` 语法)。先校验配置:`sing-box check -c scry-capture.json`。
3. 把 `scry-capture.json` 里的 `airport` 出站换成**你自己的机场节点**(协议/服务器/端口/密码按订阅填)。

## 用法(开发抓包时)

1. **关掉 Quantumult X**(它和 sing-box 的 TUN 抢系统路由,二选一)。
2. **让 scry 带上游启动**(上游指向本配置的 `scry-upstream-in` = `127.0.0.1:8899`):
   - 命令行 CLI:
     ```bash
     scry_proxy proxy --upstream socks5://127.0.0.1:8899
     ```
   - GUI(`scry_app`):读环境变量 `SCRY_UPSTREAM`。macOS 的 GUI 从访达启动**不继承**终端变量,用下面任一:
     ```bash
     # 方式一:同终端导出后启动
     export SCRY_UPSTREAM=socks5://127.0.0.1:8899
     open -a scry_app            # 或直接运行可执行文件

     # 方式二:写进 launchd 环境(对所有 GUI 生效,重启前有效)
     launchctl setenv SCRY_UPSTREAM socks5://127.0.0.1:8899
     ```
     然后在 scry 里点「开始抓包」(MITM 代理源 127.0.0.1:8888)。
     > 不想折腾环境变量?图形「设置页直接填上游」正在路线图上(见 scry `docs/进度.md`)。
3. **启动 sing-box** 加载 `scry-capture.json`(GUI 导入或 `sudo sing-box run -c scry-capture.json`)。
4. 打开任意软件正常用 —— 流量会自动出现在 scry 里(已解密)。
5. 抓完:停 sing-box,重新打开圈X 恢复日常。

## 上游协议任选

`SCRY_UPSTREAM` / `--upstream` 接受:

```text
socks5://127.0.0.1:8899              # 推荐:远程解析,无 fake-ip 问题
http://127.0.0.1:8899                # mixed 入站同时支持
socks5://user:pass@host:port         # 带认证
http://user:pass@host:port
```

## 解不开的情况(正常,非 bug)

- **证书 pinning**(部分大厂自有域名)、**应用层加密**(微信 MMTLS 等):任何 MITM 都解不开,握手秒断属正常。
  要明文得 Frida hook(需关 SIP),不在本链路范围。
- 验证链路是否通,用普通 HTTPS 站(`curl https://example.com` 之类)最稳。

## 也可以配合 QX(不切 sing-box)

把上游指向 QX 暴露的本地端口即可(QX 需开本地 HTTP/SOCKS 入站),原理相同:
`SCRY_UPSTREAM=http://127.0.0.1:<QX本地端口>`。sing-box 链式更顺(本配置),QX 视你的策略而定。
