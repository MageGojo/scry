# Scry × Proxifier(按进程喂流量给 scry 抓包)

系统代理被 Quantumult X / Surge 占着时,用 **Proxifier 按进程**把目标流量转发给 scry
(`127.0.0.1:8888`)做解密抓包;scry 解密后的上游照常走系统默认路由(= QX/Surge),
**不抢系统代理**。本目录的 [`Scry.ppx`](./Scry.ppx) 就是配好的 Proxifier profile。

```
目标 App ──(Proxifier 按进程)──▶ scry MITM 解密(127.0.0.1:8888) ──默认路由──▶ QX/Surge ──▶ 真实服务器
                                         └ 落盘 + 仪表盘实时显示
```

## 只需一个 HTTPS(CONNECT)代理

scry 收到 `CONNECT` 后会**自动判断隧道里是 TLS 还是明文**:

| 隧道内容 | scry 处理 |
|---|---|
| TLS(首字节 0x16) | 动态签叶子证书 → **MITM 解密**(HTTPS / 443) |
| 明文 HTTP | 当普通 HTTP **抓取**(80 等) |

所以 Proxifier 里只配一个 **HTTPS 类型(= CONNECT 隧道)** 代理即可,所有端口统一走 CONNECT,不用按端口分流、不用 HTTP 类型代理。和 Burp / mitmproxy 的标准 Proxifier 配法一致。

> 已本地实证(`curl` 穿过 scry):明文绝对URI、明文-over-CONNECT(模拟 Proxifier 打 80)、HTTPS-MITM 三类都被抓到并落盘。

## 一、导入 profile

打开 Proxifier → 菜单 `File` → `Import Profile…` → 选 `scry/proxifier/Scry.ppx`,然后 **Load** 它(主界面顶部显示当前 profile 名 = Scry 即生效)。

> ⚠️ **macOS 首次用 Proxifier 必须授权它的系统/网络扩展**,否则 Proxifier 静默不拦截、scry 自然抓不到:
> 打开 Proxifier 会提示安装 Network/Privileged Helper;到 `系统设置 → 隐私与安全性`(及 `网络`)里**允许 Initex/Proxifier**,按提示重启 Proxifier。装好后主界面会实时滚动各 App 的连接。

## 二、抓包前置(scry 侧)

1. 启动 scry(`cargo run -p scry_app`),进入 **仪表盘 / Dashboard**。
2. 抓包源保持默认 **MITM 代理(`127.0.0.1:8888`)**,点 **开始抓包**(没点就不会监听 8888 → 抓不到)。
3. **安装信任根 CA(HTTPS 解密必须,90% 抓不到 HTTPS 都卡在这)**:scry 设置页点「一键安装信任」,或终端执行(会要管理员密码):

   ```bash
   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.scry/ca.pem
   security verify-cert -c ~/.scry/ca.pem -p ssl   # 显示 ...successful 即已信任
   ```

> ⚠️ **别用 Google / 大厂域名验证**:Chrome 对 `*.google.com`、`gstatic`、`clients4.google.com`、Twitter/FB 等做了**证书 pinning**,任何 MITM 都解不开(连接会秒断、页面打不开),这是正常现象,不代表 scry 坏了。验证解密请用 **curl + 非 pinning 站点**(见下)。

## 三、最快验证(curl,profile 默认就代理 curl/wget)

确保 Proxifier 已 `Load` 本 profile、scry 已点「开始抓包」,然后:

```bash
curl --cacert ~/.scry/ca.pem https://example.com/   # HTTPS → CONNECT → scry MITM 解密
curl http://example.com/                             # 明文 HTTP → scry 抓取
```

两条都应在 scry 的 HTTP History 里**实时出现**,HTTPS 那条能看到**解密后的明文**。
（注意:这里**不要**给 curl 设 `-x` / `https_proxy`——是 Proxifier 透明地把 curl 的连接喂给 scry,不是 curl 自己走代理。）

## 四、抓你自己的目标 App

编辑 `Scry.ppx`(或在 Proxifier 的 `Proxification Rules` 界面),把目标进程名加到 `Target to Scry` 规则的 `Applications`:

```
<Applications>curl; wget; 你的进程名</Applications>
```

- 进程名 = 可执行文件名(`.app` 取 `Contents/MacOS/` 里那个),用 `;` 分隔,支持 `*` 通配(如 `MyApp*`),**不要加引号**,名字里的空格原样写(如 `Google Chrome`)。
- 不确定进程名:看 Proxifier 主界面连接列表的 Application 列,或活动监视器。
- 想**抓全机**:把最后那条 `Default` 规则的 Action 改成 `Proxy 100`(防回环规则已保护 scry/QX)。

## 五、防回环(重要)

- profile 默认 **Default = Direct**,即**只代理列进 `Target to Scry` 的进程**,其余(含 scry 自身、QX/Surge、系统)全 Direct → 天然不回环。
- 另有一条 **`Bypass scry and proxy clients`** Direct 规则兜底:即使你把 Default 改成 Proxy,scry 解密后的上游连接(来自 `scry_app`/`scry_proxy`)和 QX/Surge 客户端也不会被再喂回 scry。
- 千万**别**把 `scry_app` / `scry_proxy` 放进 `Target to Scry`,否则死循环。

## 六、抓不到?按这个顺序排查

| 检查 | 说明 |
|---|---|
| Proxifier 系统扩展是否已授权 | 最常见!没授权 = 静默不拦截。见上「一」。主界面应能看到 App 的连接在滚动。 |
| 本 profile 是否已 Load | 顶部 profile 名要是 Scry;不是就 `File → Load Profile`。 |
| scry 是否点了「开始抓包」 | 没点则 8888 没监听。可 `lsof -nP -iTCP:8888 -sTCP:LISTEN` 确认有 scry 在听。 |
| 目标进程名是否匹配 | 先用默认的 `curl` 跑第三节命令验证链路;能抓到再换/加你的 App。 |
| HTTPS 报证书错 / 失败 | 没信任 scry 根 CA;装 `~/.scry/ca.pem` 或 curl 加 `--cacert`。 |
| scry 里 host 显示成 IP、上游失败 | 域名被本地解析了。本 profile 已设「通过代理解析」;确认 Proxifier `Name Resolution` 为 *Resolve hostnames through proxy*。 |
| 浏览器部分流量抓不到 | 浏览器多走 QUIC(UDP/443),Proxifier 只管 TCP;且 Chrome 实际联网在 `Google Chrome Helper` 子进程,需把 helper 也加进目标。可在浏览器禁用 HTTP/3。 |
| 某 App 仍解不开 | 有 SSL Pinning,任何 MITM 都解不开,属预期。 |

## 相关

- 设计背景:[`../docs/设计-抓包源选择.md`](../docs/设计-抓包源选择.md)、[`../docs/设计-解密抓包-与QX共存.md`](../docs/设计-解密抓包-与QX共存.md)
- scry 代理实现:`../crates/scry_proxy/src/lib.rs`(CONNECT 后 peek 首字节:TLS→`mitm.rs` 解密 / 明文→`capture_tunneled_http`;绝对 URI→`proxy_plain`)
