# Scry

> 占卜之术，窥探流量。A Burp-style security pentest suite — pure-Rust core + gpui(mage_ui) UI, macOS-first.

Scry 是一款面向安全渗透 / 逆向的流量分析与改写工具(对标 Burp Suite / Reqable),
纯 Rust 内核 + 基于 [`mage_ui`](../mage-ui)(gpui)的原生界面,**优先 macOS**。

## 设计取舍

- **抓包模型 =「按抓什么」+ scry 自管流量源**(开箱即用,不抢系统代理):默认由 Scry **自己拉起流量源**并自动喂代理 + 注入 CA ——
  T1 **内置浏览器**一键抓网站(过 pinning、免装系统 CA)、T2 **托管启动**任意程序/命令。抓「已运行的任意软件」走进阶路径:
  T4 对接代理客户端(sing-box 插件 / Quantumult X / [Proxifier](https://www.proxifier.com/))、T3 透明代理 / 被动嗅探。
  Scry 引擎(MITM + 上游回流)零改动复用,专注**解密 / 分析 / 改写 / 重放**。完整设计见 [`docs/设计-抓包方案重构.md`](docs/设计-抓包方案重构.md)。
- **不内置进程级劫持**:macOS 的进程劫持必须走 Network Extension(开发者账号 + 系统扩展签名),成本高,已规避。
- **UI 复用并反哺 `mage_ui`**:界面用同级 `mage-ui` 组件库(虚拟化 Table / 侧边栏 / 主题等),
  新需要的组件直接补进 `mage_ui`。
- **请求先保存(save-first)**:抓到请求的第一件事是落盘(SQLite + 去重),再分析,绝不只留内存。

## 工作区结构

```
scry/
├─ crates/
│  ├─ scry_core/     # 共享类型:HttpFlow / 头部 / 指纹
│  ├─ scry_ca/       # CA 证书生成与叶子证书签发(rcgen)+ 按域名缓存
│  ├─ scry_storage/  # SQLite 落盘 + 去重(请求先保存)
│  ├─ scry_decode/   # 展示用解码:Content-Encoding 解压 + charset + MIME 分类
│  ├─ scry_analyze/  # 分析层:参数/Cookie/摘要提取 + 过滤搜索 + 导出 curl(纯函数)
│  ├─ scry_proxy/    # HTTP/S MITM 引擎 + 代理入口 + 透明抓包(pf,macOS)+ Repeater 重放(replay)
│  └─ scry_app/      # gpui 界面(mage_ui),Burp 式三栏
└─ docs/             # 需求 / 设计 / 进度(文档驱动 + 断点续作)
```

## 快速开始

```bash
# 编译全部
cargo build

# 启动界面(Burp 式窗口):仪表盘选「抓什么」→ 一键抓
cargo run -p scry_app

# 单独跑引擎(本地测试入口:curl -x / 代理客户端指向 127.0.0.1:8888)
cargo run -p scry_proxy
```

## 路线图

详见 [`docs/进度.md`](docs/进度.md)。核心引擎(MITM 解密 / 上游回流 / 落盘 / Repeater / Intruder / Scanner /
Sequencer / Decoder / Comparer / TLS 指纹 / pcapng)已就绪;**当前主线 = 抓包方案重构**
([`docs/设计-抓包方案重构.md`](docs/设计-抓包方案重构.md)):T1 内置浏览器 → T2 托管启动 → Dashboard 四卡 → 零环境出包(.app 带 Chromium)。
