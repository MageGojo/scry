//! 极简界面国际化:[`Lang`] + 以英文原文为 key 的翻译表 [`Lang::t`]。
//!
//! 设计:UI 一律写**英文 key**,渲染时 `self.lang.t("English")` 取当前语言文案。
//! 英文模式直接回原文;中文模式查表(命中给中文,未命中回原文,如 URL / 协议名)。

use mage_ui::prelude::SharedString;

/// 界面语言。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    Zh,
    En,
}

impl Lang {
    /// 在中 / 英之间切换。
    pub fn toggle(self) -> Self {
        match self {
            Lang::Zh => Lang::En,
            Lang::En => Lang::Zh,
        }
    }

    /// 语言切换按钮上显示的短标(当前语言)。
    pub fn short(self) -> &'static str {
        match self {
            Lang::Zh => "中",
            Lang::En => "EN",
        }
    }

    /// 是否中文。
    pub fn is_zh(self) -> bool {
        matches!(self, Lang::Zh)
    }

    /// 翻译:英文 key → 当前语言文案。英文模式回原文;中文命中查表、否则回原文。
    pub fn t(self, en: &str) -> SharedString {
        if self == Lang::En {
            return SharedString::from(en.to_owned());
        }
        match en {
            // 顶栏 / 品牌
            "Pentest Suite" => "渗透套件".into(),
            // 工具页签
            "Dashboard" => "仪表盘".into(),
            "Proxy" => "代理".into(),
            "Repeater" => "重放".into(),
            "Intruder" => "爆破".into(),
            "Sequencer" => "序列器".into(),
            "Decoder" => "解码器".into(),
            "Comparer" => "比较器".into(),
            "Logger" => "日志".into(),
            "Extender" => "扩展".into(),
            "Settings" => "设置".into(),
            // 上游代理(设置页)
            "Upstream proxy (chain out)" => "上游代理(链式出网)".into(),
            "Decrypted traffic exits via this proxy. Off = direct connect." => "解密后的流量经此代理出网(如 sing-box 的 127.0.0.1:20122)。关闭 = 直连。".into(),
            "Enabled" => "已启用".into(),
            "Direct" => "直连".into(),
            // 左栏分组
            "Sessions" => "会话".into(),
            "Sites" => "网站分类".into(),
            "Tools" => "工具".into(),
            "Projects" => "项目".into(),
            // 会话名
            "Default Session" => "默认会话".into(),
            "VulnScan" => "漏洞扫描".into(),
            "Mobile App" => "移动应用".into(),
            "WebSocket Test" => "WebSocket 测试".into(),
            // 工具
            "Scope" => "范围".into(),
            // 代理右键菜单(级联父类目)
            "Send to" => "发送到".into(),
            "Copy as" => "复制为".into(),
            "Mark" => "标记".into(),
            // 项目
            "Demo Project" => "演示项目".into(),
            // Inspector
            "Inspector" => "检查器".into(),
            "Notes" => "备注".into(),
            "General" => "概览".into(),
            "Method" => "方法".into(),
            "Status" => "状态".into(),
            "Latency" => "耗时".into(),
            "Request Headers" => "请求头".into(),
            "Request Cookies" => "请求 Cookie".into(),
            "Response Headers" => "响应头".into(),
            "Response Cookies" => "响应 Cookie".into(),
            "(none)" => "(无)".into(),
            "Pending" => "等待中".into(),
            "Select a request to inspect" => "选中一条流量查看详情".into(),
            "No notes for this request" => "此请求暂无备注".into(),
            "Module planned · see docs" => "模块规划中 · 详见 docs/进度.md".into(),
            // 状态栏
            "Online" => "在线".into(),
            "Ready" => "就绪".into(),
            "Memory" => "内存".into(),
            "Events" => "事件".into(),
            "Duration" => "运行时长".into(),
            // Proxy 工具条
            "Intercept" => "拦截".into(),
            "on" => "开".into(),
            "off" => "关".into(),
            "HTTP History" => "HTTP 历史".into(),
            "WebSocket" => "WebSocket".into(),
            "Options" => "选项".into(),
            // 交互式拦截(Intercept)
            "Intercept requests" => "拦截请求".into(),
            "Intercept responses" => "拦截响应".into(),
            "Forward" => "放行".into(),
            "Drop" => "丢弃".into(),
            "Intercepted request" => "已拦截请求".into(),
            "Intercepted response" => "已拦截响应".into(),
            "Waiting for matching traffic…" => "等待匹配的流量…".into(),
            "Intercept is off" => "拦截已关闭".into(),
            "Intercepted traffic will appear here to edit" => "被拦截的报文会出现在这里供编辑".into(),
            "Sent to Repeater" => "已发送到重放".into(),
            "Sent to Intruder" => "已发送到爆破".into(),
            "Matching requests/responses will pause here for you to edit, then Forward or Drop." => {
                "匹配的请求 / 响应会暂停在这里,改完点「放行」或「丢弃」。".into()
            }
            "Turn on a switch above; matching traffic will pause here to edit and forward." => {
                "打开上方开关后,匹配的流量会暂停在这里供你改包放行。".into()
            }
            "All" => "全部".into(),
            "Clear" => "清空".into(),
            "Filter: host / path / header / body…" => "过滤:主机 / 路径 / 头 / body…".into(),
            // 历史表列
            "URL" => "URL".into(),
            "Size" => "大小".into(),
            "Time" => "时间".into(),
            "Type" => "类型".into(),
            // 报文区
            "Request" => "请求".into(),
            "Response" => "响应".into(),
            "Pretty" => "美化".into(),
            "Raw" => "原始".into(),
            "Hex" => "十六进制".into(),
            "Render" => "渲染".into(),
            "Send" => "发送".into(),
            "Select a row above to view the message" => "选中上方一行查看报文".into(),
            "Render view applies to responses only." => "渲染视图仅适用于响应。".into(),
            "Rendered preview is not available in this MVP." => "当前版本暂不支持渲染预览。".into(),
            "Awaiting response…" => "等待响应…".into(),
            "(empty body)" => "(空 body)".into(),
            // Repeater
            "Sending…" => "发送中…".into(),
            "Failed" => "失败".into(),
            "editable · request line + headers + blank + body" => {
                "可编辑 · 请求行 + 头 + 空行 + body".into()
            }
            "highlighted · switch to Raw to edit" => "已高亮 · 切到 Raw 可编辑".into(),
            // 右键上下文菜单
            "Send to Repeater" => "发送到重放".into(),
            "Copy as curl" => "复制为 curl".into(),
            "Copy as Python" => "复制为 Python".into(),
            "Copy as JavaScript (fetch)" => "复制为 JavaScript(fetch)".into(),
            "Copy as JavaScript (XHR)" => "复制为 JavaScript(XHR)".into(),
            "Copied to clipboard" => "已复制到剪贴板".into(),
            "read-only" => "只读".into(),
            "failed" => "失败".into(),
            "Edit the request on the left, then Send" => "编辑左侧请求,点「发送」查看响应".into(),
            "https://host[:port]" => "https://host[:端口]".into(),
            // 抓包
            "Start capture" => "开始抓包".into(),
            "Stop capture" => "停止抓包".into(),
            "Capturing" => "抓包中".into(),
            "Stopped" => "未抓包".into(),
            "Capture mode" => "抓包方式".into(),
            "Kernel sniff" => "内核抓包".into(),
            "MITM proxy" => "MITM 代理".into(),
            "Network interface" => "网卡".into(),
            "Authorize capture (BPF)" => "授权抓包(BPF)".into(),
            "No Proxifier needed; sniffs your NIC directly. HTTPS shows SNI only." => {
                "无需 Proxifier,直接抓本机网卡;HTTPS 仅显示 SNI(用代理模式可解密)。".into()
            }
            "TLS fingerprint" => "TLS 指纹(伪装)".into(),
            "Mimic a browser ClientHello upstream (proxy & repeater)" => {
                "让上游握手贴近浏览器 ClientHello(代理 + 重放生效)".into()
            }
            "Upstream JA4" => "上游 JA4(真实指纹)".into(),
            "JA4 is the real upstream fingerprint (order-stable). JA3 varies per connection; an exact browser match needs BoringSSL." => {
                "JA4 是上游握手的真实指纹(顺序无关、稳定);JA3 因 rustls 每连接随机化扩展而变;要逐字节等于浏览器需 BoringSSL。".into()
            }
            "Save pcapng (Wireshark)" => "保存 pcapng(Wireshark 可开)".into(),
            "Also write raw L2/L3 frames to ~/.scry/*.pcapng" => {
                "内核抓包时同时把原始 L2/L3 帧写入 ~/.scry/*.pcapng".into()
            }
            // 仪表盘 / 抓包源(Wireshark 式)
            "Capture" => "抓包".into(),
            "Choose a capture source, then start capturing" => "选择抓包源,然后开始抓包".into(),
            "Current source" => "当前源".into(),
            "Total flows" => "总流量".into(),
            "Capture source" => "抓包源".into(),
            "Click a source · capture targets the selected one" => {
                "点选一个源 · 抓包即抓选中的那个".into()
            }
            "Decrypts HTTPS" => "解密 HTTPS".into(),
            "Decrypt" => "解密".into(),
            "Kernel sniff · HTTPS shows SNI only" => "内核抓包 · HTTPS 仅显示 SNI".into(),
            "SNI only" => "仅 SNI".into(),
            "Default" => "默认".into(),
            "Default NIC" => "默认网卡".into(),
            "How to feed traffic" => "如何把流量喂给 Scry".into(),
            "Set the target app / browser proxy to 127.0.0.1:8888." => {
                "把目标 App / 浏览器的代理指向 127.0.0.1:8888。".into()
            }
            "Behind Quantumult X / Surge? Use Proxifier to route the target process to Scry; add a Direct rule for Scry itself to avoid a loop." => {
                "被 Quantumult X / Surge 占着系统代理?用 Proxifier 按进程把目标转发给 Scry;给 Scry 自身加 Direct 规则防回环。".into()
            }
            "Install & trust the root CA so HTTPS can be decrypted." => {
                "安装并信任根证书,HTTPS 才能解密。".into()
            }
            "Open certificate settings" => "打开证书设置".into(),
            "Passively sniffs the selected NIC — no Proxifier, no proxy needed." => {
                "被动嗅探选中网卡 —— 无需 Proxifier、无需代理。".into()
            }
            "HTTPS is not decrypted here (SNI only). Use the MITM proxy source to decrypt." => {
                "此模式不解密 HTTPS(仅 SNI)。要解密请改用 MITM 代理源。".into()
            }
            // 证书(设置页)
            "Root CA" => "根证书".into(),
            "Trust the Scry root CA to decrypt HTTPS" => "信任 Scry 根证书以解密 HTTPS".into(),
            "Certificate path" => "证书路径".into(),
            "Trust status" => "信任状态".into(),
            "Unknown" => "未检查".into(),
            "Checking…" => "检查中…".into(),
            "Trusted" => "已信任".into(),
            "Not trusted" => "未信任".into(),
            "Check trust" => "检查信任".into(),
            "Install & trust (one-click)" => "一键安装并信任".into(),
            "Installing…" => "安装中…".into(),
            "Reveal in Finder" => "在访达中显示".into(),
            "Open with Keychain" => "用钥匙串打开".into(),
            "Export installer (other devices)" => "导出安装包(其他电脑)".into(),
            "Exporting…" => "导出中…".into(),
            "Share one CA across devices" => "多台设备共用同一根 CA".into(),
            "Export the CA (with private key) and import it on another computer, so multiple machines use the same root." => {
                "导出含私钥的 CA,在另一台电脑导入,即可让多台设备共用同一根证书(A 机签的证书 B 机也认)。".into()
            }
            "The identity file contains the private key — transfer it only between your own devices." => {
                "身份文件含私钥,仅在你自己掌控的设备间传输,切勿公开。".into()
            }
            "Export CA (with key)" => "导出 CA(含私钥)".into(),
            "Import CA" => "导入 CA".into(),
            "Manual steps" => "手动安装步骤".into(),
            "1. Open Keychain Access and import ca.pem" => "1. 打开「钥匙串访问」导入 ca.pem".into(),
            "2. Find Scry Root CA, set Trust to Always Trust" => {
                "2. 找到「Scry Root CA」,信任改为「始终信任」".into()
            }
            "3. Re-run capture; HTTPS will decrypt" => "3. 重新开始抓包,HTTPS 即可解密".into(),
            "Proxy & Capture" => "代理与抓包".into(),
            "Proxy address" => "代理地址".into(),
            "Captured flows" => "条已抓取".into(),
            "Point Proxifier (or system proxy) to this address." => {
                "把 Proxifier(或系统代理)指向此地址。".into()
            }
            // 扫描器
            "Scanner" => "扫描器".into(),
            "Passive scan" => "被动扫描".into(),
            "Active scan" => "主动扫描".into(),
            "Sensitive files" => "敏感文件".into(),
            "Scanning…" => "扫描中…".into(),
            "Run a scan to find issues" => "运行扫描以发现问题".into(),
            "No issues found" => "未发现问题".into(),
            "All hosts" => "全部 host".into(),
            "Pause" => "暂停".into(),
            "Resume" => "继续".into(),
            // OOB 带外检测(interactsh)
            "OOB blind scan" => "带外盲扫".into(),
            "Stop OOB" => "停止带外".into(),
            // 站点爬虫(Spider)
            "Spider" => "爬虫".into(),
            "Crawl" => "爬取".into(),
            "Depth" => "深度".into(),
            "Pages" => "页数".into(),
            "Seed URL(s), e.g. https://example.com/" => "种子 URL(可多个),如 https://example.com/".into(),
            "Browser-driven crawl; traffic flows into Proxy history" => {
                "浏览器驱动爬取(真实 Chrome) · 流量汇入「代理」历史".into()
            }
            "Start a crawl to discover pages" => "开始爬取以发现页面".into(),
            // 严重度
            "Info" => "信息".into(),
            "Low" => "低危".into(),
            "Medium" => "中危".into(),
            "High" => "高危".into(),
            "Critical" => "严重".into(),
            // 扫描规则标题
            "Missing HSTS header" => "缺少 HSTS 头".into(),
            "Missing X-Content-Type-Options" => "缺少 X-Content-Type-Options".into(),
            "Missing Content-Security-Policy" => "缺少内容安全策略(CSP)".into(),
            "Clickjacking: no frame protection" => "点击劫持:无框架保护".into(),
            "Cookie without Secure flag" => "Cookie 缺少 Secure 标志".into(),
            "Cookie without HttpOnly flag" => "Cookie 缺少 HttpOnly 标志".into(),
            "Cookie without SameSite" => "Cookie 缺少 SameSite".into(),
            "Cookie set over plaintext HTTP" => "明文 HTTP 下发 Cookie".into(),
            "CORS wildcard with credentials" => "CORS 通配符且携带凭据".into(),
            "CORS allows any origin" => "CORS 允许任意来源".into(),
            "Missing Referrer-Policy" => "缺少 Referrer-Policy".into(),
            "Technology / version disclosure" => "技术栈 / 版本信息泄露".into(),
            "Server version disclosure" => "服务器版本泄露".into(),
            "Sensitive data in URL query" => "URL 查询串含敏感数据".into(),
            "HTTP Basic auth over plaintext" => "明文 HTTP 上的 Basic 认证".into(),
            "Verbose error / stack trace" => "详细报错 / 栈回溯泄露".into(),
            "CORS reflects arbitrary origin with credentials" => "CORS 反射任意源且携带凭据".into(),
            "CORS allows null origin with credentials" => "CORS 允许 null 源且携带凭据".into(),
            "Mixed content over HTTPS" => "HTTPS 页面混合不安全内容".into(),
            "AWS access key ID exposed" => "AWS Access Key ID 泄露".into(),
            "Google API key exposed" => "Google API Key 泄露".into(),
            "GitHub token exposed" => "GitHub 令牌泄露".into(),
            "Slack token exposed" => "Slack 令牌泄露".into(),
            "Stripe live secret key exposed" => "Stripe 生产密钥泄露".into(),
            "Private key exposed" => "私钥泄露".into(),
            "Param miner" => "参数挖掘".into(),
            "Hidden parameter discovered" => "发现隐藏参数".into(),
            "Request smuggling" => "请求走私".into(),
            "Possible HTTP request smuggling (timing)" => "疑似 HTTP 请求走私(计时)".into(),
            "Directory listing exposed" => "目录列表暴露".into(),
            "Reflected parameter in response" => "参数在响应中被反射".into(),
            "SQL injection (error-based)" => "SQL 注入(报错型)".into(),
            "Reflected XSS" => "反射型 XSS".into(),
            "Reflected value (non-HTML)" => "参数被反射(非 HTML 上下文)".into(),
            "Path traversal / LFI" => "路径穿越 / 本地文件包含".into(),
            "Server-side template injection (SSTI)" => "服务端模板注入(SSTI)".into(),
            "OS command injection" => "操作系统命令注入".into(),
            "CRLF / response header injection" => "CRLF / 响应头注入".into(),
            "Open redirect" => "开放重定向".into(),
            "SSRF (cloud metadata)" => "SSRF(云元数据)".into(),
            "XXE external entity (file disclosure)" => "XXE 外部实体(文件泄露)".into(),
            "LDAP injection" => "LDAP 注入".into(),
            "XPath injection" => "XPath 注入".into(),
            "Server-side includes (SSI) injection" => "服务端包含(SSI)注入".into(),
            "Host header injection" => "主机头注入".into(),
            "Unauthenticated access to protected resource" => "未认证即可访问受保护资源".into(),
            "Broken access control (privilege escalation)" => "越权访问(权限提升)".into(),
            // OOB 带外盲注确认发现标题
            "Blind SSRF (out-of-band)" => "盲 SSRF(带外确认)".into(),
            "Blind OS command injection (out-of-band)" => "盲 OS 命令注入(带外确认)".into(),
            "Blind SQL injection (out-of-band)" => "盲 SQL 注入(带外确认)".into(),
            "Blind XXE (out-of-band)" => "盲 XXE(带外确认)".into(),
            "Blind / stored XSS (out-of-band)" => "盲打 / 存储型 XSS(带外确认)".into(),
            // 敏感文件 / 路径扫描(Nikto 式)发现标题
            "Exposed Git repository" => "Git 仓库泄露".into(),
            "Exposed SVN repository" => "SVN 仓库泄露".into(),
            "Exposed Mercurial repository" => "Mercurial 仓库泄露".into(),
            "Exposed environment file" => "环境变量文件泄露".into(),
            "Exposed cloud credentials" => "云凭据泄露".into(),
            "Exposed npm credentials" => "npm 凭据泄露".into(),
            "Exposed password file" => "密码文件泄露".into(),
            "Exposed source backup" => "源码备份泄露".into(),
            "Exposed database dump" => "数据库导出泄露".into(),
            "Exposed backup archive" => "备份压缩包泄露".into(),
            "Exposed .DS_Store metadata" => ".DS_Store 元数据泄露".into(),
            "Exposed configuration file" => "配置文件泄露".into(),
            "PHP configuration disclosure" => "PHP 配置信息泄露".into(),
            "Server status page exposed" => "服务器状态页暴露".into(),
            "Exposed API documentation" => "API 文档泄露".into(),
            "Spring Boot Actuator exposed" => "Spring Boot Actuator 暴露".into(),
            "Spring Boot Actuator env exposed" => "Spring Boot Actuator env 暴露".into(),
            "Spring Boot heap dump exposed" => "Spring Boot 堆转储暴露".into(),
            "phpMyAdmin reachable" => "phpMyAdmin 可访问".into(),
            "Exposed source metadata" => "源码元数据泄露".into(),
            "Exposed Docker compose file" => "Docker compose 文件泄露".into(),
            "Exposed CI configuration" => "CI 配置泄露".into(),
            "Exposed IDE project files" => "IDE 项目文件泄露".into(),
            // 事件日志(Logger 页)
            "Event Log" => "事件日志".into(),
            "Logs are recorded as you capture, scan, and manage certificates." => {
                "抓包、扫描、证书等操作都会实时记录到这里。".into()
            }
            "Filter logs…" => "过滤日志…".into(),
            "Copy all" => "复制全部".into(),
            "Clear log" => "清空日志".into(),
            "No log entries yet" => "暂无日志".into(),
            // 日志级别
            "Debug" => "调试".into(),
            "Success" => "成功".into(),
            "Warning" => "警告".into(),
            "Error" => "错误".into(),
            // 爆破(Intruder)
            "Sniper" => "狙击手".into(),
            "Battering ram" => "攻城锤".into(),
            "Cluster bomb" => "集束炸弹".into(),
            "Start attack" => "开始爆破".into(),
            "Stop" => "停止".into(),
            "Total requests" => "请求总数".into(),
            "Target" => "目标".into(),
            "Request template" => "请求模板".into(),
            "mark injection points with §…§" => "用 §…§ 标记注入点".into(),
            "Auto-mark params" => "自动标记参数".into(),
            "Clear markers" => "清除标记".into(),
            "Payloads" => "载荷".into(),
            "one per line" => "每行一个".into(),
            "Payload" => "载荷".into(),
            "Pos" => "位置".into(),
            "Length" => "长度".into(),
            "Time(ms)" => "耗时(ms)".into(),
            "Match" => "匹配".into(),
            "Grep match (optional)" => "匹配关键字(可选)".into(),
            "No injection positions — mark some with §…§ or Auto-mark" => {
                "没有注入点 —— 用 §…§ 标记,或点「自动标记参数」".into()
            }
            "Add payloads (one per line) to start" => "添加载荷(每行一个)再开始".into(),
            "Configure positions & payloads, then Start attack" => {
                "配置注入点与载荷,然后开始爆破".into()
            }
            "Select a result to view the response" => "选中一个结果查看响应".into(),
            "Send to Intruder" => "发送到爆破".into(),
            // SQLi(SQL 注入)页
            "SQLi" => "SQL 注入".into(),
            "Send to SQLi" => "发送到 SQL 注入".into(),
            "Injection point" => "注入点".into(),
            "All parameters (auto)" => "全部参数(自动)".into(),
            "Delay" => "延时".into(),
            "Start test" => "开始测试".into(),
            "Injectable" => "可注入".into(),
            "Testing…" => "测试中…".into(),
            "No SQL injection found" => "未发现 SQL 注入".into(),
            "SQL injection" => "SQL 注入".into(),
            "DBMS" => "数据库".into(),
            "Techniques" => "注入技术".into(),
            "Boundary" => "闭合边界".into(),
            "Dump schema" => "枚举库表".into(),
            "Tables" => "表".into(),
            "rows" => "行".into(),
            "Configure a request and start testing" => "配置请求后开始测试".into(),
            "Only test targets you are authorized to assess." => {
                "仅测试你已获授权的目标。".into()
            }
            "Version" => "版本".into(),
            "Current user" => "当前用户".into(),
            "Current database" => "当前数据库".into(),
            "Error-based" => "报错型".into(),
            "Boolean-based blind" => "布尔盲注".into(),
            "Time-based blind" => "时间盲注".into(),
            "UNION query" => "联合查询".into(),
            // XSS(跨站脚本)页
            "Send to XSS" => "发送到 XSS".into(),
            "Exploitable" => "可利用".into(),
            "Reflected (not exploitable)" => "反射(不可利用)".into(),
            "No reflection found" => "未发现反射".into(),
            "DOM sinks" => "DOM 接收点".into(),
            "Static check" => "静态检测".into(),
            "Live browser" => "浏览器真执行".into(),
            "Live execution" => "浏览器执行确认".into(),
            "Stored" => "存储型".into(),
            "Stored XSS" => "存储型 XSS".into(),
            "Stored (encoded)" => "已存储(已编码)".into(),
            "HTML text" => "HTML 文本".into(),
            "Attribute (double-quoted)" => "属性(双引号)".into(),
            "Attribute (single-quoted)" => "属性(单引号)".into(),
            "Attribute (unquoted)" => "属性(无引号)".into(),
            "JavaScript string" => "JavaScript 字符串".into(),
            "JavaScript" => "JavaScript".into(),
            "HTML comment" => "HTML 注释".into(),
            // 越权 / 访问控制(Authz · Autorize 式)页
            "Authz" => "越权".into(),
            "Send to Authz" => "发送到越权".into(),
            "WS Repeater" => "WS 重放".into(),
            "Export report" => "导出报告".into(),
            "Access control test" => "越权 / 访问控制测试".into(),
            "Access control" => "访问控制".into(),
            "Access control enforced" => "访问控制到位".into(),
            "Broken access control" => "越权 / 访问控制缺陷".into(),
            "Test identities" => "测试身份".into(),
            "High-privilege identity (baseline)" => "高权限身份(基准)".into(),
            "Low-privilege identity" => "低权限身份".into(),
            "High-privilege (baseline)" => "高权限(基准)".into(),
            "Low-privilege" => "低权限".into(),
            "Anonymous" => "匿名".into(),
            "Header: value per line (empty = use the request as-is)" => {
                "每行一条 Header: value(留空 = 直接用上面的请求当基准)".into()
            }
            "Header: value per line (optional)" => "每行一条 Header: value(可选)".into(),
            "Replays the request as low-privilege & anonymous; the request itself is the privileged baseline." => {
                "用低权限 / 匿名身份重放该请求,与高权限基准比对;请求本身即高权限基准。".into()
            }
            "Enforced" => "拦截到位".into(),
            "Bypass" => "疑似越权".into(),
            "Inconclusive" => "无法判定".into(),
            "Baseline" => "基准".into(),
            "No access control issues" => "未发现越权问题".into(),
            "Configure identities and start testing" => "配置身份后开始测试".into(),
            // 竞态 / single-packet(Race)
            "Race" => "竞态".into(),
            "Race / single-packet" => "竞态 / 单包攻击".into(),
            "Send group" => "并发发送".into(),
            "Requests" => "路数".into(),
            "Mode" => "模式".into(),
            "Last-byte sync" => "最后字节同步".into(),
            "Parallel" => "并行".into(),
            "Send to Race" => "发送到竞态".into(),
            "Possible race condition" => "疑似竞态".into(),
            "Responses consistent" => "响应一致".into(),
            "OK" => "成功".into(),
            "Errors" => "出错".into(),
            "Sync window" => "同步窗口".into(),
            "No responses" => "无响应".into(),
            "Set count and send the group" => "设置路数后并发发送".into(),
            "Fires N identical requests at once (last-byte sync). Diverging responses suggest a race condition — confirm manually. Authorized targets only." => {
                "同时发出 N 个相同请求(最后字节同步)。响应出现差异 = 疑似竞态,需人工确认。仅限已授权目标。".into()
            }
            // 爆破:载荷生成器 / 处理器 / 导出
            "List" => "列表".into(),
            "Numbers" => "数字".into(),
            "Brute force" => "字符集暴破".into(),
            "Range" => "区间".into(),
            "Charset" => "字符集".into(),
            "Prefix" => "前缀".into(),
            "Suffix" => "后缀".into(),
            "Preview" => "预览".into(),
            "Export CSV" => "导出 CSV".into(),
            "Threads" => "并发".into(),
            "Throttle ms" => "限速ms".into(),
            "Sort" => "排序".into(),
            "Extract" => "提取".into(),
            "No payloads generated — check payload source" => "未生成任何载荷 —— 检查载荷来源配置".into(),
            "from-to[:step] — e.g. 1-9999 or 0-100:5" => "from-to[:step] —— 如 1-9999 或 0-100:5".into(),
            "charset × length min-max — careful: combinations explode" => {
                "字符集 × 长度 min-max —— 注意组合数会爆炸".into()
            }
            // 序列器(Sequencer)
            "Analyze" => "分析".into(),
            "Load sample" => "载入样例".into(),
            "From traffic" => "从流量提取".into(),
            "Copy report" => "复制报告".into(),
            "Report copied" => "报告已复制".into(),
            "Analyze first" => "请先分析".into(),
            "tokens" => "个令牌".into(),
            "Token samples" => "令牌样本".into(),
            "one token per line" => "每行一个令牌".into(),
            "Analysis" => "分析报告".into(),
            "entropy & FIPS 140-2" => "熵 & FIPS 140-2".into(),
            "Paste tokens and Analyze to estimate randomness" => "粘贴令牌后点「分析」估计随机性".into(),
            "Overall quality" => "总体评级".into(),
            "Poor" => "差".into(),
            "Weak" => "弱".into(),
            "Reasonable" => "尚可".into(),
            "Strong" => "强".into(),
            "Excellent" => "极强".into(),
            "Char entropy" => "字符熵".into(),
            "Samples" => "样本数".into(),
            "Unique" => "去重数".into(),
            "Duplicate samples found" => "发现重复样本".into(),
            "Metrics" => "指标".into(),
            "Bit entropy" => "比特熵".into(),
            "Mean bits/char" => "每字符均熵".into(),
            "Ones ratio" => "1 比特占比".into(),
            "Per-character entropy" => "每字符位置熵".into(),
            "bit / position (max 8)" => "bit / 位置(上限 8)".into(),
            "more positions" => "个更多位置".into(),
            "Monobit" => "单比特".into(),
            "Poker" => "扑克".into(),
            "Runs" => "游程".into(),
            "Long run" => "长游程".into(),
            "FIPS inspects the raw byte stream; text tokens (base62/hex) fail Monobit by the constant high bit — judge by character entropy." => {
                "FIPS 检验的是原始字节流;文本令牌(base62/hex)的高位恒 0 会让 Monobit 失败,属编码特征而非弱点 —— 强度以字符熵为准。".into()
            }
            "FIPS needs ≥20000 bit; collect more samples" => "FIPS 需 ≥20000 bit,样本不足".into(),
            // 解码器(Decoder)
            "Smart decode" => "智能解码".into(),
            "Output → input" => "输出转输入".into(),
            "Could not detect an encoding" => "未能识别出编码".into(),
            "Output promoted to input" => "已把输出转为输入".into(),
            "Encode / Decode" => "编码 / 解码".into(),
            "Hash (one-way)" => "哈希(单向)".into(),
            "Input" => "输入".into(),
            "Output" => "输出".into(),
            "Copy" => "复制".into(),
            "chars" => "字符".into(),
            "bytes" => "字节".into(),
            "Paste text to encode / decode…" => "粘贴要编 / 解码的文本…".into(),
            "Result appears here" => "结果显示在这里".into(),
            "URL encode" => "URL 编码".into(),
            "URL decode" => "URL 解码".into(),
            "HTML encode" => "HTML 编码".into(),
            "HTML decode" => "HTML 解码".into(),
            "Base64 encode" => "Base64 编码".into(),
            "Base64 decode" => "Base64 解码".into(),
            "Hex encode" => "Hex 编码".into(),
            "Hex decode" => "Hex 解码".into(),
            "Base32 encode" => "Base32 编码".into(),
            "Base32 decode" => "Base32 解码".into(),
            "Base58 encode" => "Base58 编码".into(),
            "Base58 decode" => "Base58 解码".into(),
            "Binary encode" => "二进制编码".into(),
            "Binary decode" => "二进制解码".into(),
            "Unicode escape" => "Unicode 转义".into(),
            "Unicode unescape" => "Unicode 反转义".into(),
            "JWT decode" => "JWT 解析".into(),
            "Protobuf / gRPC decode" => "Protobuf / gRPC 解码".into(),
            // 响应渲染预览(Render)
            "Preview failed" => "预览失败".into(),
            "HTML preview: switch to Pretty / Raw to read the source (full rendering needs a browser)." => {
                "HTML 预览:切到「美化 / 原始」查看源码(完整渲染需浏览器)。".into()
            }
            "SVG is text — view it under Pretty / Raw." => {
                "SVG 是文本 —— 在「美化 / 原始」中查看。".into()
            }
            "No visual preview for this content type. Use Pretty / Raw / Hex." => {
                "该内容类型无可视预览,请用「美化 / 原始 / 十六进制」。".into()
            }
            // 解码器:对称加解密 / MAC + 分组标签
            "Encrypt / Decrypt (key)" => "加密 / 解密(需密钥)".into(),
            "Hash / MAC (one-way)" => "哈希 / MAC(单向)".into(),
            "Key" => "密钥".into(),
            "IV" => "IV".into(),
            "Key (UTF-8) · AES needs 16/24/32 bytes" => "密钥(UTF-8)· AES 需 16/24/32 字节".into(),
            "IV (16 bytes) · AES-CBC only" => "IV(16 字节)· 仅 AES-CBC".into(),
            "XOR encrypt" => "XOR 加密".into(),
            "XOR decrypt" => "XOR 解密".into(),
            "RC4 encrypt" => "RC4 加密".into(),
            "RC4 decrypt" => "RC4 解密".into(),
            "AES-CBC encrypt" => "AES-CBC 加密".into(),
            "AES-CBC decrypt" => "AES-CBC 解密".into(),
            "AES-ECB encrypt" => "AES-ECB 加密".into(),
            "AES-ECB decrypt" => "AES-ECB 解密".into(),
            // 比较器(Comparer)
            "Compare" => "比较".into(),
            "Swap A ⇄ B" => "交换 A ⇄ B".into(),
            "Lines" => "按行".into(),
            "Words" => "按词".into(),
            "Chars" => "按字符".into(),
            "Item A" => "第一项".into(),
            "Item B" => "第二项".into(),
            "Edit both items, then Compare" => "编辑两项后点「比较」".into(),
            "Difference" => "差异".into(),
            "Similarity" => "相似度".into(),
            "Identical" => "完全相同".into(),
            "The two items are identical" => "两项内容完全相同".into(),
            "Added" => "新增".into(),
            "Removed" => "删除".into(),
            "Paste the first item…" => "粘贴第一项…".into(),
            "Paste the second item…" => "粘贴第二项…".into(),
            // 发送到比较器(Proxy 右键 / Repeater 面板头)
            "Request → Comparer A" => "请求 → 比较器 A".into(),
            "Request → Comparer B" => "请求 → 比较器 B".into(),
            "Response → Comparer A" => "响应 → 比较器 A".into(),
            "Response → Comparer B" => "响应 → 比较器 B".into(),
            "Sent to Comparer A" => "已发送到比较器 A".into(),
            "Sent to Comparer B" => "已发送到比较器 B".into(),
            "Paste → A" => "粘贴 → A".into(),
            "Paste → B" => "粘贴 → B".into(),
            "Clipboard is empty" => "剪贴板为空".into(),
            // 仪表盘(抓什么 · 重构)—— scry 自管流量源
            "What do you want to capture?" => "你要抓什么?".into(),
            "Scry launches the traffic source itself — no system proxy, no Chrome tweaks" => {
                "由 Scry 自己拉起流量源 —— 不抢系统代理、不改 Chrome".into()
            }
            "MITM core" => "MITM 内核".into(),
            "Idle" => "未启动".into(),
            "Decrypting capture (MITM core)" => "解密抓包(MITM 内核)".into(),
            "Passive (auxiliary · metadata only)" => "被动嗅探(辅助 · 仅元数据)".into(),
            "Capture a website (built-in browser)" => "抓网站(内置浏览器)".into(),
            "Scry launches Chromium pointed at it — decrypts HTTPS, bypasses pinning, no system CA" => {
                "Scry 拉起 Chromium 指向自己 —— 解密 HTTPS、过 pinning、免装系统 CA".into()
            }
            "Recommended" => "推荐".into(),
            "Isolated profile — won't touch your daily browser" => {
                "独立 profile —— 不影响你的日常浏览器".into()
            }
            "Using an HTTP proxy disables QUIC, so nothing slips by" => {
                "走 HTTP 代理会自动禁用 QUIC,流量不会绕过".into()
            }
            "Launch browser capture" => "启动浏览器抓包".into(),
            "Close browser" => "关闭浏览器".into(),
            "Built-in browser running" => "内置浏览器运行中".into(),
            "No Chrome/Chromium found — download a built-in one for one-click capture" => "未检测到 Chrome/Chromium —— 下载一个内置浏览器即可一键抓包".into(),
            "Download built-in browser (~150MB)" => "下载内置浏览器(约 150MB)".into(),
            "Downloading built-in browser…" => "正在下载内置浏览器…".into(),
            "Capture a program / command" => "抓程序 / 命令".into(),
            "Launches it with proxy + CA injected (curl, Electron, Java, Python, Node…)" => {
                "拉起它并注入代理 + CA 信任(curl、Electron、Java、Python、Node…)".into()
            }
            "Launch & capture" => "启动并抓包".into(),
            "e.g. curl https://example.com" => "例如:curl https://example.com".into(),
            "Connect a proxy client (sing-box / QX / Proxifier)" => {
                "对接代理客户端(sing-box / QX / Proxifier)".into()
            }
            "Capture any already-running app by routing its traffic into Scry" => {
                "把已运行的任意软件流量引入 Scry 抓取".into()
            }
            "Advanced" => "进阶".into(),
            "Point the client proxy to 127.0.0.1:8888 (sing-box: use the Scry plugin)" => {
                "把客户端代理指向 127.0.0.1:8888(sing-box 用 Scry 插件)".into()
            }
            "Set upstream to socks5://127.0.0.1:8899 in Settings so traffic exits via your nodes" => {
                "在设置页把上游设为 socks5://127.0.0.1:8899,让流量经你的节点出网".into()
            }
            "Start MITM core only" => "仅启动 MITM 内核".into(),
            "Upstream / cert settings" => "上游 / 证书设置".into(),
            "Connect Proxifier" => "对接 Proxifier".into(),
            "Force any already-running app's traffic into Scry by process" => {
                "按进程把任意已运行软件的流量强制喂给 Scry".into()
            }
            "In Proxifier, add proxy 127.0.0.1:8888 (HTTPS) + a rule sending the target app to it" => {
                "在 Proxifier 里加代理 127.0.0.1:8888(HTTPS),再加规则把目标软件指向它".into()
            }
            "Give Scry itself (and QX/sing-box) a Direct rule to avoid loops; install the CA in Settings" => {
                "给 Scry 自身(及 QX/sing-box)加 Direct 规则防回环;到设置页安装根证书".into()
            }
            "Capture the whole machine (passive sniff)" => "抓整机(被动嗅探)".into(),
            "Any app, but HTTPS shows metadata + SNI only (no decryption)" => {
                "任意软件,但 HTTPS 仅元数据 + SNI(不解密)".into()
            }
            "Metadata only" => "仅元数据".into(),
            "Auxiliary" => "辅助".into(),
            "Switch" => "切换".into(),
            "Authorize & sniff" => "授权并嗅探".into(),
            // 仪表盘:离线导入(HAR / XHR)
            "Import" => "导入".into(),
            "Import / offline" => "离线导入 / 分析".into(),
            "Import HAR / XHR file" => "导入 HAR / XHR 文件".into(),
            "Export HAR" => "导出 HAR".into(),
            // 设置 → 弱网 / 限速模拟
            "Network throttle" => "弱网 / 限速模拟".into(),
            "Simulate slow networks (2G/3G). Applies on next capture start." => {
                "模拟慢速网络(2G/3G)。下次开始抓包时生效。".into()
            }
            "Off" => "关闭".into(),
            "Regular 2G" => "普通 2G".into(),
            "Regular 3G" => "普通 3G".into(),
            "Good 3G" => "良好 3G".into(),
            "Regular 4G" => "普通 4G".into(),
            // 代理 → Options 页:Map & Mock
            "Map & Mock" => "映射 / 模拟(Map & Mock)".into(),
            "Map Remote" => "映射远程(Map Remote)".into(),
            "Map Local" => "映射本地(Map Local)".into(),
            "Mock" => "模拟响应(Mock)".into(),
            "Action" => "动作".into(),
            "Match URL contains…" => "匹配 URL 包含…".into(),
            "Target host[:port] / local file / content-type" => {
                "目标 host[:port] / 本地文件 / content-type".into()
            }
            "Target host[:port]" => "目标 host[:port]".into(),
            "Local file" => "本地文件".into(),
            "Content-Type" => "内容类型".into(),
            "Mock response body" => "模拟响应体".into(),
            "Enter a URL match first" => "请先填写 URL 匹配".into(),
            "Enter a local file path" => "请填写本地文件路径".into(),
            "Enter a target host[:port]" => "请填写目标 host[:port]".into(),
            "No rules — redirect a host (Map Remote), serve a local file (Map Local), or return a canned response (Mock)." => {
                "暂无规则 —— 可重定向主机(Map Remote)、用本地文件替身响应(Map Local)、或返回固定响应(Mock)。".into()
            }
            "Load requests exported from browser DevTools (Network → Save all as HAR)" => {
                "导入浏览器开发者工具导出的请求(Network → 右键 Save all as HAR)".into()
            }
            "Imported requests go into history — ready for Repeater / Scanner" => {
                "导入的请求会进入历史,可直接用于重放 / 扫描 / 比对".into()
            }
            "Choose .har file…" => "选择 .har 文件…".into(),
            "Offline" => "离线".into(),
            // 代理 → Options 页:拦截规则(自定义范围 + Match & Replace)
            "Intercept scope" => "拦截范围".into(),
            "Match & Replace" => "匹配替换".into(),
            "Add rule" => "添加规则".into(),
            "Skip" => "排除".into(),
            "Negate" => "取反".into(),
            "Text" => "文本".into(),
            "Regex" => "正则".into(),
            "(append)" => "(追加)".into(),
            // 条件字段(Field)
            "Host" => "主机".into(),
            "Path" => "路径".into(),
            "Request headers" => "请求头".into(),
            "Request body" => "请求体".into(),
            "Response headers" => "响应头".into(),
            "Response body" => "响应体".into(),
            "Anywhere" => "任意位置".into(),
            // 匹配算子(Op)
            "contains" => "包含".into(),
            "equals" => "等于".into(),
            "wildcard" => "通配".into(),
            "regex" => "正则".into(),
            // Match & Replace 目标(Target,单条头)
            "Request path" => "请求路径".into(),
            "Request header" => "请求头".into(),
            "Response header" => "响应头".into(),
            // 表单占位 / 提示
            "value, e.g. api.example.com" => "值,如 api.example.com".into(),
            "Find (empty = append a header)" => "查找(留空 = 追加一条头)".into(),
            "Replace with…" => "替换为…".into(),
            "Enter a match value first" => "请先填写匹配值".into(),
            "Enter find or replace text first" => "请先填写查找或替换内容".into(),
            "No scope rules — intercept pauses all matching traffic. Add a rule to narrow it." => {
                "暂无范围规则 —— 拦截会暂停该方向全部流量;加一条规则可缩小范围。".into()
            }
            "No rules — add one to rewrite live traffic automatically (e.g. spoof User-Agent)." => {
                "暂无规则 —— 加一条即可自动改写实时流量(如伪造 User-Agent)。".into()
            }
            "Rules below shape interception and auto-rewrite. Scope decides which traffic pauses in Intercept; Match & Replace rewrites traffic automatically (no pause). Tip: right-click a row in HTTP History for quick scope." => {
                "下面的规则控制拦截与自动改包:范围决定哪些流量在「拦截」页暂停;匹配替换则自动改写流量(不暂停)。提示:在 HTTP 历史中右键某行可快速设置范围。".into()
            }
            "Intercept only this host" => "仅拦截此 Host".into(),
            "Don't intercept this host" => "不拦截此 Host".into(),
            "Turn off intercept" => "关闭拦截".into(),
            "Intercept turned off" => "已关闭拦截".into(),
            // Nuclei 模板扫描页
            "Template scan" => "模板扫描".into(),
            "Start scan" => "开始扫描".into(),
            "Severity" => "严重度".into(),
            "All severities" => "全部严重度".into(),
            "Low and above" => "Low 及以上".into(),
            "Medium and above" => "Medium 及以上".into(),
            "High and above" => "High 及以上".into(),
            "Critical only" => "仅 Critical".into(),
            "Templates directory" => "模板目录".into(),
            "Templates loaded" => "已加载模板".into(),
            "Template matches" => "模板命中".into(),
            "Path to nuclei-templates dir (optional; built-ins always run)" => {
                "nuclei-templates 目录路径(可选;内置模板始终运行)".into()
            }
            "Loads nuclei-format YAML templates and runs them against the target." => {
                "加载 nuclei 格式的 YAML 模板,逐个对目标运行。".into()
            }
            "Built-in templates always run; point the directory at the nuclei-templates repo for thousands more." => {
                "内置模板始终运行;把目录指向 nuclei-templates 仓库即可白嫖几千个模板。".into()
            }
            "Configure a target and start scanning" => "配置目标并开始扫描".into(),
            "No template matched" => "无模板命中".into(),
            // Session 会话处理页
            "Session handling" => "会话处理".into(),
            "Apply to scans" => "套用到扫描".into(),
            "Run login macro" => "运行登录宏".into(),
            "Running login macro…" => "运行登录宏中…".into(),
            "Running…" => "运行中…".into(),
            "Login macro (raw request)" => "登录宏(原始请求)".into(),
            "Capture & inject" => "捕获与注入".into(),
            "Capture Set-Cookie" => "捕获 Set-Cookie".into(),
            "Token regex (optional)" => "令牌正则(可选)".into(),
            "Inject token into header (optional)" => "把令牌注入请求头(可选)".into(),
            "Logged-out body marker (optional)" => "掉登录正文标记(可选)".into(),
            "Session active" => "会话有效".into(),
            "No session" => "无会话".into(),
            "Active session" => "活动会话".into(),
            "Macro status" => "宏响应状态".into(),
            "Scans auto re-login via the macro and inject the captured session (Cookie + token)." => {
                "扫描会自动跑登录宏重登,并把捕获的会话(Cookie + 令牌)注入每个请求。".into()
            }
            "e.g. csrf_token\" value=\"([^\"]+)\"" => "如 csrf_token\" value=\"([^\"]+)\"".into(),
            "e.g. session expired" => "如 session expired".into(),
            // 代理历史 HTTPQL 搜索框
            "Filter / HTTPQL: resp.status.gt:400 AND req.host.cont:api" => {
                "过滤 / HTTPQL:resp.status.gt:400 AND req.host.cont:api".into()
            }
            // 代理 → Site map 子页签
            "Site map" => "站点地图".into(),
            "No traffic captured yet" => "尚无抓到的流量".into(),
            "Select a node to list its requests" => "选中节点以列出其请求".into(),
            "requests" => "请求".into(),
            "Query in history" => "在历史中查询".into(),
            // JWT 攻击套件页
            "JWT attack toolkit" => "JWT 攻击套件".into(),
            "Decode any JWT and forge attack tokens (alg:none / weak HS256 / kid injection / brute force). Use only on authorized targets." => {
                "解码任意 JWT 并伪造攻击令牌(alg:none / 弱密钥 HS256 / kid 注入 / 弱密钥爆破)。仅对已授权目标使用。".into()
            }
            "Paste a JWT (header.payload.signature)…" => "粘贴 JWT(header.payload.signature)…".into(),
            "Token" => "令牌".into(),
            "Decoded" => "解码".into(),
            "Paste a JWT to decode" => "粘贴 JWT 以解码".into(),
            "Load payload" => "载入 payload".into(),
            "Loaded payload ·" => "已载入 payload ·".into(),
            "Forge" => "伪造".into(),
            "Payload (editable JSON)" => "Payload(可编辑 JSON)".into(),
            "HS256 secret" => "HS256 密钥".into(),
            "HS256 secret (sign / extra brute candidate)" => "HS256 密钥(签名 / 爆破额外候选)".into(),
            "kid (for kid injection)" => "kid(用于 kid 注入)".into(),
            "Sign HS256" => "HS256 签名".into(),
            "kid injection" => "kid 注入".into(),
            "Brute force secret" => "爆破弱密钥".into(),
            "Result token" => "结果令牌".into(),
            "Forged token appears here" => "伪造的令牌出现在这里".into(),
            "Forged alg:none token" => "已伪造 alg:none 令牌".into(),
            "Signed HS256 token" => "已签发 HS256 令牌".into(),
            "Forged kid-injection token" => "已伪造 kid 注入令牌".into(),
            "Enter a kid value first" => "请先填写 kid 值".into(),
            "Brute force only supports HS256" => "弱密钥爆破仅支持 HS256".into(),
            "Weak secret cracked:" => "爆破出弱密钥:".into(),
            "No weak secret found" => "未爆破出弱密钥".into(),
            "(empty secret)" => "(空密钥)".into(),
            "Header" => "头部".into(),
            "Signature (raw, not verified)" => "签名(原始,未验证)".into(),
            "unsigned / none — likely forgeable" => "无签名 / none —— 大概率可伪造".into(),
            "JWT extracted from request" => "已从请求提取 JWT".into(),
            "No JWT found in this request" => "该请求未发现 JWT".into(),
            // Compose 请求构造器页
            "Compose" => "构造".into(),
            "Response appears here" => "响应出现在这里".into(),
            "Build a request from scratch. Use {{var}} placeholders, defined in Environment on the right." => {
                "从零构造请求。用 {{var}} 占位符,变量在右侧「环境变量」里定义。".into()
            }
            "Build the request on the left, then Send" => "在左侧构造请求,然后发送".into(),
            "Environment" => "环境变量".into(),
            "No variables yet" => "暂无变量".into(),
            "Add" => "添加".into(),
            "name" => "名称".into(),
            "value" => "值".into(),
            "Collection" => "集合".into(),
            "Saved requests appear here" => "保存的请求出现在这里".into(),
            "Save" => "保存".into(),
            "Saved request" => "已保存请求".into(),
            "Request name to save" => "保存的请求命名".into(),
            // GraphQL 页
            "Query" => "查询".into(),
            "Variables (JSON)" => "变量(JSON)".into(),
            "Headers" => "请求头".into(),
            "Beautify" => "美化".into(),
            "Minify" => "压缩".into(),
            "Introspect" => "拉取 Schema".into(),
            "Introspecting…" => "拉取 Schema 中…".into(),
            "Schema" => "结构 Schema".into(),
            "Schema loaded ·" => "Schema 已加载 ·".into(),
            // Crawl → Audit 流水线(Spider 页)
            "Audit after crawl" => "爬完自动审计".into(),
            // 流量统计页(Stats)
            "Traffic stats" => "流量统计".into(),
            "Stats" => "统计".into(),
            "Aggregated over the current session's captured flows" => "对当前会话已抓到的流量做聚合".into(),
            "Response bytes" => "响应字节".into(),
            "By method" => "按方法".into(),
            "By status" => "按状态码".into(),
            "By type" => "按类型".into(),
            "Top hosts" => "主机 Top".into(),
            // 活动 WebSocket 改帧(Proxy → Options)
            "WebSocket frames" => "WebSocket 改帧".into(),
            "→ Server" => "→ 服务端".into(),
            "→ Client" => "→ 客户端".into(),
            "Find in frame…" => "在帧中查找…".into(),
            "Enter find text first" => "请先填写查找内容".into(),
            "No rules — rewrite live WebSocket text frames (e.g. tamper a chat / game message). Literal find → replace, per direction." => {
                "暂无规则 —— 改写实时 WebSocket 文本帧(如篡改聊天 / 游戏消息)。字面量 查找 → 替换,按方向。".into()
            }
            "Rewrite live WS text frames. Takes effect on next capture start." => {
                "改写实时 WS 文本帧。下次开始抓包时生效。".into()
            }
            "Send a query or run Introspect" => "发送查询,或点「拉取 Schema」".into(),
            "Invalid endpoint URL" => "端点 URL 非法".into(),
            "Imported from request" => "已从请求导入".into(),
            // 兜底:原样返回(URL / 协议名 / 数字等)
            _ => SharedString::from(en.to_owned()),
        }
    }
}
