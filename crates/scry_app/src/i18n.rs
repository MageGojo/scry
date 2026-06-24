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
            "Directory listing exposed" => "目录列表暴露".into(),
            "Reflected parameter in response" => "参数在响应中被反射".into(),
            "SQL injection (error-based)" => "SQL 注入(报错型)".into(),
            "Reflected XSS" => "反射型 XSS".into(),
            "Reflected value (non-HTML)" => "参数被反射(非 HTML 上下文)".into(),
            "Path traversal / LFI" => "路径穿越 / 本地文件包含".into(),
            "Unauthenticated access to protected resource" => "未认证即可访问受保护资源".into(),
            "Broken access control (privilege escalation)" => "越权访问(权限提升)".into(),
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
            // 兜底:原样返回(URL / 协议名 / 数字等)
            _ => SharedString::from(en.to_owned()),
        }
    }
}
