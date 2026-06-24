//! Scry 站点爬虫内核（对标 Burp Spider/Crawler）—— **纯函数 + 无 IO**,可独立单测。
//!
//! 职责拆成两块,刻意把「抓取(IO)」留给调用方(`scry_app::crawler` 的异步 runner 用
//! `scry_proxy::replay` 抓页),内核只管「**算什么该抓**」:
//! 1. [`extract_links`]:从一页 HTML 里抽出所有链接(`<a href>` / `<script src>` / `<img src>`
//!    / `<link href>` / `<iframe src>` / `<form action>` …),用 [`url`] crate 相对→绝对解引、
//!    去 fragment 归一化。
//! 2. [`Crawler`]:BFS 调度器——种子入队(深度 0),`next()` 取下一个待抓 URL(受**页数上限**约束),
//!    调用方抓回 HTML 后 `feed()` 解析其链接并把**同站 / 未越深 / 未见过**的新 URL 入队。
//!
//! 这样内核全程不碰网络,既能在毫秒级单测里验证调度正确性,又能在 UI 里被异步驱动。

use std::collections::{HashSet, VecDeque};
use url::Url;

/// 爬虫调度配置。
#[derive(Debug, Clone)]
pub struct CrawlConfig {
    /// BFS 最大深度:种子为深度 0,种子页上发现的链接为深度 1,以此类推;`> max_depth` 不入队。
    pub max_depth: usize,
    /// 最多**抓取**多少页(`next()` 返回的次数上限;队列本身可超出,只是不再被取出)。
    pub max_pages: usize,
    /// 是否仅限**同站**(种子的 host 集合);`false` = 跟随到任意外站。
    pub same_host_only: bool,
    /// 同站判定是否放宽到**子域**(如种子 `example.com` 时允许 `api.example.com`)。
    pub include_subdomains: bool,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            max_depth: 2,
            max_pages: 100,
            same_host_only: true,
            include_subdomains: true,
        }
    }
}

/// 队列中的一个待抓条目(URL + 其相对种子的 BFS 深度)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlItem {
    pub url: String,
    pub depth: usize,
}

/// BFS 站点爬虫调度器(无 IO):种子 → `next()` 取待抓 → 调用方抓页 → `feed()` 喂回 HTML。
#[derive(Debug)]
pub struct Crawler {
    cfg: CrawlConfig,
    /// BFS 前沿队列。
    queue: VecDeque<CrawlItem>,
    /// 已决策过的归一化 URL(已入队 **或** 已被范围/深度拒绝),用于去重、避免重复处理。
    seen: HashSet<String>,
    /// 种子的 host 集合,用于同站判定。
    scope: Vec<String>,
    /// 已通过 `next()` 取出(= 计划抓取)的页数。
    fetched: usize,
    /// 累计入队(被发现且接纳)的页数(含种子)。
    discovered: usize,
}

impl Crawler {
    /// 用配置 + 种子 URL 列表新建。非法 / 非 http(s) 的种子会被忽略;种子的 host 自动登记为同站范围。
    pub fn new(cfg: CrawlConfig, seeds: &[String]) -> Self {
        let mut c = Self {
            cfg,
            queue: VecDeque::new(),
            seen: HashSet::new(),
            scope: Vec::new(),
            fetched: 0,
            discovered: 0,
        };
        for s in seeds {
            let Ok(u) = Url::parse(s.trim()) else { continue };
            if !is_web(&u) {
                continue;
            }
            if let Some(h) = u.host_str() {
                let h = h.to_ascii_lowercase();
                if !c.scope.contains(&h) {
                    c.scope.push(h);
                }
            }
            let n = normalize(&u);
            if c.seen.insert(n.clone()) {
                c.queue.push_back(CrawlItem { url: n, depth: 0 });
                c.discovered += 1;
            }
        }
        c
    }

    /// 取下一个待抓 URL;队列空或已达页数上限返回 `None`。每次取出计一次「已抓」。
    ///
    /// 不实现 `Iterator`:取出后需调用方抓页并 [`feed`](Self::feed) 喂回 HTML 才会产生后续项,
    /// 是「外部驱动」的调度,与迭代器的自洽产出语义不同。
    pub fn next_target(&mut self) -> Option<CrawlItem> {
        if self.fetched >= self.cfg.max_pages {
            return None;
        }
        let item = self.queue.pop_front()?;
        self.fetched += 1;
        Some(item)
    }

    /// 喂回某页(`from_url` @ `from_depth`)抓到的 HTML:解析其链接,把**同站 / 未越深 / 未见过**
    /// 的新 URL 入队,返回本次**新入队**的 URL(供 UI 显示「发现了哪些」)。
    pub fn feed(&mut self, from_url: &str, from_depth: usize, html: &str) -> Vec<String> {
        let next_depth = from_depth + 1;
        if next_depth > self.cfg.max_depth {
            return Vec::new();
        }
        let mut added = Vec::new();
        // 链接来源 = HTML 属性(a/link/script/img/iframe/form)+ JS / 内联文本里的 URL 字符串。
        // 对标 Burp 扫 JS:很多站把路由 / API / 文章路径写在脚本里,光看 DOM 的 <a> 抓不全。
        let mut links = extract_links(from_url, html);
        for u in extract_urls_from_text(from_url, html) {
            if !links.contains(&u) {
                links.push(u);
            }
        }
        for link in links {
            if self.seen.contains(&link) {
                continue;
            }
            if self.cfg.same_host_only && !self.link_in_scope(&link) {
                // 越界:也记入 seen,避免后续重复判定同一外链。
                self.seen.insert(link);
                continue;
            }
            self.seen.insert(link.clone());
            self.queue
                .push_back(CrawlItem { url: link.clone(), depth: next_depth });
            self.discovered += 1;
            added.push(link);
        }
        added
    }

    /// **注入一个已发现的 URL**(不经 HTML 解析):把 sitemap / robots / 被动观测到的 URL 喂进 BFS 队列。
    /// 做 http(s) / 同站范围 / 去重 / 深度检查;真正新入队返回 `true`。
    pub fn enqueue(&mut self, url: &str, depth: usize) -> bool {
        if depth > self.cfg.max_depth {
            return false;
        }
        let Ok(u) = Url::parse(url.trim()) else {
            return false;
        };
        if !is_web(&u) {
            return false;
        }
        let n = normalize(&u);
        if self.seen.contains(&n) {
            return false;
        }
        if self.cfg.same_host_only && !self.link_in_scope(&n) {
            self.seen.insert(n);
            return false;
        }
        self.seen.insert(n.clone());
        self.queue.push_back(CrawlItem { url: n, depth });
        self.discovered += 1;
        true
    }

    /// 是否已无可抓(队列空 或 达页数上限)。
    pub fn is_done(&self) -> bool {
        self.queue.is_empty() || self.fetched >= self.cfg.max_pages
    }

    /// 已取出(计划抓取)的页数。
    pub fn fetched(&self) -> usize {
        self.fetched
    }

    /// 累计入队(被接纳)的页数。
    pub fn discovered(&self) -> usize {
        self.discovered
    }

    /// 当前队列中等待抓取的页数。
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// 同站范围(种子的 host 集合)。
    pub fn scope_hosts(&self) -> &[String] {
        &self.scope
    }

    /// 判断某绝对 URL 的 host 是否落在同站范围。
    fn link_in_scope(&self, link: &str) -> bool {
        match Url::parse(link).ok().and_then(|u| u.host_str().map(|s| s.to_ascii_lowercase())) {
            Some(h) => host_in_scope(&h, &self.scope, self.cfg.include_subdomains),
            None => false,
        }
    }
}

/// 从一页 HTML(`html`)里抽取所有链接,基于 `base`(该页 URL)把相对链接解引为绝对 URL。
///
/// - 扫描 `href` / `src` / `action` 属性值(覆盖 a/link/script/img/iframe/form …);
/// - 跳过 `javascript:` / `mailto:` / `tel:` / `data:` / `about:` 以及纯 `#fragment`;
/// - 仅保留 http / https;去掉 fragment 归一化;**结果按出现序去重**。
pub fn extract_links(base: &str, html: &str) -> Vec<String> {
    let Ok(base_url) = Url::parse(base) else {
        return Vec::new();
    };
    // 逐属性收集原始值。`to_ascii_lowercase` 不改字节长度 → lower 的下标与原文对齐,可从原文取值保留大小写。
    let lower = html.to_ascii_lowercase();
    let lb = lower.as_bytes();
    let ob = html.as_bytes();
    let mut raw = Vec::new();
    for attr in [&b"href"[..], b"src", b"action"] {
        collect_attr(lb, ob, attr, &mut raw);
    }

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for r in raw {
        let v = decode_entities(r.trim());
        if v.is_empty() {
            continue;
        }
        let low = v.to_ascii_lowercase();
        if v.starts_with('#')
            || low.starts_with("javascript:")
            || low.starts_with("mailto:")
            || low.starts_with("tel:")
            || low.starts_with("data:")
            || low.starts_with("about:")
            || low.starts_with("blob:")
        {
            continue;
        }
        if let Ok(abs) = base_url.join(&v) {
            if is_web(&abs) {
                let n = normalize(&abs);
                if seen.insert(n.clone()) {
                    out.push(n);
                }
            }
        }
    }
    out
}

/// 从任意文本(JS / 内联脚本 / JSON)里**启发式**提取 URL 与站内绝对路径(对标 Burp 扫 JS)。
/// 保守:只接受引号(`"` `'` 反引号)包裹、且为完整 http(s):// URL 或以单个 `/` 开头路径的候选;
/// 含空白 / 尖括号 / 大括号等的丢弃。误报由调用方的同站 + 去重过滤兜底。
pub fn extract_urls_from_text(base: &str, text: &str) -> Vec<String> {
    let Ok(base_url) = Url::parse(base) else {
        return Vec::new();
    };
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut i = 0;
    while i < n {
        let q = bytes[i];
        if q == b'"' || q == b'\'' || q == b'`' {
            let s = i + 1;
            let mut k = s;
            while k < n && bytes[k] != q && bytes[k] != b'\n' {
                k += 1;
            }
            if k > s && k <= n {
                consider_candidate(&base_url, &text[s..k.min(n)], &mut out, &mut seen);
            }
            i = k + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// 判定引号内候选是否像 URL / 站内路径,是则解引为绝对 URL 收集(供 [`extract_urls_from_text`])。
fn consider_candidate(base: &Url, cand: &str, out: &mut Vec<String>, seen: &mut HashSet<String>) {
    let c = cand.trim();
    let abs_http = c.starts_with("http://") || c.starts_with("https://");
    let site_path = c.starts_with('/') && !c.starts_with("//") && c.len() > 1;
    if !(abs_http || site_path) || c.len() > 2048 {
        return;
    }
    if c.chars().any(|ch| {
        ch.is_whitespace() || matches!(ch, '<' | '>' | '{' | '}' | '\\' | '"' | '\'' | '`')
    }) {
        return;
    }
    if let Ok(abs) = base.join(c) {
        if is_web(&abs) {
            let nrm = normalize(&abs);
            if seen.insert(nrm.clone()) {
                out.push(nrm);
            }
        }
    }
}

/// 解析 `sitemap.xml`(含 sitemap index):提取全部 `<loc>…</loc>`。纯函数。
/// 这是发现「未被任何页面链接的孤立页」的关键(用户的"博客页没加首页链接却被 Burp 抓到"即此类)。
pub fn parse_sitemap(xml: &str) -> Vec<String> {
    let lower = xml.to_ascii_lowercase();
    let lb = lower.as_bytes();
    let ob = xml.as_bytes();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut i = 0;
    while let Some(p) = find_sub(lb, b"<loc>", i) {
        let s = p + 5;
        let Some(e) = find_sub(lb, b"</loc>", s) else {
            break;
        };
        let raw = String::from_utf8_lossy(&ob[s..e]);
        let v = decode_entities(raw.trim());
        if (v.starts_with("http://") || v.starts_with("https://")) && seen.insert(v.clone()) {
            out.push(v);
        }
        i = e + 6;
    }
    out
}

/// `robots.txt` 解析结果:声明的 sitemap(绝对 URL)+ Allow/Disallow 的路径(相对,需用 base 拼)。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RobotsHints {
    pub sitemaps: Vec<String>,
    pub paths: Vec<String>,
}

/// 解析 `robots.txt`:取 `Sitemap:` 行(发现孤立页的金矿)+ `Allow:`/`Disallow:` 路径
///(去掉 `*`/`?`/`$` 通配后的前缀;这些常指向存在但未被首页链接的目录)。纯函数。
pub fn parse_robots(txt: &str) -> RobotsHints {
    let mut h = RobotsHints::default();
    for line in txt.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        if v.is_empty() {
            continue;
        }
        match k.as_str() {
            "sitemap" => {
                if (v.starts_with("http://") || v.starts_with("https://"))
                    && !h.sitemaps.contains(&v.to_string())
                {
                    h.sitemaps.push(v.to_string());
                }
            }
            "allow" | "disallow" => {
                let p = v.split(['*', '?', '$', ' ']).next().unwrap_or("").trim();
                if p.starts_with('/') && p.len() > 1 && !h.paths.contains(&p.to_string()) {
                    h.paths.push(p.to_string());
                }
            }
            _ => {}
        }
    }
    h
}

/// 在 `hay` 中从 `from` 起查子串 `needle` 的起始下标。
fn find_sub(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() {
        return None;
    }
    let m = needle.len();
    let mut i = from;
    while i + m <= hay.len() {
        if &hay[i..i + m] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// 扫描 `lower`(小写化的 HTML)里形如 `<attr> [空白] = [空白] <value>` 的属性,把 value 从原文 `orig`
/// 同位置取出追加到 `out`。要求 attr 前一个字符不是字母/数字/`-`/`_`/`:`,以排除 `data-href` 等误匹配。
fn collect_attr(lower: &[u8], orig: &[u8], attr: &[u8], out: &mut Vec<String>) {
    let n = lower.len();
    let m = attr.len();
    let mut i = 0;
    while i + m <= n {
        if &lower[i..i + m] == attr {
            let prev_ok = i == 0 || {
                let p = lower[i - 1];
                !(p.is_ascii_alphanumeric() || p == b'-' || p == b'_' || p == b':')
            };
            let mut j = i + m;
            while j < n && lower[j].is_ascii_whitespace() {
                j += 1;
            }
            if prev_ok && j < n && lower[j] == b'=' {
                j += 1;
                while j < n && lower[j].is_ascii_whitespace() {
                    j += 1;
                }
                if let Some(v) = read_value(orig, j) {
                    out.push(v);
                }
            }
            i += m;
        } else {
            i += 1;
        }
    }
}

/// 从 `bytes[start]` 读一个属性值:支持双引号 / 单引号包裹,或无引号(读到空白或 `>` 为止)。
fn read_value(bytes: &[u8], start: usize) -> Option<String> {
    if start >= bytes.len() {
        return None;
    }
    let q = bytes[start];
    if q == b'"' || q == b'\'' {
        let s = start + 1;
        let mut k = s;
        while k < bytes.len() && bytes[k] != q {
            k += 1;
        }
        Some(String::from_utf8_lossy(&bytes[s..k]).into_owned())
    } else {
        let s = start;
        let mut k = start;
        while k < bytes.len() && !bytes[k].is_ascii_whitespace() && bytes[k] != b'>' {
            k += 1;
        }
        if k > s {
            Some(String::from_utf8_lossy(&bytes[s..k]).into_owned())
        } else {
            None
        }
    }
}

/// 归一化:去掉 fragment(`#...`),其余交给 [`Url`] 的规范形式。
fn normalize(u: &Url) -> String {
    let mut u = u.clone();
    u.set_fragment(None);
    u.to_string()
}

/// 是否 http / https。
fn is_web(u: &Url) -> bool {
    matches!(u.scheme(), "http" | "https")
}

/// host 是否落在范围内:精确相等,或(放宽子域时)是某范围 host 的子域。
fn host_in_scope(host: &str, scope: &[String], include_subdomains: bool) -> bool {
    scope
        .iter()
        .any(|s| host == s || (include_subdomains && host.ends_with(&format!(".{s}"))))
}

/// 解 HTML 里常见于 URL 的实体(主要是 `&amp;`,顺带 `&#38;`)。其余实体原样保留。
fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&amp;", "&").replace("&#38;", "&").replace("&#x26;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_and_resolves_relative_and_absolute() {
        let html = r#"
            <a href="/about">about</a>
            <a href='sub/page.html'>rel</a>
            <a href="https://other.com/x">abs</a>
            <script src="//cdn.example.com/a.js"></script>
            <img src="/img/p.png">
            <link href="/style.css">
            <form action="/submit"></form>
        "#;
        let links = extract_links("https://example.com/dir/index.html", html);
        assert!(links.contains(&"https://example.com/about".to_string()));
        assert!(links.contains(&"https://example.com/dir/sub/page.html".to_string()));
        assert!(links.contains(&"https://other.com/x".to_string()));
        // 协议相对 //cdn... 继承 https
        assert!(links.contains(&"https://cdn.example.com/a.js".to_string()));
        assert!(links.contains(&"https://example.com/img/p.png".to_string()));
        assert!(links.contains(&"https://example.com/submit".to_string()));
    }

    #[test]
    fn skips_non_navigational_and_strips_fragment() {
        let html = r##"
            <a href="javascript:void(0)">x</a>
            <a href="mailto:a@b.com">x</a>
            <a href="tel:123">x</a>
            <a href="#top">x</a>
            <a href="/p#section">frag</a>
            <a href="data:text/plain,hi">x</a>
        "##;
        let links = extract_links("https://example.com/", html);
        assert_eq!(links, vec!["https://example.com/p".to_string()]);
    }

    #[test]
    fn unquoted_and_entity_decoded_values() {
        let html = r#"<a href=/a?x=1&amp;y=2>e</a> <img src=/u.png >"#;
        let links = extract_links("https://example.com/", html);
        assert!(links.contains(&"https://example.com/a?x=1&y=2".to_string()));
        assert!(links.contains(&"https://example.com/u.png".to_string()));
    }

    #[test]
    fn ignores_lookalike_attrs() {
        // data-href 不应被当作 href。
        let html = r#"<div data-href="/nope"></div><a href="/yes">y</a>"#;
        let links = extract_links("https://example.com/", html);
        assert_eq!(links, vec!["https://example.com/yes".to_string()]);
    }

    #[test]
    fn dedupes_within_page() {
        let html = r#"<a href="/a">1</a><a href="/a">2</a><a href="/a#x">3</a>"#;
        let links = extract_links("https://example.com/", html);
        assert_eq!(links, vec!["https://example.com/a".to_string()]);
    }

    #[test]
    fn host_scope_exact_and_subdomain() {
        let scope = vec!["example.com".to_string()];
        assert!(host_in_scope("example.com", &scope, false));
        assert!(!host_in_scope("api.example.com", &scope, false));
        assert!(host_in_scope("api.example.com", &scope, true));
        assert!(!host_in_scope("notexample.com", &scope, true));
        assert!(!host_in_scope("evil.com", &scope, true));
    }

    #[test]
    fn seeds_register_scope_and_enqueue() {
        let c = Crawler::new(
            CrawlConfig::default(),
            &["https://example.com/".to_string(), "not a url".to_string()],
        );
        assert_eq!(c.scope_hosts(), &["example.com".to_string()]);
        assert_eq!(c.queued(), 1);
        assert_eq!(c.discovered(), 1);
    }

    #[test]
    fn bfs_respects_depth_limit() {
        let cfg = CrawlConfig {
            max_depth: 1,
            ..Default::default()
        };
        let mut c = Crawler::new(cfg, &["https://example.com/".to_string()]);
        let seed = c.next_target().unwrap();
        assert_eq!(seed.depth, 0);
        // 深度 1 的链接应被接纳。
        let added = c.feed(&seed.url, seed.depth, r#"<a href="/a">a</a>"#);
        assert_eq!(added, vec!["https://example.com/a".to_string()]);
        let a = c.next_target().unwrap();
        assert_eq!(a.depth, 1);
        // 深度 2(> max_depth=1)的链接应被丢弃,不入队。
        let added2 = c.feed(&a.url, a.depth, r#"<a href="/b">b</a>"#);
        assert!(added2.is_empty());
        assert!(c.next_target().is_none());
    }

    #[test]
    fn max_pages_caps_fetches() {
        let cfg = CrawlConfig {
            max_depth: 5,
            max_pages: 2,
            ..Default::default()
        };
        let mut c = Crawler::new(cfg, &["https://example.com/".to_string()]);
        let s = c.next_target().unwrap();
        c.feed(&s.url, s.depth, r#"<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>"#);
        // 只能再取 1 个(共 2),即使队列里有 3 个。
        assert!(c.next_target().is_some());
        assert!(c.next_target().is_none());
        assert_eq!(c.fetched(), 2);
    }

    #[test]
    fn same_host_only_filters_external() {
        let cfg = CrawlConfig {
            same_host_only: true,
            include_subdomains: false,
            ..Default::default()
        };
        let mut c = Crawler::new(cfg, &["https://example.com/".to_string()]);
        let s = c.next_target().unwrap();
        let added = c.feed(
            &s.url,
            s.depth,
            r#"<a href="/in">in</a><a href="https://evil.com/out">out</a><a href="https://api.example.com/x">sub</a>"#,
        );
        assert_eq!(added, vec!["https://example.com/in".to_string()]);
    }

    #[test]
    fn same_host_only_subdomains_allowed() {
        let cfg = CrawlConfig {
            same_host_only: true,
            include_subdomains: true,
            ..Default::default()
        };
        let mut c = Crawler::new(cfg, &["https://example.com/".to_string()]);
        let s = c.next_target().unwrap();
        let added = c.feed(
            &s.url,
            s.depth,
            r#"<a href="https://api.example.com/x">sub</a><a href="https://evil.com/out">out</a>"#,
        );
        assert_eq!(added, vec!["https://api.example.com/x".to_string()]);
    }

    #[test]
    fn dedupes_across_feeds() {
        let mut c = Crawler::new(CrawlConfig::default(), &["https://example.com/".to_string()]);
        let s = c.next_target().unwrap();
        let a1 = c.feed(&s.url, s.depth, r#"<a href="/a">a</a>"#);
        assert_eq!(a1.len(), 1);
        let a = c.next_target().unwrap();
        // 再次发现 /a(已见过)+ 种子自身(已见过)→ 不重复入队。
        let a2 = c.feed(&a.url, a.depth, r#"<a href="/a">a</a><a href="/">home</a>"#);
        assert!(a2.is_empty());
    }

    #[test]
    fn done_when_queue_drained() {
        let mut c = Crawler::new(CrawlConfig::default(), &["https://example.com/".to_string()]);
        assert!(!c.is_done());
        let _ = c.next_target().unwrap();
        assert!(c.is_done());
    }

    #[test]
    fn enqueue_injects_orphan_url_with_scope_and_dedup() {
        let mut c = Crawler::new(CrawlConfig::default(), &["https://example.com/".to_string()]);
        // 孤立页(不在任何页的链接里,如 sitemap 才有的)经 enqueue 注入。
        assert!(c.enqueue("https://example.com/secret-blog", 1));
        // 重复不再入队。
        assert!(!c.enqueue("https://example.com/secret-blog", 1));
        // 外站被同站范围拒绝。
        assert!(!c.enqueue("https://evil.com/x", 1));
        // 超过最大深度被拒。
        assert!(!c.enqueue("https://example.com/deep", 99));
    }

    #[test]
    fn parse_sitemap_extracts_locs() {
        let xml = r#"<?xml version="1.0"?><urlset>
            <url><loc>https://example.com/a</loc></url>
            <url><loc>https://example.com/blog/hidden?x=1&amp;y=2</loc></url>
        </urlset>"#;
        let locs = parse_sitemap(xml);
        assert!(locs.contains(&"https://example.com/a".to_string()));
        assert!(locs.contains(&"https://example.com/blog/hidden?x=1&y=2".to_string()));
    }

    #[test]
    fn parse_robots_takes_sitemap_and_disallow_paths() {
        let txt = "User-agent: *\nDisallow: /admin/\nAllow: /public\nSitemap: https://example.com/sitemap.xml\n# c\nDisallow: /tmp/*.php\n";
        let h = parse_robots(txt);
        assert_eq!(h.sitemaps, vec!["https://example.com/sitemap.xml".to_string()]);
        assert!(h.paths.contains(&"/admin/".to_string()));
        assert!(h.paths.contains(&"/public".to_string()));
        assert!(h.paths.contains(&"/tmp/".to_string())); // 通配前缀
    }

    #[test]
    fn extract_urls_from_text_finds_js_paths() {
        let js = r#"const api='/api/v1/posts'; fetch("https://example.com/hidden/page"); var x="not a url"; let y='//cdn.x/a';"#;
        let urls = extract_urls_from_text("https://example.com/app.js", js);
        assert!(urls.contains(&"https://example.com/api/v1/posts".to_string()));
        assert!(urls.contains(&"https://example.com/hidden/page".to_string()));
        // 含空格的 "not a url" 不被采纳;协议相对 // 也保守跳过。
        assert!(!urls.iter().any(|u| u.contains("not")));
    }

    #[test]
    fn feed_also_extracts_links_from_inline_script() {
        let mut c = Crawler::new(CrawlConfig::default(), &["https://example.com/".to_string()]);
        let s = c.next_target().unwrap();
        // 页面没有 <a>,但内联脚本里有路由路径 → 也应被发现。
        let added = c.feed(
            &s.url,
            s.depth,
            r#"<html><script>var routes=["/blog/post-1","/about"];</script></html>"#,
        );
        assert!(added.contains(&"https://example.com/blog/post-1".to_string()));
        assert!(added.contains(&"https://example.com/about".to_string()));
    }
}
