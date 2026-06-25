//! Param Miner:发现服务端「暗中处理」的隐藏查询参数(对标 Burp Param Miner 的反射检测路径)。
//!
//! 纯函数、可单测:生成探测(一批参数名各配唯一高熵金丝雀)→ 拼进 URL query → 由调用方
//! `scry_proxy::replay` 发包 → 在响应里找哪些金丝雀被反射(= 该隐藏参数被后端读取/回显)。
//! 反射检测低误报;长度/状态差异等更激进的判定留 UI/runner 兜底。

/// 内置常见隐藏参数字典(调试开关 / 功能位 / 回调 / 重定向 / 常见后端参数)。
pub const PARAM_WORDLIST: &[&str] = &[
    "debug", "test", "admin", "edit", "preview", "draft", "show", "hidden", "internal", "trace",
    "verbose", "dev", "beta", "staging", "feature", "callback", "jsonp", "redirect", "redirect_uri",
    "redirect_url", "url", "next", "return", "return_url", "returnurl", "continue", "dest",
    "destination", "id", "uid", "user", "user_id", "account", "page", "format", "output", "type",
    "mode", "view", "action", "cmd", "command", "file", "path", "lang", "locale", "country",
    "currency", "token", "key", "api_key", "access", "role", "is_admin", "isadmin", "superuser",
    "force", "override", "raw", "source", "include", "template", "theme", "skin", "filter", "sort",
    "order", "limit", "offset", "count", "fields", "expand", "embed", "status", "state", "env",
    "config", "settings", "flag", "enable", "disable",
];

/// 一个金丝雀探测:参数名 + 唯一高熵标记值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamProbe {
    pub name: String,
    pub canary: String,
}

/// 为一批参数名生成金丝雀(`name → 唯一 canary`)。canary 高熵、纯字母数字,响应里好定位、不易自然出现。
pub fn make_probes(names: &[&str], seed: u64) -> Vec<ParamProbe> {
    names
        .iter()
        .enumerate()
        .map(|(i, n)| ParamProbe {
            name: n.to_string(),
            canary: format!("zqpm{seed:x}p{i:x}"),
        })
        .collect()
}

/// 把一批探测拼进 URL 的 query(保留原 query),返回新的 `path?query`。
pub fn inject_query(path: &str, probes: &[ParamProbe]) -> String {
    if probes.is_empty() {
        return path.to_string();
    }
    let joined = probes
        .iter()
        .map(|p| format!("{}={}", p.name, p.canary))
        .collect::<Vec<_>>()
        .join("&");
    if let Some(idx) = path.find('?') {
        // 已有 query:追加(容忍结尾已是 ? 或 &)。
        let _ = idx;
        if path.ends_with('?') || path.ends_with('&') {
            format!("{path}{joined}")
        } else {
            format!("{path}&{joined}")
        }
    } else {
        format!("{path}?{joined}")
    }
}

/// 在响应文本里找哪些探测的金丝雀被反射(返回被反射的参数名,保序去重)。
///
/// 注意:若**全部**金丝雀都反射,通常是「整段 URL/query 被原样回显」而非逐个隐藏参数被处理 ——
/// 由调用方(runner)据此降权(见 `looks_like_url_echo`)。
pub fn reflected(resp_text: &str, probes: &[ParamProbe]) -> Vec<String> {
    let mut out = Vec::new();
    for p in probes {
        if resp_text.contains(&p.canary) && !out.contains(&p.name) {
            out.push(p.name.clone());
        }
    }
    out
}

/// 启发式:本批探测是否「整段回显」(反射数 == 探测数且探测≥2)——此时反射不代表隐藏参数,应忽略/降权。
pub fn looks_like_url_echo(reflected_count: usize, probe_count: usize) -> bool {
    probe_count >= 2 && reflected_count == probe_count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_have_unique_canaries() {
        let names = ["a", "b", "c"];
        let ps = make_probes(&names, 0x1234);
        let mut cs: Vec<&str> = ps.iter().map(|p| p.canary.as_str()).collect();
        cs.sort_unstable();
        cs.dedup();
        assert_eq!(cs.len(), 3, "金丝雀应各不相同");
        assert_eq!(ps[0].name, "a");
    }

    #[test]
    fn inject_query_with_and_without_existing() {
        let ps = make_probes(&["debug"], 1);
        let canary = ps[0].canary.clone();
        // 无 query
        let q1 = inject_query("/api", &ps);
        assert_eq!(q1, format!("/api?debug={canary}"));
        // 有 query
        let q2 = inject_query("/api?x=1", &ps);
        assert_eq!(q2, format!("/api?x=1&debug={canary}"));
        // 结尾是 ?
        let q3 = inject_query("/api?", &ps);
        assert_eq!(q3, format!("/api?debug={canary}"));
        // 空探测原样返回
        assert_eq!(inject_query("/api", &[]), "/api");
    }

    #[test]
    fn reflected_detects_only_echoed_canaries() {
        let ps = make_probes(&["debug", "admin", "secret"], 7);
        // 响应只回显 admin 的金丝雀。
        let body = format!("<html>value={} ok</html>", ps[1].canary);
        let r = reflected(&body, &ps);
        assert_eq!(r, vec!["admin".to_string()]);
    }

    #[test]
    fn url_echo_heuristic() {
        assert!(looks_like_url_echo(3, 3));
        assert!(!looks_like_url_echo(1, 3));
        assert!(!looks_like_url_echo(1, 1)); // 单参数不当作整段回显
    }

    #[test]
    fn wordlist_not_empty_and_chunkable() {
        assert!(!PARAM_WORDLIST.is_empty());
        // runner 用 std 的 slice::chunks 分批,无需自造。
        let first = PARAM_WORDLIST.chunks(20).next().unwrap();
        assert!(first.len() <= 20);
    }
}
