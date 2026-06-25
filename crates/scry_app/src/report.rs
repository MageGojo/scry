//! 渗透报告生成:把各引擎的发现(扫描器 / 越权 / Nuclei / XSS / SQLi)聚合成统一清单,
//! 导出 **HTML + Markdown** 到 `~/.scry/exports/` 并在访达定位。纯数据 → 模板字符串,导出走后台线程。

use std::path::PathBuf;

use mage_ui::prelude::*;
use scry_scan::Severity;

use crate::logger::LogLevel;
use crate::state::ScryApp;

/// 报告里的一条统一发现项(把异构引擎结果归一)。
struct ReportItem {
    severity: Severity,
    source: &'static str,
    title: String,
    url: String,
    detail: String,
}

impl ScryApp {
    /// 收集所有引擎的发现,按严重度降序。
    fn collect_report_items(&self) -> Vec<ReportItem> {
        let zh = self.lang.is_zh();
        let mut v: Vec<ReportItem> = Vec::new();
        for f in &self.scan_findings {
            v.push(ReportItem {
                severity: f.severity,
                source: "Scanner",
                title: self.lang.t(f.title).to_string(),
                url: f.url.clone(),
                detail: f.detail.clone(),
            });
        }
        for f in &self.authz_findings {
            v.push(ReportItem {
                severity: f.severity,
                source: "Authz",
                title: self.lang.t(f.title).to_string(),
                url: f.url.clone(),
                detail: f.detail.clone(),
            });
        }
        for h in &self.nuclei_hits {
            v.push(ReportItem {
                severity: h.severity,
                source: "Nuclei",
                title: h.name.clone(),
                url: h.url.clone(),
                detail: format!("template: {}", h.template_id),
            });
        }
        for x in &self.xss_findings {
            if x.confirmed {
                v.push(ReportItem {
                    severity: Severity::High,
                    source: "XSS",
                    title: if zh { "确认 XSS".to_string() } else { "Confirmed XSS".to_string() },
                    url: x.point.clone(),
                    detail: x.payload.clone().unwrap_or_default(),
                });
            }
        }
        if self.sqli_report.injectable {
            v.push(ReportItem {
                severity: Severity::Critical,
                source: "SQLi",
                title: if zh { "SQL 注入".to_string() } else { "SQL injection".to_string() },
                url: String::new(),
                detail: if zh {
                    "确认存在 SQL 注入,详见 SQLi 页".to_string()
                } else {
                    "Confirmed SQL injection (see SQLi tab)".to_string()
                },
            });
        }
        v.sort_by_key(|it| std::cmp::Reverse(it.severity));
        v
    }

    /// 导出渗透报告(HTML + Markdown)到 `~/.scry/exports/` 并在访达定位。
    pub fn export_report_dialog(&mut self, cx: &mut Context<Self>) {
        let zh = self.lang.is_zh();
        let items = self.collect_report_items();
        if items.is_empty() {
            self.cert_msg = Some(if zh {
                "暂无可导出的发现(先跑扫描 / 越权 / SQLi / XSS / Nuclei)".to_string()
            } else {
                "No findings to export yet".to_string()
            });
            cx.notify();
            return;
        }
        let html = render_html(&items, zh);
        let md = render_markdown(&items, zh);
        let n = items.len();
        let bg = cx.background_executor().clone();
        cx.spawn(async move |this, cx| {
            let result = bg
                .spawn(async move {
                    write_report_blocking(&html, &md).map_err(|e| format!("{e}"))
                })
                .await;
            let _ = this.update(cx, |this, cx| {
                match result {
                    Ok(path) => {
                        let _ = std::process::Command::new("open").arg("-R").arg(&path).spawn();
                        this.push_log(
                            LogLevel::Success,
                            "report",
                            format!("已导出报告({n} 项)到 {}", path.display()),
                        );
                        this.cert_msg = Some(if this.lang.is_zh() {
                            format!("已导出报告:{n} 项发现")
                        } else {
                            format!("Report exported: {n} findings")
                        });
                    }
                    Err(e) => {
                        this.push_log(LogLevel::Error, "report", format!("报告导出失败:{e}"));
                        this.cert_msg = Some(e);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }
}

/// 写 HTML + Markdown 报告,返回 HTML 路径。阻塞,放后台线程调。
fn write_report_blocking(html: &str, md: &str) -> std::io::Result<PathBuf> {
    let dir = scry_ca::default_ca_dir().join("exports");
    std::fs::create_dir_all(&dir)?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let html_path = dir.join(format!("scry-report-{ts}.html"));
    std::fs::write(&html_path, html)?;
    let md_path = dir.join(format!("scry-report-{ts}.md"));
    std::fs::write(&md_path, md)?;
    Ok(html_path)
}

fn sev_label(s: Severity, zh: bool) -> &'static str {
    match (s, zh) {
        (Severity::Critical, true) => "严重",
        (Severity::High, true) => "高危",
        (Severity::Medium, true) => "中危",
        (Severity::Low, true) => "低危",
        (Severity::Info, true) => "信息",
        (Severity::Critical, false) => "Critical",
        (Severity::High, false) => "High",
        (Severity::Medium, false) => "Medium",
        (Severity::Low, false) => "Low",
        (Severity::Info, false) => "Info",
    }
}

fn sev_color(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "#b3122b",
        Severity::High => "#d9480f",
        Severity::Medium => "#b8860b",
        Severity::Low => "#1864ab",
        Severity::Info => "#5c6773",
    }
}

fn counts(items: &[ReportItem]) -> [usize; 5] {
    let mut c = [0usize; 5];
    for it in items {
        let i = match it.severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        };
        c[i] += 1;
    }
    c
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render_html(items: &[ReportItem], zh: bool) -> String {
    let c = counts(items);
    let lang_attr = if zh { "zh" } else { "en" };
    let title = if zh { "Scry 安全评估报告" } else { "Scry Security Report" };
    let gen = if zh { "由 Scry 生成" } else { "Generated by Scry" };
    let summary = if zh {
        format!(
            "严重 {} · 高危 {} · 中危 {} · 低危 {} · 信息 {} · 合计 {}",
            c[0], c[1], c[2], c[3], c[4], items.len()
        )
    } else {
        format!(
            "Critical {} · High {} · Medium {} · Low {} · Info {} · Total {}",
            c[0], c[1], c[2], c[3], c[4], items.len()
        )
    };
    let (h_sev, h_src, h_title, h_url, h_detail) = if zh {
        ("严重度", "来源", "问题", "URL", "证据")
    } else {
        ("Severity", "Source", "Issue", "URL", "Evidence")
    };
    let mut rows = String::new();
    for it in items {
        rows.push_str(&format!(
            "<tr><td><span class=\"sev\" style=\"background:{}\">{}</span></td><td>{}</td><td>{}</td><td class=\"url\">{}</td><td>{}</td></tr>\n",
            sev_color(it.severity),
            sev_label(it.severity, zh),
            esc(it.source),
            esc(&it.title),
            esc(&it.url),
            esc(&it.detail),
        ));
    }
    format!(
        "<!doctype html><html lang=\"{lang_attr}\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title>\
<style>\
body{{font:14px -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;margin:32px;color:#1a1a1a;background:#fafafa}}\
h1{{font-size:22px;margin:0 0 4px}}\
.meta{{color:#666;margin-bottom:8px}}\
.summary{{margin:12px 0 20px;font-weight:600}}\
table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.08)}}\
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #eee;vertical-align:top}}\
th{{background:#f3f4f6;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:#555}}\
.sev{{color:#fff;padding:2px 8px;border-radius:10px;font-size:12px;white-space:nowrap}}\
.url{{font-family:Menlo,monospace;font-size:12px;word-break:break-all;max-width:320px}}\
td:last-child{{font-size:13px;color:#333}}\
</style></head><body>\
<h1>{title}</h1>\
<div class=\"meta\">{gen}</div>\
<div class=\"summary\">{summary}</div>\
<table><thead><tr><th>{h_sev}</th><th>{h_src}</th><th>{h_title}</th><th>{h_url}</th><th>{h_detail}</th></tr></thead>\
<tbody>\n{rows}</tbody></table>\
</body></html>"
    )
}

fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn render_markdown(items: &[ReportItem], zh: bool) -> String {
    let c = counts(items);
    let mut s = String::new();
    s.push_str(if zh { "# Scry 安全评估报告\n\n" } else { "# Scry Security Report\n\n" });
    s.push_str(&if zh {
        format!(
            "**汇总**:严重 {} · 高危 {} · 中危 {} · 低危 {} · 信息 {} · 合计 {}\n\n",
            c[0], c[1], c[2], c[3], c[4], items.len()
        )
    } else {
        format!(
            "**Summary**: Critical {} · High {} · Medium {} · Low {} · Info {} · Total {}\n\n",
            c[0], c[1], c[2], c[3], c[4], items.len()
        )
    });
    if zh {
        s.push_str("| 严重度 | 来源 | 问题 | URL | 证据 |\n|---|---|---|---|---|\n");
    } else {
        s.push_str("| Severity | Source | Issue | URL | Evidence |\n|---|---|---|---|---|\n");
    }
    for it in items {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            sev_label(it.severity, zh),
            it.source,
            md_cell(&it.title),
            md_cell(&it.url),
            md_cell(&it.detail),
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(sev: Severity, src: &'static str, title: &str, url: &str, detail: &str) -> ReportItem {
        ReportItem {
            severity: sev,
            source: src,
            title: title.to_string(),
            url: url.to_string(),
            detail: detail.to_string(),
        }
    }

    #[test]
    fn counts_by_severity() {
        let items = vec![
            item(Severity::Critical, "SQLi", "a", "u", "d"),
            item(Severity::High, "XSS", "b", "u", "d"),
            item(Severity::High, "Scanner", "c", "u", "d"),
        ];
        assert_eq!(counts(&items), [1, 2, 0, 0, 0]);
    }

    #[test]
    fn html_escapes_and_includes_rows() {
        let items = vec![item(Severity::High, "Scanner", "XSS <b>", "https://x/?q=<i>", "a&b")];
        let html = render_html(&items, false);
        assert!(html.contains("Scry Security Report"));
        assert!(html.contains("&lt;b&gt;")); // 标题转义
        assert!(html.contains("a&amp;b")); // 证据转义
        assert!(!html.contains("<b>")); // 不应出现未转义标签
    }

    #[test]
    fn markdown_escapes_pipes() {
        let items = vec![item(Severity::Low, "Scanner", "a|b", "u", "c\nd")];
        let md = render_markdown(&items, false);
        assert!(md.contains("a\\|b"));
        assert!(md.contains("c d")); // 换行被替换为空格
        assert!(md.contains("| Severity | Source |"));
    }
}
