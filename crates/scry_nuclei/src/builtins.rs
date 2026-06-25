//! 内置示例模板:零配置即可演示 nuclei 引擎(也作单测夹具)。
//!
//! 真正的威力来自加载社区仓库 [`projectdiscovery/nuclei-templates`](https://github.com/projectdiscovery/nuclei-templates)
//! 的几千个模板;这里仅内嵌少量高频「暴露 / 错误配置」类模板,保证装好即用、覆盖 word/regex/status/
//! binary/extractor 各形态。

use crate::template::{parse_template, Template};

/// 内置模板:`(id, YAML)`。
pub const BUILTIN_TEMPLATES: &[(&str, &str)] = &[
    (
        "scry-git-config",
        r#"
id: scry-git-config
info:
  name: Git Config Exposure
  author: scry
  severity: medium
  description: A .git/config file is publicly accessible, potentially exposing repository metadata.
  tags: config,git,exposure
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - '[core]'
          - 'repositoryformatversion ='
        condition: and
      - type: status
        status:
          - 200
"#,
    ),
    (
        "scry-dotenv",
        r#"
id: scry-dotenv
info:
  name: Environment File Exposure (.env)
  author: scry
  severity: high
  description: A .env file is publicly accessible, potentially exposing application secrets.
  tags: config,exposure,env
http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
    matchers-condition: and
    matchers:
      - type: regex
        part: body
        regex:
          - '(?m)^\s*[A-Z][A-Z0-9_]+\s*='
      - type: status
        status:
          - 200
    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - '(?m)^\s*([A-Z][A-Z0-9_]+)\s*='
"#,
    ),
    (
        "scry-phpinfo",
        r#"
id: scry-phpinfo
info:
  name: phpinfo() Exposure
  author: scry
  severity: low
  description: A phpinfo() page is publicly accessible, leaking environment details.
  tags: phpinfo,exposure,php
http:
  - method: GET
    path:
      - "{{BaseURL}}/phpinfo.php"
      - "{{BaseURL}}/info.php"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - 'PHP Version'
          - '<title>phpinfo()'
        condition: or
      - type: status
        status:
          - 200
    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - 'PHP Version ([0-9.]+)'
"#,
    ),
    (
        "scry-ds-store",
        r#"
id: scry-ds-store
info:
  name: .DS_Store File Exposure
  author: scry
  severity: info
  description: A macOS .DS_Store file is exposed; it can reveal the directory structure.
  tags: exposure,osx,listing
http:
  - method: GET
    path:
      - "{{BaseURL}}/.DS_Store"
    matchers-condition: and
    matchers:
      - type: binary
        binary:
          - '0000000142756431'
      - type: status
        status:
          - 200
"#,
    ),
    (
        "scry-swagger-api",
        r#"
id: scry-swagger-api
info:
  name: Swagger / OpenAPI Definition Exposure
  author: scry
  severity: info
  description: An API definition (Swagger/OpenAPI) is publicly accessible.
  tags: exposure,api,swagger
http:
  - method: GET
    path:
      - "{{BaseURL}}/swagger.json"
      - "{{BaseURL}}/openapi.json"
      - "{{BaseURL}}/v2/api-docs"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - '"swagger"'
          - '"openapi"'
        condition: or
      - type: status
        status:
          - 200
    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - '"(?:swagger|openapi)"\s*:\s*"([0-9.]+)"'
"#,
    ),
    (
        "scry-dir-listing",
        r#"
id: scry-dir-listing
info:
  name: Directory Listing Enabled
  author: scry
  severity: low
  description: The server returns an auto-generated directory index.
  tags: exposure,listing,misconfig
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - 'Index of /'
          - '<title>Directory listing for'
        condition: or
      - type: status
        status:
          - 200
"#,
    ),
];

/// 解析全部内置模板(忽略个别解析失败,理论上都应成功)。
pub fn load_builtins() -> Vec<Template> {
    BUILTIN_TEMPLATES
        .iter()
        .filter_map(|(_, y)| parse_template(y).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_builtins_parse() {
        let templates = load_builtins();
        assert_eq!(
            templates.len(),
            BUILTIN_TEMPLATES.len(),
            "某个内置模板解析失败"
        );
        for t in &templates {
            assert!(t.matcher_count() >= 1, "{} 无 matcher", t.id);
        }
    }
}
