//! Scry 解码层 —— **展示用**:按 `Content-Encoding` 把响应体解压回明文。
//!
//! 设计前提(见 `docs/设计.md`):落盘永远存**原始字节**(可能 gzip / br / 二进制),守 save-first;
//! 解压只在**展示层**按需进行。本 crate 是一组**纯函数 + 单测**,不碰 IO、不碰存储,
//! 供 `scry_app`(详情区)与分析逻辑复用。
//!
//! 支持的 `Content-Encoding`:`gzip` / `x-gzip`、`deflate`(zlib 或裸 deflate 自适应)、`br`(brotli)、
//! `identity`;允许逗号分隔的多层编码(按应用顺序的逆序解开)。任何一层解码失败都**保守退回**原始字节,
//! 保证展示不崩。

use std::io::Read;

/// 一个 HTTP 头(name, value)—— 与 `scry_core::Header` 同构,但本 crate 不依赖它以保持轻量。
pub type Header = (String, String);

/// 单层解压结果的上限(防超大 / 解压炸弹拖垮展示),默认 64 MiB。
pub const MAX_DECODED: usize = 64 * 1024 * 1024;

/// 大小写不敏感地取某个头的值。
pub fn header_get<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// 取 `Content-Encoding`(原样字符串,可能是逗号分隔的多层)。
pub fn content_encoding(headers: &[Header]) -> Option<&str> {
    header_get(headers, "content-encoding")
}

/// 按 `Content-Encoding` 把 `body` 解压成明文字节。
///
/// 无编码 / `identity` / 未知编码 / 解码失败 → 原样返回(克隆)。多层编码按逆序解开。
pub fn decode_body(headers: &[Header], body: &[u8]) -> Vec<u8> {
    let Some(enc) = content_encoding(headers) else {
        return body.to_vec();
    };
    decode_with_encoding(enc, body)
}

/// 按给定的 `Content-Encoding` 字符串解压 `body`。
pub fn decode_with_encoding(encoding: &str, body: &[u8]) -> Vec<u8> {
    // "gzip, br" 表示先 gzip 再 br;解码要逆序(先 br 后 gzip)。
    let layers: Vec<&str> = encoding
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    let mut data = body.to_vec();
    for layer in layers.into_iter().rev() {
        match decode_one(layer, &data) {
            Some(decoded) => data = decoded,
            // 该层无法解(未知编码 / 失败)→ 保守停在当前层,返回已解到的内容。
            None => break,
        }
    }
    data
}

/// 解一层编码;`None` 表示「未知编码」或「解码失败」(由调用方决定保守退回)。
fn decode_one(encoding: &str, body: &[u8]) -> Option<Vec<u8>> {
    match encoding.to_ascii_lowercase().as_str() {
        "identity" | "" => Some(body.to_vec()),
        "gzip" | "x-gzip" => inflate_gzip(body).ok(),
        "deflate" => inflate_deflate(body).ok(),
        "br" => inflate_brotli(body).ok(),
        _ => None,
    }
}

fn read_capped<R: Read>(mut r: R) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    // 限制总量,防解压炸弹。
    r.by_ref()
        .take(MAX_DECODED as u64 + 1)
        .read_to_end(&mut out)?;
    if out.len() > MAX_DECODED {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "解压结果超过上限",
        ));
    }
    Ok(out)
}

fn inflate_gzip(body: &[u8]) -> std::io::Result<Vec<u8>> {
    read_capped(flate2::read::GzDecoder::new(body))
}

/// HTTP 的 `deflate` 历史上含义不一:优先按 zlib(带头)解,失败再按裸 deflate 解。
fn inflate_deflate(body: &[u8]) -> std::io::Result<Vec<u8>> {
    if let Ok(v) = read_capped(flate2::read::ZlibDecoder::new(body)) {
        return Ok(v);
    }
    read_capped(flate2::read::DeflateDecoder::new(body))
}

fn inflate_brotli(body: &[u8]) -> std::io::Result<Vec<u8>> {
    // 4096 = 内部读缓冲大小。
    read_capped(brotli::Decompressor::new(body, 4096))
}

/// 把响应体解码成可展示文本:先按 `Content-Encoding` 解压,再按 `Content-Type` 的 `charset`
/// 解码(GBK / Big5 / Shift_JIS… → UTF-8);未声明 charset 时按 UTF-8 宽松解码。
pub fn body_text(headers: &[Header], body: &[u8]) -> String {
    let decoded = decode_body(headers, body);
    let label = content_type(headers).and_then(charset_from_content_type);
    decode_text(&decoded, label.as_deref())
}

/// 取 `Content-Type` 原值。
pub fn content_type(headers: &[Header]) -> Option<&str> {
    header_get(headers, "content-type")
}

/// 从 `Content-Type` 里抽出 `charset=` 标签(小写、去引号);大小写不敏感。
pub fn charset_from_content_type(ct: &str) -> Option<String> {
    for part in ct.split(';').skip(1) {
        let lower = part.trim().to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("charset=") {
            let v = rest.trim().trim_matches('"').trim_matches('\'');
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// 按字符集标签把字节解成字符串;标签未知 / 为空时退回 UTF-8(宽松)。
pub fn decode_text(bytes: &[u8], charset_label: Option<&str>) -> String {
    if let Some(label) = charset_label {
        if let Some(enc) = encoding_rs::Encoding::for_label(label.as_bytes()) {
            let (cow, _, _) = enc.decode(bytes);
            return cow.into_owned();
        }
    }
    String::from_utf8_lossy(bytes).into_owned()
}

/// 若(解压后的)body 是合法 JSON,返回**美化缩进**后的字符串;否则 `None`。
pub fn pretty_json(headers: &[Header], body: &[u8]) -> Option<String> {
    let decoded = decode_body(headers, body);
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    serde_json::to_string_pretty(&value).ok()
}

// ── 展示总入口(去 chunk → 解压 → charset / JSON 美化)──────────────
//
// 落盘的 body 形态不一:MITM 解密路径已去 chunked 框架(但可能仍 gzip);内核被动抓包 /
// 明文代理路径可能**保留 chunked 框架**。展示前先按 `Transfer-Encoding: chunked` 去框架,
// 再交给既有的解压 + 字符集逻辑。去框架失败一律保守退回原字节,保证不崩。

/// 头里是否声明 `Transfer-Encoding: chunked`。
pub fn is_chunked(headers: &[Header]) -> bool {
    header_get(headers, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
}

/// 解 chunked 传输编码的框架,返回拼接后的 body。框架不合法 → `None`(调用方保守退回)。
pub fn dechunk(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        // chunk-size 行:十六进制大小(可带 `;ext`),以 CRLF 结尾。
        let rel = find(&body[i..], b"\r\n")?;
        let line_end = i + rel;
        let size_line = std::str::from_utf8(&body[i..line_end]).ok()?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        if size_hex.is_empty() {
            return None;
        }
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        let data_start = line_end + 2;
        if size == 0 {
            // 末块:成功结束(忽略可能的 trailer)。
            return Some(out);
        }
        let data_end = data_start.checked_add(size)?;
        if data_end > body.len() {
            return None; // 数据不全
        }
        out.extend_from_slice(&body[data_start..data_end]);
        // 块数据后必须跟 CRLF。
        if body.get(data_end..data_end + 2) != Some(b"\r\n") {
            return None;
        }
        i = data_end + 2;
        // 防御:跑飞。
        if out.len() > MAX_DECODED {
            return None;
        }
    }
}

/// 先按需去 chunk,得到「可解压」的原始 body。
fn unframe(headers: &[Header], body: &[u8]) -> Vec<u8> {
    if is_chunked(headers) {
        if let Some(v) = dechunk(body) {
            return v;
        }
    }
    body.to_vec()
}

/// **展示总入口**:去 chunk → 按 `Content-Encoding` 解压 → 按 `charset` 解成 UTF-8 文本。
pub fn display_text(headers: &[Header], body: &[u8]) -> String {
    let unframed = unframe(headers, body);
    let decompressed = decode_body(headers, &unframed);
    let label = content_type(headers).and_then(charset_from_content_type);
    decode_text(&decompressed, label.as_deref())
}

/// **展示总入口**:去 chunk → 解压后若是合法 JSON,返回美化缩进文本;否则 `None`。
pub fn display_pretty_json(headers: &[Header], body: &[u8]) -> Option<String> {
    let unframed = unframe(headers, body);
    let decompressed = decode_body(headers, &unframed);
    let value: serde_json::Value = serde_json::from_slice(&decompressed).ok()?;
    serde_json::to_string_pretty(&value).ok()
}

/// 在 `hay` 中找子序列 `needle` 的起始位置。
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// 响应体大类(给 UI 着色 / 决定是否美化 / 是否当文本展示)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    Json,
    Html,
    Xml,
    JavaScript,
    Css,
    /// 表单编码 `application/x-www-form-urlencoded`。
    Form,
    /// 其它纯文本(`text/plain` 等)。
    Text,
    Image,
    Audio,
    Video,
    Font,
    Wasm,
    /// 二进制 / 未知。
    Binary,
}

impl ContentKind {
    /// 是否适合当**文本**展示(可读)。
    pub fn is_textual(self) -> bool {
        matches!(
            self,
            ContentKind::Json
                | ContentKind::Html
                | ContentKind::Xml
                | ContentKind::JavaScript
                | ContentKind::Css
                | ContentKind::Form
                | ContentKind::Text
        )
    }
}

/// 按 `Content-Type` 把响应体归类。
pub fn content_kind(headers: &[Header]) -> ContentKind {
    let ct = content_type(headers).unwrap_or("");
    // 取 `;` 前的 MIME 主体并小写。
    let mime = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();

    // 先按后缀 / 关键字识别结构化文本(覆盖 application/xxx+json、+xml 等)。
    if mime.contains("json") {
        return ContentKind::Json;
    }
    if mime.contains("xml") {
        return ContentKind::Xml;
    }
    if mime == "text/html" || mime == "application/xhtml+xml" {
        return ContentKind::Html;
    }
    if mime.contains("javascript") || mime == "application/ecmascript" || mime == "text/ecmascript"
    {
        return ContentKind::JavaScript;
    }
    if mime == "text/css" {
        return ContentKind::Css;
    }
    if mime == "application/x-www-form-urlencoded" {
        return ContentKind::Form;
    }
    if mime == "application/wasm" {
        return ContentKind::Wasm;
    }

    match mime.split_once('/').map(|(t, _)| t) {
        Some("text") => ContentKind::Text,
        Some("image") => ContentKind::Image,
        Some("audio") => ContentKind::Audio,
        Some("video") => ContentKind::Video,
        Some("font") => ContentKind::Font,
        _ => ContentKind::Binary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn brotli_c(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            w.write_all(data).unwrap();
        }
        out
    }

    fn h(enc: &str) -> Vec<Header> {
        vec![("Content-Encoding".into(), enc.into())]
    }

    #[test]
    fn gzip_roundtrip() {
        let plain = b"hello scry gzip world";
        assert_eq!(decode_body(&h("gzip"), &gzip(plain)), plain);
    }

    #[test]
    fn deflate_zlib_roundtrip() {
        let plain = b"deflate via zlib header";
        assert_eq!(decode_body(&h("deflate"), &zlib(plain)), plain);
    }

    #[test]
    fn brotli_roundtrip() {
        let plain = b"brotli compressed payload";
        assert_eq!(decode_body(&h("br"), &brotli_c(plain)), plain);
    }

    #[test]
    fn no_encoding_is_passthrough() {
        let raw = b"plain body";
        assert_eq!(decode_body(&[], raw), raw);
        assert_eq!(decode_body(&h("identity"), raw), raw);
    }

    #[test]
    fn unknown_encoding_is_passthrough() {
        let raw = b"weird";
        assert_eq!(decode_body(&h("zstd-not-supported"), raw), raw);
    }

    #[test]
    fn layered_gzip_then_br_decodes_in_reverse() {
        let plain = b"layered encodings";
        // 先 gzip 再 br(Content-Encoding: gzip, br)
        let body = brotli_c(&gzip(plain));
        assert_eq!(decode_body(&h("gzip, br"), &body), plain);
    }

    #[test]
    fn body_text_decodes_then_utf8() {
        let plain = "你好,Scry".as_bytes();
        assert_eq!(body_text(&h("gzip"), &gzip(plain)), "你好,Scry");
    }

    #[test]
    fn body_text_handles_gbk_charset() {
        // 把「你好」编成 GBK 字节,再声明 charset=gbk → 应解回「你好」。
        let (gbk_bytes, _, had_err) = encoding_rs::GBK.encode("你好");
        assert!(!had_err);
        let headers = vec![(
            "Content-Type".to_string(),
            "text/html; charset=gbk".to_string(),
        )];
        assert_eq!(body_text(&headers, &gbk_bytes), "你好");
    }

    #[test]
    fn body_text_gbk_with_gzip_layered() {
        // 先 GBK 编码再 gzip 压缩,同时声明两头:Content-Encoding: gzip + charset=gb2312。
        let (gbk_bytes, _, _) = encoding_rs::GBK.encode("中文测试");
        let headers = vec![
            ("Content-Encoding".to_string(), "gzip".to_string()),
            (
                "Content-Type".to_string(),
                "application/json; charset=gb2312".to_string(),
            ),
        ];
        assert_eq!(body_text(&headers, &gzip(&gbk_bytes)), "中文测试");
    }

    #[test]
    fn charset_parsing() {
        assert_eq!(
            charset_from_content_type("text/html; charset=UTF-8"),
            Some("utf-8".to_string())
        );
        assert_eq!(
            charset_from_content_type("text/html; charset=\"GBK\""),
            Some("gbk".to_string())
        );
        assert_eq!(charset_from_content_type("application/json"), None);
    }

    #[test]
    fn content_kind_classification() {
        let kind = |ct: &str| content_kind(&[("Content-Type".into(), ct.into())]);
        assert_eq!(kind("application/json; charset=utf-8"), ContentKind::Json);
        assert_eq!(kind("application/vnd.api+json"), ContentKind::Json);
        assert_eq!(kind("text/html"), ContentKind::Html);
        assert_eq!(kind("application/xml"), ContentKind::Xml);
        assert_eq!(kind("text/javascript"), ContentKind::JavaScript);
        assert_eq!(kind("application/x-www-form-urlencoded"), ContentKind::Form);
        assert_eq!(kind("image/png"), ContentKind::Image);
        assert_eq!(kind("application/octet-stream"), ContentKind::Binary);
        assert_eq!(content_kind(&[]), ContentKind::Binary);

        assert!(ContentKind::Json.is_textual());
        assert!(!ContentKind::Image.is_textual());
    }

    #[test]
    fn pretty_json_after_decompress() {
        let json = br#"{"b":2,"a":1}"#;
        let out = pretty_json(&h("gzip"), &gzip(json)).unwrap();
        assert!(out.contains("\n")); // 已缩进
        assert!(out.contains("\"a\": 1"));
    }

    #[test]
    fn pretty_json_none_for_non_json() {
        assert!(pretty_json(&[], b"<html>not json</html>").is_none());
    }

    #[test]
    fn dechunk_basic() {
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(dechunk(body).as_deref(), Some(&b"Wikipedia"[..]));
    }

    #[test]
    fn dechunk_rejects_non_chunked() {
        // 普通文本不是合法 chunked → None(调用方退回原文)。
        assert!(dechunk(b"just plain text without crlf").is_none());
    }

    #[test]
    fn display_text_dechunks_then_decompresses() {
        // 先 gzip 压缩明文,再包成单个 chunk;声明 TE chunked + CE gzip。
        let plain = b"hello chunked gzip";
        let gz = gzip(plain);
        let mut framed = format!("{:x}\r\n", gz.len()).into_bytes();
        framed.extend_from_slice(&gz);
        framed.extend_from_slice(b"\r\n0\r\n\r\n");
        let headers = vec![
            ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ("Content-Encoding".to_string(), "gzip".to_string()),
        ];
        assert_eq!(display_text(&headers, &framed), "hello chunked gzip");
    }

    #[test]
    fn display_text_passthrough_when_already_unframed() {
        // MITM 已去框架的 body(纯文本)即使头里仍写 chunked,dechunk 失败也能安全退回。
        let headers = vec![("Transfer-Encoding".to_string(), "chunked".to_string())];
        assert_eq!(display_text(&headers, b"already plain"), "already plain");
    }

    #[test]
    fn display_pretty_json_after_dechunk() {
        let json = br#"{"b":2,"a":1}"#;
        let mut framed = format!("{:x}\r\n", json.len()).into_bytes();
        framed.extend_from_slice(json);
        framed.extend_from_slice(b"\r\n0\r\n\r\n");
        let headers = vec![("Transfer-Encoding".to_string(), "chunked".to_string())];
        let out = display_pretty_json(&headers, &framed).unwrap();
        assert!(out.contains("\"a\": 1"));
    }
}
