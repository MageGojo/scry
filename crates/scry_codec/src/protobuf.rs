//! 无 schema 的 Protobuf / gRPC 线格式解码器(对标 Reqable 的 protobuf 解析)。
//!
//! 没有 `.proto` 时,protobuf 字节仍可按 [wire format](https://protobuf.dev/programming-guides/encoding/)
//! 解析出「字段号 + wire 类型 + 值」的树:varint / 64-bit / length-delimited / 32-bit 四类。
//! length-delimited 用启发式递归当嵌套 message,失败回退按 UTF-8 字符串 / 原始字节(hex)展示。
//!
//! 纯函数、零依赖、可单测。`decode_to_text` 解析失败(非合法 protobuf)返回 `None`。

/// 解析后的一个字段。
#[derive(Debug, Clone, PartialEq)]
enum Field {
    Varint(u64, u64),
    Fixed64(u64, u64),
    Fixed32(u64, u32),
    Len(u64, Vec<u8>),
}

/// 递归深度上限(防恶意构造的深嵌套)。
const MAX_DEPTH: usize = 32;

/// 读一个 LEB128 varint,返回 `(值, 消耗字节数)`;非法 / 截断返回 `None`。
fn read_varint(b: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in b.iter().enumerate() {
        if shift >= 64 {
            return None; // 超过 10 字节 → 非法
        }
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None // 截断:最后一字节仍有续位
}

/// 把一段字节解析为一组 protobuf 字段;任何不一致(越界 / 非法 wire 类型 / 字段号 0)返回 `None`。
fn parse_message(bytes: &[u8]) -> Option<Vec<Field>> {
    let mut fields = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let (tag, adv) = read_varint(&bytes[i..])?;
        i += adv;
        let field_no = tag >> 3;
        let wire = (tag & 0x7) as u8;
        // 字段号合法范围 1..=536870911;0 非法。
        if field_no == 0 || field_no > 536_870_911 {
            return None;
        }
        match wire {
            0 => {
                let (v, adv) = read_varint(&bytes[i..])?;
                i += adv;
                fields.push(Field::Varint(field_no, v));
            }
            1 => {
                if i + 8 > bytes.len() {
                    return None;
                }
                let mut a = [0u8; 8];
                a.copy_from_slice(&bytes[i..i + 8]);
                i += 8;
                fields.push(Field::Fixed64(field_no, u64::from_le_bytes(a)));
            }
            2 => {
                let (len, adv) = read_varint(&bytes[i..])?;
                i += adv;
                let len = len as usize;
                if i + len > bytes.len() {
                    return None;
                }
                fields.push(Field::Len(field_no, bytes[i..i + len].to_vec()));
                i += len;
            }
            5 => {
                if i + 4 > bytes.len() {
                    return None;
                }
                let mut a = [0u8; 4];
                a.copy_from_slice(&bytes[i..i + 4]);
                i += 4;
                fields.push(Field::Fixed32(field_no, u32::from_le_bytes(a)));
            }
            // 3/4 = 已废弃的 group(start/end),其它 = 非法 → 整体判非 protobuf。
            _ => return None,
        }
    }
    Some(fields)
}

/// 字节是否「像」可打印文本(用于 length-delimited 值在「嵌套 message」与「字符串」间抉择)。
fn looks_like_text(b: &[u8]) -> bool {
    if b.is_empty() {
        return false;
    }
    let s = match std::str::from_utf8(b) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // 全部为可打印字符或常见空白即视为文本。
    s.chars()
        .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
}

fn indent_str(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn render_fields(fields: &[Field], depth: usize, out: &mut String) {
    for f in fields {
        indent_str(out, depth);
        match f {
            Field::Varint(n, v) => {
                // 同时给出有符号 zigzag 解读(sint32/64 常见)。
                let zigzag = ((v >> 1) as i64) ^ -((v & 1) as i64);
                out.push_str(&format!("field {n} (varint): {v}"));
                if zigzag != *v as i64 {
                    out.push_str(&format!("  (zigzag {zigzag})"));
                }
                out.push('\n');
            }
            Field::Fixed64(n, v) => {
                let d = f64::from_bits(*v);
                out.push_str(&format!("field {n} (64-bit): {v}  (double {d})\n"));
            }
            Field::Fixed32(n, v) => {
                let fl = f32::from_bits(*v);
                out.push_str(&format!("field {n} (32-bit): {v}  (float {fl})\n"));
            }
            Field::Len(n, data) => {
                // 递归尝试嵌套 message(非空 + 能完整解析 + 至少一个字段)。
                let nested = if depth + 1 < MAX_DEPTH && !data.is_empty() {
                    parse_message(data).filter(|fs| !fs.is_empty())
                } else {
                    None
                };
                match nested {
                    Some(fs) if !looks_like_text(data) || all_nested(&fs) => {
                        out.push_str(&format!("field {n} (message, {} bytes):\n", data.len()));
                        render_fields(&fs, depth + 1, out);
                    }
                    _ if looks_like_text(data) => {
                        let s = String::from_utf8_lossy(data);
                        out.push_str(&format!("field {n} (string): {s:?}\n"));
                    }
                    _ => {
                        out.push_str(&format!(
                            "field {n} (bytes, {}): {}\n",
                            data.len(),
                            hex_preview(data)
                        ));
                    }
                }
            }
        }
    }
}

/// 嵌套字段是否「足够像」一个真 message(用于在 message vs 字符串间打破平局:
/// 若所有子字段都是嵌套 message / 合理结构,则倾向 message)。这里用简单判据:含非字符串字段。
fn all_nested(fields: &[Field]) -> bool {
    fields
        .iter()
        .any(|f| !matches!(f, Field::Len(_, d) if looks_like_text(d)))
}

/// 十六进制预览(最多 32 字节,超出省略)。
fn hex_preview(b: &[u8]) -> String {
    let mut s = String::new();
    for (i, byte) in b.iter().take(32).enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{byte:02x}"));
    }
    if b.len() > 32 {
        s.push_str(" …");
    }
    s
}

/// 解析 protobuf 字节为可读文本树;非合法 protobuf(空 / 解析失败 / 无字段)返回 `None`。
pub fn decode_to_text(bytes: &[u8]) -> Option<String> {
    let fields = parse_message(bytes)?;
    if fields.is_empty() {
        return None;
    }
    let mut out = String::new();
    render_fields(&fields, 0, &mut out);
    Some(out)
}

/// 解析 gRPC 帧(`application/grpc`):可含多个 `[1 字节压缩标志][4 字节大端长度][message]`。
///
/// 压缩标志为 1(gzip 等)时无法在此解压(交由调用方先解压);返回各帧的 protobuf 树。
pub fn decode_grpc_to_text(bytes: &[u8]) -> Option<String> {
    let mut out = String::new();
    let mut i = 0usize;
    let mut frame = 0;
    while i + 5 <= bytes.len() {
        let compressed = bytes[i];
        let len = u32::from_be_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]) as usize;
        i += 5;
        if i + len > bytes.len() {
            return None;
        }
        let msg = &bytes[i..i + len];
        i += len;
        frame += 1;
        out.push_str(&format!("─ gRPC frame #{frame} ({len} bytes"));
        if compressed != 0 {
            out.push_str(", compressed");
        }
        out.push_str(") ─\n");
        if compressed != 0 {
            out.push_str("(compressed payload — decompress first)\n");
        } else if let Some(tree) = decode_to_text(msg) {
            out.push_str(&tree);
        } else {
            out.push_str(&format!("{}\n", hex_preview(msg)));
        }
    }
    if frame == 0 || i != bytes.len() {
        return None;
    }
    Some(out)
}

/// 把 Decoder 页的文本输入(hex / base64 / 原始)当作 protobuf 字节解码。
///
/// 自动识别:全 hex 且偶数长度 → hex;否则尝试 base64;再否则按 UTF-8 字节。
pub fn decode_text_input(input: &str) -> Result<String, String> {
    let trimmed: String = input.split_whitespace().collect();
    let bytes = if !trimmed.is_empty()
        && trimmed.len().is_multiple_of(2)
        && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
    {
        hex_to_bytes(&trimmed)
    } else if let Some(b) = base64_to_bytes(&trimmed) {
        b
    } else {
        input.as_bytes().to_vec()
    };
    decode_to_text(&bytes).ok_or_else(|| "不是有效的 Protobuf 字节(可粘贴 hex / base64)".to_string())
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// 宽松标准 base64 解码(忽略空白 / 填充);非法返回 `None`。
fn base64_to_bytes(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }
    let mut buf = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::new();
    let mut any = false;
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = val(c)?;
        any = true;
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    if any {
        Some(out)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 手工编码一条 protobuf:field1 varint=150, field2 string="testing"。
    /// 来自官方文档示例(field1=150 → 08 96 01;field2="testing" → 12 07 74 65 73 74 69 6e 67)。
    #[test]
    fn decodes_canonical_example() {
        let bytes = [
            0x08, 0x96, 0x01, // field 1 varint 150
            0x12, 0x07, b't', b'e', b's', b't', b'i', b'n', b'g', // field 2 string
        ];
        let txt = decode_to_text(&bytes).unwrap();
        assert!(txt.contains("field 1 (varint): 150"), "{txt}");
        assert!(txt.contains("field 2 (string): \"testing\""), "{txt}");
    }

    #[test]
    fn decodes_nested_message() {
        // 外层 field 3 (message) 内含 field 1 varint = 150。
        let inner = [0x08, 0x96, 0x01];
        let mut bytes = vec![0x1a, inner.len() as u8]; // field 3, wire 2 (len)
        bytes.extend_from_slice(&inner);
        let txt = decode_to_text(&bytes).unwrap();
        assert!(txt.contains("field 3 (message"), "{txt}");
        assert!(txt.contains("field 1 (varint): 150"), "{txt}");
    }

    #[test]
    fn rejects_truncated_and_empty() {
        assert!(decode_to_text(&[]).is_none());
        // 截断的 varint(续位但无后续字节)。
        assert!(decode_to_text(&[0x08, 0x80]).is_none());
        // 越界的 length-delimited(声明 10 字节但没有)。
        assert!(decode_to_text(&[0x12, 0x0a, 0x00]).is_none());
    }

    #[test]
    fn fixed32_and_fixed64() {
        // field 5 (32-bit) = 1.0f32 (0x3f800000 little-endian) ; field 6 (64-bit) = 1.0f64。
        let mut bytes = vec![0x2d]; // (5<<3)|5
        bytes.extend_from_slice(&1.0f32.to_bits().to_le_bytes());
        bytes.push(0x31); // (6<<3)|1
        bytes.extend_from_slice(&1.0f64.to_bits().to_le_bytes());
        let txt = decode_to_text(&bytes).unwrap();
        assert!(txt.contains("field 5 (32-bit)"), "{txt}");
        assert!(txt.contains("float 1"), "{txt}");
        assert!(txt.contains("field 6 (64-bit)"), "{txt}");
        assert!(txt.contains("double 1"), "{txt}");
    }

    #[test]
    fn grpc_frame_wraps_protobuf() {
        let inner = [0x08, 0x96, 0x01]; // field1 varint 150
        let mut bytes = vec![0x00]; // not compressed
        bytes.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&inner);
        let txt = decode_grpc_to_text(&bytes).unwrap();
        assert!(txt.contains("gRPC frame #1"), "{txt}");
        assert!(txt.contains("field 1 (varint): 150"), "{txt}");
    }

    #[test]
    fn text_input_accepts_hex_and_base64() {
        // hex of canonical example。
        let hex = "08 96 01 12 07 74 65 73 74 69 6e 67";
        assert!(decode_text_input(hex).unwrap().contains("testing"));
        // base64 of [08 96 01]。
        let b64 = base64_of(&[0x08, 0x96, 0x01]);
        assert!(decode_text_input(&b64).unwrap().contains("field 1 (varint): 150"));
        // 明显非 protobuf。
        assert!(decode_text_input("hello world this is plain text!!").is_err());
    }

    /// 测试辅助:标准 base64 编码(仅供单测构造输入)。
    fn base64_of(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
            out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
        }
        out
    }
}
