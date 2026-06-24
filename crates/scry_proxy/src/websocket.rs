//! WebSocket 帧解析(RFC 6455)—— 抓包用:从**已解密的明文字节流**增量切出完整帧并解 payload。
//!
//! 纯逻辑、无 IO,可单测。MITM 升级为 WS 后,转发走**字节透传**(不等帧完整,零破坏),
//! 本模块只负责"看懂"帧 → 聚合成消息以记录,转发与记录互不影响。
//!
//! 帧格式(RFC 6455 §5.2):
//! ```text
//! FIN+RSV+opcode(1B) | MASK+len7(1B) | [ext len 2/8B] | [mask key 4B] | payload
//! ```
//! 客户端→服务端帧**必须 mask**,服务端→客户端**不 mask**。消息可分片(首帧 opcode + 若干
//! Continuation,末帧 FIN=1);control 帧(close/ping/pong)不参与分片。

/// 单帧解析允许的最大 payload(防恶意/异常长度把缓冲撑爆;抓包展示足够)。
const MAX_FRAME_PAYLOAD: usize = 64 * 1024 * 1024;

/// WebSocket 帧操作码(RFC 6455 §5.2)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    /// 0x0 续帧(分片消息的后续部分)。
    Continuation,
    /// 0x1 文本(UTF-8)。
    Text,
    /// 0x2 二进制。
    Binary,
    /// 0x8 关闭。
    Close,
    /// 0x9 ping。
    Ping,
    /// 0xA pong。
    Pong,
    /// 其它(保留 / 未知)。
    Other(u8),
}

impl OpCode {
    /// 从低 4 位 opcode 字段构造。
    pub fn from_u8(v: u8) -> Self {
        match v & 0x0f {
            0x0 => OpCode::Continuation,
            0x1 => OpCode::Text,
            0x2 => OpCode::Binary,
            0x8 => OpCode::Close,
            0x9 => OpCode::Ping,
            0xA => OpCode::Pong,
            other => OpCode::Other(other),
        }
    }

    /// 是否 control 帧(close/ping/pong;opcode 高位 0x8)——不参与分片聚合。
    pub fn is_control(self) -> bool {
        matches!(self, OpCode::Close | OpCode::Ping | OpCode::Pong)
    }

    /// 展示用短标签。
    pub fn label(self) -> &'static str {
        match self {
            OpCode::Continuation => "Continuation",
            OpCode::Text => "Text",
            OpCode::Binary => "Binary",
            OpCode::Close => "Close",
            OpCode::Ping => "Ping",
            OpCode::Pong => "Pong",
            OpCode::Other(_) => "Other",
        }
    }
}

/// 一个完整 WS 帧(payload 已解 mask)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub opcode: OpCode,
    pub payload: Vec<u8>,
}

/// 增量帧解析器:喂字节流 → 逐个吐出完整帧(处理跨 read 的半帧)。
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// 追加新读到的字节。
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// 尝试取出下一个完整帧;数据不足返回 `None`(等待更多字节)。
    ///
    /// 异常:payload 长度超过 [`MAX_FRAME_PAYLOAD`] → 丢弃缓冲并返回 `None`(避免无限累积)。
    pub fn next_frame(&mut self) -> Option<Frame> {
        let buf = &self.buf;
        if buf.len() < 2 {
            return None;
        }
        let b0 = buf[0];
        let b1 = buf[1];
        let fin = b0 & 0x80 != 0;
        let opcode = OpCode::from_u8(b0);
        let masked = b1 & 0x80 != 0;
        let len7 = (b1 & 0x7f) as usize;

        let mut offset = 2usize;
        let payload_len = match len7 {
            126 => {
                if buf.len() < offset + 2 {
                    return None;
                }
                let l = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
                offset += 2;
                l
            }
            127 => {
                if buf.len() < offset + 8 {
                    return None;
                }
                let mut a = [0u8; 8];
                a.copy_from_slice(&buf[offset..offset + 8]);
                offset += 8;
                u64::from_be_bytes(a) as usize
            }
            n => n,
        };

        if payload_len > MAX_FRAME_PAYLOAD {
            // 异常长度:放弃这条流的帧解析(转发不受影响,仍是字节透传)。
            self.buf.clear();
            return None;
        }

        let mask_key = if masked {
            if buf.len() < offset + 4 {
                return None;
            }
            let k = [buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]];
            offset += 4;
            Some(k)
        } else {
            None
        };

        let total = offset + payload_len;
        if buf.len() < total {
            return None;
        }

        let mut payload = buf[offset..total].to_vec();
        if let Some(k) = mask_key {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= k[i % 4];
            }
        }
        self.buf.drain(..total);
        Some(Frame {
            fin,
            opcode,
            payload,
        })
    }
}

/// 一条聚合后的 WS 消息(分片已拼接;control 帧单独成条)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub opcode: OpCode,
    pub payload: Vec<u8>,
}

/// 把帧聚合成消息:数据帧(Text/Binary)按 FIN 聚合分片;control 帧(close/ping/pong)立即单独产出。
#[derive(Debug, Default)]
pub struct Assembler {
    /// 进行中的分片消息:(首帧 opcode, 已累积 payload)。
    cur: Option<(OpCode, Vec<u8>)>,
}

impl Assembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// 吃一个帧 → 返回完成的消息(`None` = 分片仍在进行 / 孤立续帧被忽略)。
    pub fn push(&mut self, frame: Frame) -> Option<Message> {
        // control 帧:独立消息,不影响数据帧分片状态。
        if frame.opcode.is_control() {
            return Some(Message {
                opcode: frame.opcode,
                payload: frame.payload,
            });
        }
        match frame.opcode {
            OpCode::Continuation => {
                if let Some((op, buf)) = self.cur.as_mut() {
                    buf.extend_from_slice(&frame.payload);
                    if frame.fin {
                        let op = *op;
                        let payload = self.cur.take().map(|(_, b)| b).unwrap_or_default();
                        Some(Message { opcode: op, payload })
                    } else {
                        None
                    }
                } else {
                    // 没有进行中的消息却来续帧:协议异常,忽略。
                    None
                }
            }
            data_op => {
                if frame.fin {
                    Some(Message {
                        opcode: data_op,
                        payload: frame.payload,
                    })
                } else {
                    self.cur = Some((data_op, frame.payload));
                    None
                }
            }
        }
    }
}

/// 请求头是否为 WebSocket 升级握手(`Upgrade: websocket`)。
pub fn is_upgrade_request(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("upgrade") && v.to_ascii_lowercase().contains("websocket")
    })
}

/// 响应是否为 `101` 且确为 WebSocket 协议切换。
pub fn is_switching_response(status: u16, headers: &[(String, String)]) -> bool {
    status == 101
        && headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("upgrade") && v.to_ascii_lowercase().contains("websocket")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个(可选 mask 的)WS 帧字节。
    fn frame_bytes(fin: bool, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(if fin { 0x80 } else { 0 } | (opcode & 0x0f));
        let mask_bit = if mask.is_some() { 0x80 } else { 0 };
        let len = payload.len();
        if len <= 125 {
            out.push(mask_bit | len as u8);
        } else if len <= 0xffff {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        if let Some(k) = mask {
            out.extend_from_slice(&k);
            for (i, b) in payload.iter().enumerate() {
                out.push(b ^ k[i % 4]);
            }
        } else {
            out.extend_from_slice(payload);
        }
        out
    }

    #[test]
    fn decodes_unmasked_text_frame() {
        let bytes = frame_bytes(true, 0x1, b"hello", None);
        let mut d = FrameDecoder::new();
        d.feed(&bytes);
        let f = d.next_frame().unwrap();
        assert!(f.fin);
        assert_eq!(f.opcode, OpCode::Text);
        assert_eq!(f.payload, b"hello");
        assert!(d.next_frame().is_none());
    }

    #[test]
    fn decodes_masked_client_frame() {
        let key = [0x37, 0xfa, 0x21, 0x3d];
        let bytes = frame_bytes(true, 0x1, b"client->server", Some(key));
        let mut d = FrameDecoder::new();
        d.feed(&bytes);
        let f = d.next_frame().unwrap();
        // 解 mask 后应还原明文。
        assert_eq!(f.payload, b"client->server");
        assert_eq!(f.opcode, OpCode::Text);
    }

    #[test]
    fn handles_partial_then_complete() {
        let bytes = frame_bytes(true, 0x2, b"binarydata", None);
        let mut d = FrameDecoder::new();
        // 先喂前 3 字节:不足一帧。
        d.feed(&bytes[..3]);
        assert!(d.next_frame().is_none());
        // 喂完剩余:出帧。
        d.feed(&bytes[3..]);
        let f = d.next_frame().unwrap();
        assert_eq!(f.opcode, OpCode::Binary);
        assert_eq!(f.payload, b"binarydata");
    }

    #[test]
    fn decodes_multiple_frames_in_one_feed() {
        let mut bytes = frame_bytes(true, 0x1, b"one", None);
        bytes.extend(frame_bytes(true, 0x1, b"two", None));
        let mut d = FrameDecoder::new();
        d.feed(&bytes);
        assert_eq!(d.next_frame().unwrap().payload, b"one");
        assert_eq!(d.next_frame().unwrap().payload, b"two");
        assert!(d.next_frame().is_none());
    }

    #[test]
    fn extended_len_126_u16() {
        let payload = vec![b'a'; 200]; // > 125 → 走 u16 扩展长度
        let bytes = frame_bytes(true, 0x2, &payload, None);
        let mut d = FrameDecoder::new();
        d.feed(&bytes);
        let f = d.next_frame().unwrap();
        assert_eq!(f.payload.len(), 200);
    }

    #[test]
    fn assembler_joins_fragments() {
        let mut a = Assembler::new();
        // 文本消息分 3 片:Text(fin=0) + Cont(fin=0) + Cont(fin=1)。
        assert!(a
            .push(Frame { fin: false, opcode: OpCode::Text, payload: b"Hel".to_vec() })
            .is_none());
        assert!(a
            .push(Frame { fin: false, opcode: OpCode::Continuation, payload: b"lo ".to_vec() })
            .is_none());
        let m = a
            .push(Frame { fin: true, opcode: OpCode::Continuation, payload: b"World".to_vec() })
            .unwrap();
        assert_eq!(m.opcode, OpCode::Text);
        assert_eq!(m.payload, b"Hello World");
    }

    #[test]
    fn assembler_control_frame_passes_through() {
        let mut a = Assembler::new();
        // 分片进行中突然来个 ping(control)——ping 立即产出,不打断数据消息聚合。
        assert!(a
            .push(Frame { fin: false, opcode: OpCode::Text, payload: b"da".to_vec() })
            .is_none());
        let ping = a
            .push(Frame { fin: true, opcode: OpCode::Ping, payload: b"".to_vec() })
            .unwrap();
        assert_eq!(ping.opcode, OpCode::Ping);
        let m = a
            .push(Frame { fin: true, opcode: OpCode::Continuation, payload: b"ta".to_vec() })
            .unwrap();
        assert_eq!(m.payload, b"data");
    }

    #[test]
    fn detects_upgrade_and_switching() {
        let req = vec![
            ("Host".to_string(), "x".to_string()),
            ("Upgrade".to_string(), "websocket".to_string()),
            ("Connection".to_string(), "Upgrade".to_string()),
        ];
        assert!(is_upgrade_request(&req));
        let resp = vec![("Upgrade".to_string(), "websocket".to_string())];
        assert!(is_switching_response(101, &resp));
        assert!(!is_switching_response(200, &resp));
    }
}
