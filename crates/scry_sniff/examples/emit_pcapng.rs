//! 用 [`scry_sniff::pcapng::PcapngWriter`] 写一个**样例 pcapng**(含一个 以太网+IPv4+TCP 帧),
//! 便于用 Wireshark / tshark 验证导出格式。
//!
//! 用法:`cargo run -p scry_sniff --example emit_pcapng -- /tmp/sample.pcapng`

use std::fs::File;
use std::io::BufWriter;

use scry_sniff::pcapng::{PcapngWriter, LINKTYPE_ETHERNET};

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/sample.pcapng".to_string());
    let file = File::create(&path).expect("创建文件失败");
    let mut w =
        PcapngWriter::new(BufWriter::new(file), LINKTYPE_ETHERNET, 65535).expect("写文件头失败");

    let frame = sample_eth_ipv4_tcp(b"GET / HTTP/1.1\r\nHost: scry.local\r\n\r\n");
    // 纪元微秒(任意时刻)。
    w.write_packet(1_700_000_000_000_000, &frame).expect("写帧失败");
    w.flush().expect("flush 失败");
    println!("已写出 {path}({} 字节帧)", frame.len());
}

/// 构造一个最小可解析的 以太网 + IPv4 + TCP 帧(校验和留 0,够 Wireshark 解出 L2/L3 结构)。
fn sample_eth_ipv4_tcp(payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    // ── 以太网头(14)──
    f.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]); // dst MAC
    f.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x02]); // src MAC
    f.extend_from_slice(&[0x08, 0x00]); // EtherType = IPv4

    // ── TCP 头(20)+ payload ──
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&50000u16.to_be_bytes()); // src port
    tcp.extend_from_slice(&80u16.to_be_bytes()); // dst port
    tcp.extend_from_slice(&1u32.to_be_bytes()); // seq
    tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
    tcp.extend_from_slice(&[0x50, 0x18]); // data offset 5 + flags PSH,ACK
    tcp.extend_from_slice(&65535u16.to_be_bytes()); // window
    tcp.extend_from_slice(&[0x00, 0x00]); // checksum(留 0)
    tcp.extend_from_slice(&[0x00, 0x00]); // urgent
    tcp.extend_from_slice(payload);

    // ── IPv4 头(20)──
    let total_len = (20 + tcp.len()) as u16;
    let mut ip = Vec::new();
    ip.push(0x45); // version 4 + IHL 5
    ip.push(0x00); // DSCP/ECN
    ip.extend_from_slice(&total_len.to_be_bytes());
    ip.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // flags DF
    ip.push(64); // TTL
    ip.push(6); // protocol TCP
    ip.extend_from_slice(&[0x00, 0x00]); // header checksum(留 0)
    ip.extend_from_slice(&[192, 168, 1, 2]); // src IP
    ip.extend_from_slice(&[93, 184, 216, 34]); // dst IP

    f.extend_from_slice(&ip);
    f.extend_from_slice(&tcp);
    f
}
