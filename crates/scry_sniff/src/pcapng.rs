//! pcapng 导出 —— 把抓到的**原始链路帧**(L2 以太网 / L3 IP)写成标准 **pcapng** 文件,
//! Wireshark / tshark 可直接打开。
//!
//! 设计:块编码器([`encode_shb`] / [`encode_idb`] / [`encode_epb`])是**纯函数**(返回字节,可单测);
//! [`PcapngWriter`] 只负责把它们顺序写进任意 [`Write`]。全部小端、4 字节对齐,块长在块首和块尾各写一次
//! (pcapng 规范要求,便于双向遍历)。
//!
//! 块结构(本实现用到的最小子集):
//! - SHB(Section Header Block,0x0A0D0D0A):魔数 + 版本 + 段长(未知 = -1)。
//! - IDB(Interface Description Block,0x00000001):linktype(同 libpcap DLT)+ snaplen。
//! - EPB(Enhanced Packet Block,0x00000006):接口 id + 64 位时间戳(默认 µs 分辨率)+ 原始帧字节。

use std::io::{self, Write};

/// pcapng / libpcap 链路类型(DLT)常量(与 `pcap` 同值,可直接透传)。
pub const LINKTYPE_NULL: u16 = 0;
pub const LINKTYPE_ETHERNET: u16 = 1;
pub const LINKTYPE_RAW: u16 = 101;

/// 段头块魔数(也是 pcapng 文件魔数)。
const BT_SHB: u32 = 0x0A0D_0D0A;
/// 字节序魔数(小端写入,读端据此判序)。
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
/// 接口描述块。
const BT_IDB: u32 = 0x0000_0001;
/// 增强分组块。
const BT_EPB: u32 = 0x0000_0006;

/// 4 字节对齐所需的填充字节数。
fn pad4(n: usize) -> usize {
    (4 - (n % 4)) % 4
}

/// 编码段头块(SHB)。固定 28 字节,段长写未知(-1)。
pub fn encode_shb() -> Vec<u8> {
    let total: u32 = 28;
    let mut b = Vec::with_capacity(total as usize);
    b.extend_from_slice(&BT_SHB.to_le_bytes());
    b.extend_from_slice(&total.to_le_bytes());
    b.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes()); // major
    b.extend_from_slice(&0u16.to_le_bytes()); // minor
    b.extend_from_slice(&(-1i64).to_le_bytes()); // section length unknown
    b.extend_from_slice(&total.to_le_bytes()); // 块尾再写一次总长
    b
}

/// 编码接口描述块(IDB)。固定 20 字节(无选项;默认时间戳分辨率 = µs)。
pub fn encode_idb(linktype: u16, snaplen: u32) -> Vec<u8> {
    let total: u32 = 20;
    let mut b = Vec::with_capacity(total as usize);
    b.extend_from_slice(&BT_IDB.to_le_bytes());
    b.extend_from_slice(&total.to_le_bytes());
    b.extend_from_slice(&linktype.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes()); // reserved
    b.extend_from_slice(&snaplen.to_le_bytes());
    b.extend_from_slice(&total.to_le_bytes());
    b
}

/// 编码增强分组块(EPB)。`ts_micros` 为自纪元的微秒数(默认分辨率),`data` 为原始链路帧。
pub fn encode_epb(ts_micros: u64, data: &[u8]) -> Vec<u8> {
    let cap_len = data.len();
    let pad = pad4(cap_len);
    let total = 32 + cap_len + pad;
    let mut b = Vec::with_capacity(total);
    b.extend_from_slice(&BT_EPB.to_le_bytes());
    b.extend_from_slice(&(total as u32).to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes()); // interface id = 0
    b.extend_from_slice(&((ts_micros >> 32) as u32).to_le_bytes()); // ts high
    b.extend_from_slice(&((ts_micros & 0xFFFF_FFFF) as u32).to_le_bytes()); // ts low
    b.extend_from_slice(&(cap_len as u32).to_le_bytes()); // captured length
    b.extend_from_slice(&(cap_len as u32).to_le_bytes()); // original length
    b.extend_from_slice(data);
    b.extend(std::iter::repeat_n(0u8, pad));
    b.extend_from_slice(&(total as u32).to_le_bytes()); // 块尾总长
    b
}

/// 顺序写出 pcapng 的写入器:`new` 即写 SHB+IDB,之后每帧一个 EPB。
pub struct PcapngWriter<W: Write> {
    w: W,
}

impl<W: Write> PcapngWriter<W> {
    /// 新建并写出文件头(SHB + 单接口 IDB)。
    pub fn new(mut w: W, linktype: u16, snaplen: u32) -> io::Result<Self> {
        w.write_all(&encode_shb())?;
        w.write_all(&encode_idb(linktype, snaplen))?;
        Ok(Self { w })
    }

    /// 追加一帧(原始链路字节)。
    pub fn write_packet(&mut self, ts_micros: u64, data: &[u8]) -> io::Result<()> {
        self.w.write_all(&encode_epb(ts_micros, data))
    }

    /// 刷盘。
    pub fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rd_u32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }

    #[test]
    fn shb_has_magics_and_consistent_length() {
        let shb = encode_shb();
        assert_eq!(shb.len(), 28);
        assert_eq!(rd_u32(&shb, 0), BT_SHB);
        assert_eq!(rd_u32(&shb, 4), 28); // 头部总长
        assert_eq!(rd_u32(&shb, 8), BYTE_ORDER_MAGIC);
        assert_eq!(rd_u32(&shb, 24), 28); // 尾部总长一致
    }

    #[test]
    fn idb_roundtrip_fields() {
        let idb = encode_idb(LINKTYPE_ETHERNET, 65535);
        assert_eq!(idb.len(), 20);
        assert_eq!(rd_u32(&idb, 0), BT_IDB);
        assert_eq!(u16::from_le_bytes([idb[8], idb[9]]), LINKTYPE_ETHERNET);
        assert_eq!(rd_u32(&idb, 12), 65535); // snaplen
        assert_eq!(rd_u32(&idb, 0), BT_IDB);
        assert_eq!(rd_u32(&idb, 16), 20);
    }

    #[test]
    fn epb_pads_to_4_and_keeps_lengths() {
        // 5 字节数据 → 需要 3 字节填充 → 总长 = 32 + 5 + 3 = 40。
        let data = [1u8, 2, 3, 4, 5];
        let epb = encode_epb(0x0000_0001_2345_6789, &data);
        assert_eq!(epb.len(), 40);
        assert_eq!(epb.len() % 4, 0);
        assert_eq!(rd_u32(&epb, 0), BT_EPB);
        assert_eq!(rd_u32(&epb, 4), 40); // 头部总长
        // 时间戳:high / low
        assert_eq!(rd_u32(&epb, 12), 0x0000_0001); // high
        assert_eq!(rd_u32(&epb, 16), 0x2345_6789); // low
        assert_eq!(rd_u32(&epb, 20), 5); // captured len
        assert_eq!(rd_u32(&epb, 24), 5); // original len
        assert_eq!(&epb[28..33], &data); // 数据原样
        assert_eq!(rd_u32(&epb, 36), 40); // 尾部总长一致
    }

    #[test]
    fn writer_emits_shb_idb_then_epbs() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = PcapngWriter::new(&mut buf, LINKTYPE_ETHERNET, 65535).unwrap();
            w.write_packet(1_000_000, &[0xAA; 14]).unwrap();
            w.write_packet(2_000_000, &[0xBB; 60]).unwrap();
            w.flush().unwrap();
        }
        // 按 block total length 遍历,校验块序列 = [SHB, IDB, EPB, EPB]。
        let mut off = 0usize;
        let mut types = Vec::new();
        while off + 8 <= buf.len() {
            let bt = rd_u32(&buf, off);
            let len = rd_u32(&buf, off + 4) as usize;
            assert!(len >= 12 && off + len <= buf.len(), "块长越界");
            // 块尾总长必须与块首一致。
            assert_eq!(rd_u32(&buf, off + len - 4), len as u32);
            types.push(bt);
            off += len;
        }
        assert_eq!(off, buf.len(), "块长之和应铺满整个缓冲");
        assert_eq!(types, vec![BT_SHB, BT_IDB, BT_EPB, BT_EPB]);
    }
}
