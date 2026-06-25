//! 弱网 / 限速模拟(对标 Reqable / Charles 的 Throttle)。
//!
//! 在代理把响应**回写给客户端**的链路上注入「固定延迟 + 带宽上限」,模拟 2G/3G/慢速网络。
//! 纯计算部分([`Throttle::chunk_delay`])可单测;[`write_throttled`] 是带 IO 的应用层。
//!
//! `ProxyConfig.throttle == None`(或预设 Off)时**零开销 / 零行为变化**(直接 `write_all`)。

use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// 限速参数。带宽单位 **kbps(千比特/秒)**,与 Reqable / Charles 习惯一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Throttle {
    /// 下行带宽上限(kbps);`0` = 下行不限速。
    pub down_kbps: u32,
    /// 上行带宽上限(kbps);`0` = 上行不限速(当前仅记录,主用下行)。
    pub up_kbps: u32,
    /// 附加延迟(毫秒,加在响应开始前,模拟 RTT)。
    pub latency_ms: u64,
}

impl Throttle {
    pub const fn new(down_kbps: u32, up_kbps: u32, latency_ms: u64) -> Self {
        Self {
            down_kbps,
            up_kbps,
            latency_ms,
        }
    }

    /// 是否实际不生效(无带宽限制且无延迟)→ 可走零开销直发路径。
    pub fn is_noop(&self) -> bool {
        self.down_kbps == 0 && self.latency_ms == 0
    }

    /// 发送 `bytes` 字节在下行带宽上限下应耗费的时间。
    ///
    /// kbps(千比特/秒)→ 字节/秒 = `kbps * 1000 / 8 = kbps * 125`。
    pub fn chunk_delay(&self, bytes: usize) -> Duration {
        if self.down_kbps == 0 {
            return Duration::ZERO;
        }
        let bytes_per_sec = self.down_kbps as f64 * 125.0;
        Duration::from_secs_f64(bytes as f64 / bytes_per_sec)
    }
}

/// 内置预设档(名字, 参数)。UI 直接遍历此表做下拉。
pub const PRESETS: &[(&str, Throttle)] = &[
    ("Off", Throttle::new(0, 0, 0)),
    ("GPRS", Throttle::new(50, 20, 500)),
    ("Regular 2G", Throttle::new(250, 50, 300)),
    ("Regular 3G", Throttle::new(750, 250, 100)),
    ("Good 3G", Throttle::new(1500, 750, 40)),
    ("Regular 4G", Throttle::new(4000, 3000, 20)),
    ("WiFi", Throttle::new(30000, 15000, 2)),
];

/// 按预设名取限速参数(忽略大小写;未知 / "Off" 返回 `None` = 不限速)。
pub fn preset(name: &str) -> Option<Throttle> {
    PRESETS
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, t)| *t)
        .filter(|t| !t.is_noop())
}

/// 把 `bytes` 写给客户端,按 `throttle` 注入延迟 + 限速。
///
/// - `throttle == None` 或 noop:等价于 `write_all + flush`(零开销)。
/// - 否则:先 `sleep(latency)`,再按 4KB 分块、每块按下行带宽 `sleep(chunk_delay)` 后发出。
pub async fn write_throttled<W>(
    w: &mut W,
    bytes: &[u8],
    throttle: Option<&Throttle>,
) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let t = match throttle {
        Some(t) if !t.is_noop() => t,
        _ => {
            w.write_all(bytes).await?;
            return w.flush().await;
        }
    };

    if t.latency_ms > 0 {
        tokio::time::sleep(Duration::from_millis(t.latency_ms)).await;
    }
    if t.down_kbps == 0 {
        w.write_all(bytes).await?;
        return w.flush().await;
    }

    const CHUNK: usize = 4096;
    for chunk in bytes.chunks(CHUNK) {
        let d = t.chunk_delay(chunk.len());
        if !d.is_zero() {
            tokio::time::sleep(d).await;
        }
        w.write_all(chunk).await?;
        w.flush().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_delay_math() {
        // 8 kbps = 1000 字节/秒 → 1000 字节耗时 1 秒。
        let t = Throttle::new(8, 0, 0);
        assert_eq!(t.chunk_delay(1000), Duration::from_secs(1));
        // 不限速 → 零延迟。
        assert_eq!(Throttle::new(0, 0, 0).chunk_delay(99999), Duration::ZERO);
    }

    #[test]
    fn noop_detection_and_presets() {
        assert!(Throttle::new(0, 0, 0).is_noop());
        assert!(!Throttle::new(0, 0, 100).is_noop());
        assert!(!Throttle::new(50, 0, 0).is_noop());
        // "Off" 视为不限速。
        assert!(preset("Off").is_none());
        assert!(preset("off").is_none());
        // 已知预设可取到。
        assert_eq!(preset("GPRS"), Some(Throttle::new(50, 20, 500)));
        assert!(preset("不存在").is_none());
    }

    #[tokio::test]
    async fn write_throttled_writes_all_bytes() {
        // 高带宽 + 无延迟 → 立即写完,字节完整。
        let mut sink: Vec<u8> = Vec::new();
        let data = vec![7u8; 10_000];
        write_throttled(&mut sink, &data, Some(&Throttle::new(1_000_000, 0, 0)))
            .await
            .unwrap();
        assert_eq!(sink, data);

        // None → 直发,字节完整。
        let mut sink2: Vec<u8> = Vec::new();
        write_throttled(&mut sink2, b"hello", None).await.unwrap();
        assert_eq!(sink2, b"hello");
    }
}
