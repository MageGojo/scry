//! Scry XSS 引擎 —— **dalfox 式上下文感知** 反射型 XSS 检测的**纯函数内核**。
//!
//! 相比"注入 marker 看是否原样回显"的朴素反射检测,本引擎做到 dalfox 的精髓:
//! 1. **反射定位**([`reflections`]):注入唯一标记,找出它在响应里反射的位置。
//! 2. **上下文识别**([`detect_context`]):判断标记落在 HTML 文本 / 标签属性(单 / 双 / 无引号)/
//!    `<script>` JS(字符串内 / 外)/ HTML 注释 等哪种上下文。
//! 3. **可利用字符探测**([`abusable_chars`]):用一发"金丝雀"载荷探出 `< > " ' \` ( ) = /`
//!    哪些字符**原样反射**(未被 HTML 实体编码)—— 决定能否逃逸当前上下文。
//! 4. **载荷合成**([`synthesize`]):据上下文 + 可用字符**针对性**拼出能执行的 XSS 载荷,并给出
//!    用于验证的"证据子串"(`proof`)。
//! 5. **反射验证**:UI runner 把合成载荷打过去,响应里出现 `proof`(未编码)= **确认可利用**。
//! 6. **DOM sink 提示**([`dom_sinks`]):静态扫响应里的危险 DOM 接收点(`innerHTML`/`document.write`/
//!    `eval`/`location.*` 等),提示可能的 DOM 型 XSS(信息性,不代表已确认)。
//!
//! 与 `scry_sqli` 一致:引擎纯函数 / 可单测 / 不碰网络;发包由 UI runner 复用 `scry_proxy::replay`。
//!
//! ⚠️ 主动注入会向目标发送脚本载荷,**只对你已获授权的目标使用**。

pub mod context;
pub mod payloads;
pub mod points;

pub use context::{detect_context, HtmlContext};
pub use payloads::{
    abusable_chars, canary, dom_sinks, exec_vectors, reflections, synthesize, Abusable, Payload,
    EXEC_MARK, REFLECT_MARK,
};
pub use points::{build_probe, injection_points, InjectionPoint, Location};
