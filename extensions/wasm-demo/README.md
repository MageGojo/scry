# wasm-demo —— Scry WASM 沙箱扩展示例

对标 `../py-demo`,但运行在 **wasmtime 强隔离沙箱**里:WASM 模块默认看不到文件 / 网络 / 进程,
再叠加 **fuel**(指令配额,防死循环)与**内存上限**(防内存炸弹)——装不可信的第三方扩展也安全。

## 行为
- `on_request`:给每个请求加 `X-Scry-Wasm: 1` 头(演示改写实时流量)。
- `on_flow_complete`:响应 4xx/5xx 时上报一个 finding。
- 纯计算,不外联。

## 构建
```bash
./build.sh
# 等价于:
# rustup target add wasm32-unknown-unknown
# cargo build --release --target wasm32-unknown-unknown
# cp target/wasm32-unknown-unknown/release/wasm_demo.wasm ./wasm_demo.wasm
```

## 安装
把整个目录拷到 scry 的扩展目录,scry 启动时自动发现加载:
```bash
cp -r . ~/.scry/extensions/wasm-demo
```

## 它怎么被加载(ABI)
`manifest.json` 用 `wasm` 字段指向模块文件,scry 据此走 WASM Runner(而非进程):
```json
{ "wasm": "wasm_demo.wasm", "fuel": 200000000 }
```
模块需导出 `memory` + `scry_alloc` + `scry_manifest` + 各钩子(`scry_on_request` / `scry_on_response` /
`scry_on_flow_complete`)。输入输出都是线性内存里的 JSON,用「打包指针」`(ptr<<32)|len` 传递。
详见 `scry_ext_host::wasm` 与 `src/lib.rs`。

## 为什么用 WASM 而不是进程
| 维度 | WASM(本示例) | 外部进程(py-demo) |
|---|---|---|
| 隔离 | 沙箱(无系统能力) | OS 进程(强,但有系统能力) |
| 启动 | 实例化(微秒级) | spawn 子进程 |
| 依赖 | 随包静态链接,零运行时 | 需目标机自带 `python3` |
| 适合 | **第三方不可信扩展** | 脚本党 / 复用现成 Python 库 |
