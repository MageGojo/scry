#!/usr/bin/env bash
# 编译 Scry WASM 示例扩展为 wasm32 模块,产物放到本目录供 scry 发现加载。
set -euo pipefail
cd "$(dirname "$0")"

rustup target add wasm32-unknown-unknown 2>/dev/null || true
cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/wasm_demo.wasm ./wasm_demo.wasm

echo "✅ 生成 wasm_demo.wasm（$(du -h wasm_demo.wasm | cut -f1)）"
echo "   安装:mkdir -p ~/.scry/extensions && cp manifest.json wasm_demo.wasm ~/.scry/extensions/wasm-demo/ 的方式或 cp -r . ~/.scry/extensions/wasm-demo"
