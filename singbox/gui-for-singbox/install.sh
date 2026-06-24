#!/usr/bin/env bash
# 安装 "Scry 抓包配合" 插件到 GUI.for.SingBox。
#
# 用法:
#   1) 先彻底退出 GUI.for.SingBox(否则运行中的 GUI 会在退出时覆盖 plugins.yaml,导致注册丢失)
#   2) bash install.sh           # 安装/更新
#      bash install.sh --force   # App 仍在运行也强行装(不推荐)
#      bash install.sh --uninstall  # 卸载(移除条目与 js)
#
# 幂等:重复执行只会更新 js 与(必要时)补登记,不会重复添加条目。
set -euo pipefail

APP_SUPPORT="$HOME/Library/Application Support/GUI.for.SingBox"
PLUGINS_DIR="$APP_SUPPORT/plugins"
PLUGINS_YAML="$APP_SUPPORT/plugins.yaml"
PLUGIN_ID="plugin-scry-capture"
JS_NAME="plugin-scry-capture.js"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_JS="$SCRIPT_DIR/$JS_NAME"
SRC_MANIFEST="$SCRIPT_DIR/plugin-scry-capture.manifest.yaml"

FORCE=0
UNINSTALL=0
for a in "$@"; do
  case "$a" in
    --force) FORCE=1 ;;
    --uninstall) UNINSTALL=1 ;;
  esac
done

echo "==> GUI.for.SingBox 数据目录: $APP_SUPPORT"
[ -d "$APP_SUPPORT" ] || { echo "!! 未找到 GUI.for.SingBox 数据目录,请先运行一次该 App。"; exit 1; }

if pgrep -f "GUI.for.SingBox.app/Contents/MacOS/GUI.for.SingBox" >/dev/null 2>&1; then
  if [ "$FORCE" != "1" ]; then
    echo "!! 检测到 GUI.for.SingBox 正在运行。"
    echo "   请【彻底退出】该 App 后再运行本脚本(运行中改 plugins.yaml 会在退出时被覆盖)。"
    echo "   如确需强行执行: bash install.sh --force"
    exit 2
  fi
  echo "!! 警告: App 运行中,--force 继续(可能被覆盖)。"
fi

mkdir -p "$PLUGINS_DIR"
ts="$(date +%Y%m%d%H%M%S)"
[ -f "$PLUGINS_YAML" ] && cp -p "$PLUGINS_YAML" "$PLUGINS_YAML.bak.$ts" && echo "==> 已备份 plugins.yaml -> plugins.yaml.bak.$ts"

# 从 plugins.yaml 中删除本插件条目(顶层以 '- id: plugin-scry-capture' 起、到下一个顶层 '- ' 或文件尾)
strip_entry() {
  [ -f "$PLUGINS_YAML" ] || return 0
  awk '
    /^- id: '"$PLUGIN_ID"'$/ { skip=1; next }   # 命中本条目起始,进入跳过
    skip==1 && /^- / { skip=0 }                  # 下一个顶层条目开始,停止跳过并打印该行
    skip==1 { next }                             # 仍在被删条目内部,跳过
    { print }
  ' "$PLUGINS_YAML" > "$PLUGINS_YAML.tmp"
  mv "$PLUGINS_YAML.tmp" "$PLUGINS_YAML"
}

if [ "$UNINSTALL" = "1" ]; then
  echo "==> 卸载中..."
  strip_entry
  rm -f "$PLUGINS_DIR/$JS_NAME" && echo "==> 已删除 $PLUGINS_DIR/$JS_NAME" || true
  echo "==> 卸载完成。重启 GUI.for.SingBox 生效。"
  exit 0
fi

[ -f "$SRC_JS" ] || { echo "!! 缺少 $SRC_JS"; exit 1; }
[ -f "$SRC_MANIFEST" ] || { echo "!! 缺少 $SRC_MANIFEST"; exit 1; }

cp -f "$SRC_JS" "$PLUGINS_DIR/$JS_NAME"
echo "==> 已复制插件: $PLUGINS_DIR/$JS_NAME"

# 注册 plugins.yaml:若已存在同 id 则先移除旧条目,再追加最新清单(去掉注释行)
if [ -f "$PLUGINS_YAML" ] && grep -q "^- id: $PLUGIN_ID$" "$PLUGINS_YAML"; then
  echo "==> plugins.yaml 已有 $PLUGIN_ID,刷新条目"
  strip_entry
fi

if [ ! -f "$PLUGINS_YAML" ]; then
  : > "$PLUGINS_YAML"
fi
# 保证文件以换行结尾,再追加条目正文(剔除以 # 开头的注释行)
[ -s "$PLUGINS_YAML" ] && [ "$(tail -c1 "$PLUGINS_YAML")" != "" ] && printf '\n' >> "$PLUGINS_YAML"
grep -v '^[[:space:]]*#' "$SRC_MANIFEST" >> "$PLUGINS_YAML"
echo "==> 已登记到 plugins.yaml"

echo
echo "完成。下一步:"
echo "  1) 启动 GUI.for.SingBox,在「插件」页应看到『Scry 抓包配合』(确保启用/未禁用)。"
echo "  2) 右键插件 → 安装根证书到系统信任。"
echo "  3) 启动 Scry,上游指向 socks5://127.0.0.1:8899(scry_app 用 SCRY_UPSTREAM,或 scry_proxy --upstream)。"
echo "  4) 开启 TUN 并重启内核,即可在 Scry 看到解密流量。"
