#!/usr/bin/env bash
# 零环境出包(macOS):把 scry_app 打成自带资源的 Scry.app —— 双击即用,目标机无需装 Rust/SDK。
#
# 产物:dist/Scry.app(可直接双击) + dist/Scry-macos.zip(可分发)。
# 关键点:
#  - 把 mage_ui 的图标拷进 Contents/Resources/icons;运行时 icon 加载优先读这里(见 mage_ui icon.rs),
#    因此换机器也能显示图标(不依赖源码的编译期路径)。
#  - ad-hoc 代码签名(codesign -s -)让本机 Gatekeeper 放行;分发给他人需各自「右键→打开」或做公证(需 Apple 证书)。
#  - macOS 纯 Rust+gpui 不依赖 VC++ 之类运行时(那是 Windows 的事),只需正确的 .app 结构。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ICONS_SRC="$ROOT/../mage-ui/crates/mage_ui/assets/icons"
APP_ICNS="$ROOT/assets/icon/AppIcon.icns"   # 应用图标(Dock/Finder),由 scripts/make_icon.py 从 assets/icon/scry.png 生成
BIN_NAME="scry_app"
APP_NAME="Scry"
DIST="$ROOT/dist"
APP="$DIST/$APP_NAME.app"
CONTENTS="$APP/Contents"

echo "==> [1/5] 编译 release(opt-level=z + lto,首次较慢)"
( cd "$ROOT" && cargo build --release -p "$BIN_NAME" )
BIN="$ROOT/target/release/$BIN_NAME"
[ -f "$BIN" ] || { echo "找不到二进制:$BIN"; exit 1; }

echo "==> [2/5] 组装 $APP_NAME.app 目录结构"
rm -rf "$APP"
mkdir -p "$CONTENTS/MacOS" "$CONTENTS/Resources/icons"
cp "$BIN" "$CONTENTS/MacOS/$BIN_NAME"
chmod +x "$CONTENTS/MacOS/$BIN_NAME"

echo "==> [3/5] 拷入自带资源(界面 SVG 图标 + 应用图标)"
if [ -d "$ICONS_SRC" ]; then
  cp "$ICONS_SRC"/*.svg "$CONTENTS/Resources/icons/" 2>/dev/null || true
  echo "    UI icons: $(ls "$CONTENTS/Resources/icons" | wc -l | tr -d ' ') 个"
else
  echo "    警告:未找到图标源 $ICONS_SRC(界面图标可能缺失)"
fi

# 应用图标:没有 .icns 就现场用 make_icon.py 从源 PNG 生成(需 python3 + Pillow + iconutil)。
if [ ! -f "$APP_ICNS" ] && command -v python3 >/dev/null 2>&1; then
  echo "    未找到 AppIcon.icns,尝试用 make_icon.py 生成…"
  python3 "$ROOT/scripts/make_icon.py" || true
fi
if [ -f "$APP_ICNS" ]; then
  cp "$APP_ICNS" "$CONTENTS/Resources/AppIcon.icns"
  echo "    App icon: AppIcon.icns ✓"
else
  echo "    警告:未找到 $APP_ICNS(Dock/Finder 将显示默认空白图标)"
fi

echo "==> [4/5] 写 Info.plist"
cat > "$CONTENTS/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>$APP_NAME</string>
  <key>CFBundleDisplayName</key><string>$APP_NAME</string>
  <key>CFBundleIdentifier</key><string>com.scry.app</string>
  <key>CFBundleVersion</key><string>0.1.0</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleExecutable</key><string>$BIN_NAME</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>Scry Pentest Suite</string>
</dict>
</plist>
PLIST

echo "==> [5/5] ad-hoc 代码签名 + 打包 zip"
codesign --force --deep --sign - "$APP" 2>/dev/null && echo "    已 ad-hoc 签名" || echo "    codesign 跳过(本机无 codesign?)"
( cd "$DIST" && ditto -c -k --keepParent "$APP_NAME.app" "$APP_NAME-macos.zip" )

echo ""
echo "✅ 完成:"
echo "   App : $APP"
echo "   Zip : $DIST/$APP_NAME-macos.zip"
echo "   验证: open \"$APP\"   # 双击即用"
echo "   分发: 他人首次打开需「右键→打开」放行(未公证);要彻底零提示需 Apple 证书做公证。"
