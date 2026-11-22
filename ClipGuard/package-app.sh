#!/usr/bin/env bash
# 把 SPM 构建产物打包成标准 macOS .app（ad-hoc 签名，无需付费开发者账号、无需管理员权限）。
# 打包后才能使用 UserNotifications 系统通知；裸二进制只走声音 + 菜单栏 + 日志。
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME="ClipGuard"
BUILD_CONFIG="${1:-release}"
OUT_DIR="dist"
APP_DIR="$OUT_DIR/$APP_NAME.app"

echo "▶ swift build -c $BUILD_CONFIG"
swift build -c "$BUILD_CONFIG"

BIN_PATH="$(swift build -c "$BUILD_CONFIG" --show-bin-path)/clipguard"
[[ -x "$BIN_PATH" ]] || { echo "找不到二进制 $BIN_PATH"; exit 1; }

echo "▶ 组装 $APP_DIR"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"
cp "$BIN_PATH" "$APP_DIR/Contents/MacOS/clipguard"

cat > "$APP_DIR/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>ClipGuard</string>
    <key>CFBundleDisplayName</key><string>ClipGuard 剪贴板保护</string>
    <key>CFBundleIdentifier</key><string>com.clipguard.protector</string>
    <key>CFBundleVersion</key><string>1.0</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleExecutable</key><string>clipguard</string>
    <key>LSUIElement</key><true/>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>NSAppleEventsUsageDescription</key>
    <string>ClipGuard 需要监听剪贴板变化以保护你复制的敏感内容。</string>
</dict>
</plist>
EOF

echo "▶ ad-hoc 代码签名（本机可用，不依赖开发者账号）"
codesign --force --sign - "$APP_DIR"

echo
echo "✅ 打包完成: $APP_DIR"
echo "   启动:   open '$APP_DIR'"
echo "   首次运行若被 Gatekeeper 拦截: 右键 → 打开，或 xattr -dr com.apple.quarantine '$APP_DIR'"
echo "   授予辅助功能: 系统设置 → 隐私与安全性 → 辅助功能 → 添加 ClipGuard（启用精确 ⌘V 模式）"
