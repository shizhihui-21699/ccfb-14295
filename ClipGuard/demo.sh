#!/usr/bin/env bash
# ClipGuard 一键端到端演示（无需管理员权限，所有产物在临时目录，不污染真实环境）
set -euo pipefail

cd "$(dirname "$0")"
DEMO_HOME="$(mktemp -d)/clipguard-demo"
mkdir -p "$DEMO_HOME"
export CLIPGUARD_HOME="$DEMO_HOME"

# 演示用短 TTL，便于观察自动清除
cat > "$DEMO_HOME/config.json" <<'EOF'
{
  "ttl": 8, "exposureWindow": 1.5, "fallbackExposureWindow": 3,
  "pollInterval": 0.3, "alertThreshold": 60, "alertCooldown": 30,
  "soundOnCapture": false, "soundOnRehide": false,
  "detector": {
    "detectBankCard": true, "detectPrivateKey": true, "detectMnemonic": true,
    "detectApiToken": true, "detectPassword": true, "detectOneTimeCode": false,
    "minimumConfidence": 0.6
  }
}
EOF

echo "▶ 构建（release）…"
swift build -c release >/dev/null
CG=.build/release/clipguard
THIEF=.build/release/clip-thief

echo "▶ 启动 ClipGuard 守护代理（CLIPGUARD_HOME=${DEMO_HOME}）"
"$CG" >"$DEMO_HOME/daemon.out" 2>&1 &
DAEMON=$!
trap 'kill '"$DAEMON"' 2>/dev/null || true' EXIT
sleep 2

echo
echo "▶ ① 复制银行卡号（模拟用户在任意 App 按 ⌘C）"
echo "4532015112830366" | pbcopy
sleep 1.2
echo "  剪贴板现在是: [$(pbpaste | head -c 40)…]"

echo
echo "▶ ② 可疑程序 clip-thief 尝试读取 —— 读不到明文"
"$THIEF" --mode once 2>&1 | sed 's/^/  /'

echo
echo "▶ ③ 等 TTL（8s）自动从内存清除"
sleep 9
echo "  清除后剪贴板: [$(pbpaste | head -c 30)…]"

echo
echo "▶ ④ hijacker 无手势静默写入，触发可疑评分告警"
"$THIEF" --mode hijacker --payload "https://evil.example/phish" --interval 1 --duration 3 2>&1 | sed 's/^/  /'
sleep 1

echo
echo "▶ ClipGuard 审计日志（脱敏，无明文）:"
python3 - "$DEMO_HOME/events.jsonl" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    e = json.loads(line)
    tag = {"protected":"🔒","alert":"🚨","warning":"⚠️ ","info":"ℹ️ ","paste":"📋"}.get(e["level"],"·")
    print(f"  {tag} {e['message'][:110]}")
PY

echo
echo "✅ 演示结束。守护进程将被自动停止，数据目录: ${DEMO_HOME}"
