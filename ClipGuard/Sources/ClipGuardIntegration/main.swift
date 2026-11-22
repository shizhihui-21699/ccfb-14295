import AppKit
import ClipGuardCore

// 真机集成测试：驱动真实 NSPasteboard，验证
// 外部写入识别 → 敏感捕获 → 占位符替换 → 手动恢复 → 窗口收回 → TTL 清除 的完整链路。
// 直接复用生产组件 PasteboardController / SecretVault / SensitivityDetector。

var failures = 0
func assert(_ cond: Bool, _ message: String) {
    if cond { print("  ✓ \(message)") }
    else { failures += 1; print("  ✗ \(message)") }
}
func pbString() -> String? { NSPasteboard.general.string(forType: .string) }

// 测试用短参数，避免长时间等待
let ttl: TimeInterval = 2
let exposure: TimeInterval = 0.6
let poll: TimeInterval = 0.05

let detector = SensitivityDetector()
let vault = SecretVault(ttl: ttl, exposureWindow: exposure)
let controller = PasteboardController()

/// 生产协调器 tick 逻辑的等价内联版本（不依赖菜单栏 / 事件 Tap / RunLoop 模式）
func tick() {
    // 与生产一致：先消费外部写入，再处理保险箱到期，避免同轮覆盖用户新复制
    if controller.pollForExternalChange() {
        if controller.hasTextualContent(), let snapshot = controller.currentSnapshot() {
            if let result = detector.analyze(snapshot.string) {
                vault.stash(ProtectedSecret(text: snapshot.string, result: result, capturedAt: Date()))
                controller.writePlainText(ClipGuardMeta.placeholder)
            } else if vault.secret != nil {
                vault.reset() // 普通新内容取代受保护内容
            }
        } else if vault.secret != nil {
            vault.reset() // 非文本拷贝解除保护
        }
    }

    let changes = vault.tick()
    if changes.ttlExpired || changes.exposureEnded {
        controller.writePlainText(ClipGuardMeta.placeholder)
    }
}

/// 显式驱动轮询直到条件成立或超时
func waitUntil(deadline: TimeInterval = 2, condition: () -> Bool) {
    let start = Date()
    while Date().timeIntervalSince(start) < deadline {
        tick()
        if condition() { return }
        Thread.sleep(forTimeInterval: poll)
    }
}
func waitDuration(_ seconds: TimeInterval) {
    let start = Date()
    while Date().timeIntervalSince(start) < seconds {
        tick()
        Thread.sleep(forTimeInterval: poll)
    }
}

print("▌集成测试 1：银行卡号捕获 → 占位 → 恢复 → 自动收回")
let card = "4532 0151 1283 0366"
NSPasteboard.general.clearContents()
NSPasteboard.general.setString(card, forType: .string)
waitUntil { vault.state == .protected }
assert(vault.state == .protected, "保险箱进入 protected，实际 \(vault.state)")
assert(pbString() == ClipGuardMeta.placeholder, "剪贴板已被占位符替换")
assert(pbString()?.contains(card) != true, "明文卡号已不在剪贴板上")

// 模拟用户在目标 App 按 ⌘V（生产代码里由 InputEventTap 触发）
if let secret = vault.secret {
    vault.expose(window: exposure)
    controller.writePlainText(secret.text)
}
assert(pbString() == card, "暴露窗口内可粘贴原始卡号")
waitDuration(exposure + 0.3)
assert(vault.state == .protected, "暴露窗口结束自动收回，实际 \(vault.state)")
assert(pbString() == ClipGuardMeta.placeholder, "收回后剪贴板恢复为占位符")
assert(vault.secret != nil, "收回后明文仍保留在内存保险箱")

print("▌集成测试 2：TTL 到期彻底清除")
waitDuration(ttl + 0.3)
assert(vault.state == .empty, "TTL 后保险箱清空，实际 \(vault.state)")
assert(vault.secret == nil, "明文已从内存释放")
assert(pbString() == ClipGuardMeta.placeholder, "剪贴板只留占位符")

print("▌集成测试 3：普通内容不干预，且解除旧保护")
NSPasteboard.general.clearContents()
NSPasteboard.general.setString("Sk-12345678901234567890abcdefghij", forType: .string) // 高熵令牌
waitUntil { vault.state == .protected }
assert(vault.state == .protected, "令牌被保护，实际 \(vault.state)")
NSPasteboard.general.clearContents()
NSPasteboard.general.setString("晚上一起吃饭吗", forType: .string)
waitUntil { vault.state == .empty }
assert(vault.state == .empty, "普通复制解除旧保护，实际 \(vault.state)")
assert(pbString() == "晚上一起吃饭吗", "普通内容原样保留在剪贴板")

print("▌集成测试 4：自写不计为外部变更（防止占位/恢复自我触发死循环）")
let before = controller.lastSeenChangeCount
controller.writePlainText(ClipGuardMeta.placeholder)
assert(controller.pollForExternalChange() == false, "自己的占位写入不产生外部事件")
controller.writePlainText(card)
assert(controller.pollForExternalChange() == false, "自己的恢复写入不产生外部事件")
assert(controller.lastSeenChangeCount >= before, "changeCount 基线正常推进")

print("▌集成测试 5：私钥（PEM）捕获与逐字节恢复")
vault.reset()
let pem = """
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt
cmNhLXN1Y2Mtc2hhMi1uaXN0cDI1NgAAACg8m4FfakefakefakefakefakefakeAAAAA
-----END OPENSSH PRIVATE KEY-----
"""
NSPasteboard.general.clearContents()
NSPasteboard.general.setString(pem, forType: .string)
waitUntil { vault.state == .protected }
assert(vault.state == .protected, "PEM 私钥被保护，实际 \(vault.state)")
assert(vault.secret?.result.kind == .privateKey, "分类为私钥，实际 \(vault.secret?.result.kind.rawValue ?? "nil")")
if let secret = vault.secret {
    vault.expose(window: exposure)
    controller.writePlainText(secret.text)
    assert(pbString() == pem, "恢复内容与原始私钥逐字节一致")
}

print("▌集成测试 6：非文本（文件 URL）拷贝不干预")
waitDuration(ttl + 0.3) // 先清空
NSPasteboard.general.clearContents()
let item = NSPasteboardItem()
item.setString("file:///tmp/demo.txt", forType: .fileURL)
NSPasteboard.general.writeObjects([item])
waitDuration(0.3)
assert(vault.state == .empty, "文件 URL 拷贝不触发保护，实际 \(vault.state)")

print("\n────────────")
if failures == 0 {
    print("集成测试全部通过 ✅")
    exit(0)
} else {
    print("集成测试失败 \(failures) 项 ❌")
    exit(1)
}
