import AppKit
import ClipGuardCore

/// 菜单栏图标（NSStatusItem）。常驻工具栏，不占 Dock。
@MainActor
public final class StatusBarController {
    private let item: NSStatusItem
    private weak var coordinator: ProtectionCoordinator?
    private let log: EventLog

    public init(coordinator: ProtectionCoordinator, log: EventLog) {
        self.coordinator = coordinator
        self.log = log
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.image = NSImage(systemSymbolName: "lock.shield", accessibilityDescription: "ClipGuard")
        item.button?.image?.isTemplate = true
        rebuildMenu()
    }

    public func refresh() {
        updateIcon()
        rebuildMenu()
    }

    private func updateIcon() {
        guard let coordinator else { return }
        let name: String
        if coordinator.paused {
            name = "pause.circle"
        } else if coordinator.lastAlert != nil {
            name = "exclamationmark.shield"
        } else if coordinator.vaultState == .exposed {
            name = "lock.open"
        } else if coordinator.vaultState == .protected {
            name = "lock.shield.fill"
        } else {
            name = "lock.shield"
        }
        item.button?.image = NSImage(systemSymbolName: name, accessibilityDescription: "ClipGuard")
        item.button?.image?.isTemplate = true
    }

    private func rebuildMenu() {
        let menu = NSMenu()
        guard let coordinator else {
            item.menu = menu
            return
        }

        // 状态头部
        let title: String
        switch coordinator.vaultState {
        case .empty, .expired:
            title = coordinator.paused ? "⏸ 保护已暂停" : "✅ 监控中（当前无敏感内容）"
        case .protected:
            title = "🔒 已保护：\(coordinator.currentSecretPreview ?? "敏感内容")（剩余 \(coordinator.remainingTTLText ?? "-")）"
        case .exposed:
            title = "📋 暴露中：\(coordinator.remainingExposureText ?? "-") 后自动收回"
        }
        let header = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        header.isEnabled = false
        menu.addItem(header)

        if let score = coordinator.scoreForFrontApp(), score > 0 {
            let scoreItem = NSMenuItem(
                title: "当前前台 App 可疑评分：\(score)/100",
                action: nil, keyEquivalent: "")
            scoreItem.isEnabled = false
            menu.addItem(scoreItem)
        }
        menu.addItem(.separator())

        let restore = NSMenuItem(title: "立即恢复（准备粘贴）", action: #selector(restoreAction), keyEquivalent: "r")
        restore.target = self
        restore.isEnabled = coordinator.vaultState == .protected
        menu.addItem(restore)

        let clear = NSMenuItem(title: "立即清除受保护内容", action: #selector(clearAction), keyEquivalent: "d")
        clear.target = self
        clear.isEnabled = coordinator.vaultState != .empty
        menu.addItem(clear)

        let pause = NSMenuItem(
            title: coordinator.paused ? "恢复保护" : "暂停保护",
            action: #selector(pauseAction), keyEquivalent: "p")
        pause.target = self
        menu.addItem(pause)
        menu.addItem(.separator())

        // 最近告警
        if let alert = coordinator.lastAlert {
            let alertItem = NSMenuItem(
                title: "最近告警：\(alert.severity.label)（\(alert.score)分）→ \(alert.app)",
                action: nil, keyEquivalent: "")
            alertItem.isEnabled = false
            menu.addItem(alertItem)
        }

        // 最近日志（最多 8 条）
        let recent = Array(log.snapshot().suffix(8).reversed())
        if !recent.isEmpty {
            let logHeader = NSMenuItem(title: "最近事件", action: nil, keyEquivalent: "")
            logHeader.isEnabled = false
            menu.addItem(logHeader)
            for entry in recent {
                let short = entry.message.count > 60
                    ? String(entry.message.prefix(60)) + "…"
                    : entry.message
                let m = NSMenuItem(title: "· \(short)", action: nil, keyEquivalent: "")
                m.isEnabled = false
                menu.addItem(m)
            }
        }
        menu.addItem(.separator())

        let quit = NSMenuItem(title: "退出 ClipGuard", action: #selector(quitAction), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
        item.menu = menu
    }

    @objc private func restoreAction() { coordinator?.manualRestore() }
    @objc private func clearAction() { coordinator?.manualClear() }
    @objc private func pauseAction() { coordinator?.togglePause() }
    @objc private func quitAction() { NSApp.terminate(nil) }
}
