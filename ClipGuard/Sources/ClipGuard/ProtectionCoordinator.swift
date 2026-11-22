import AppKit
import ClipGuardCore

/// 中央协调器：把剪贴板轮询、手势监听、App 切换、保险箱、推断引擎、告警串成一个状态机。
/// 约定：所有入口（Timer、事件回调）都在主线程 RunLoop 上串行执行，避免竞态。
public final class ProtectionCoordinator {
    public var config: GuardConfig
    private let detector: SensitivityDetector
    private let vault: SecretVault
    private let engine: SuspicionEngine
    private let log: EventLog
    private let pasteboard: PasteboardController
    private let visibility: AppVisibilityWatcher
    private let eventTap: InputEventTap
    private let notifier: UserNotifier

    private var pollTimer: Timer?
    private var uiTimer: Timer?
    private(set) var paused = false
    /// 是否具备辅助功能权限（决定精确 ⌘V 模式还是 App 切换降级模式）
    private(set) var tapActive = false
    /// 最近一次用户 ⌘C/⌘X 的时间，用于识别「无手势写入」
    private var lastUserCopyAt: Date?
    /// 最近一次告警（菜单栏红点）
    private(set) var lastAlert: SuspicionAlert?
    /// 受保护内容的原始富文本快照（纯内存，随清除一起释放）
    private var currentSnapshot: PasteboardController.Snapshot?
    /// 状态栏刷新回调
    public var onStatusChange: (() -> Void)?

    public var vaultState: VaultState { vault.state }
    public var currentSecretPreview: String? { vault.secret?.result.preview }

    public init(config: GuardConfig, log: EventLog) {
        self.config = config
        self.detector = SensitivityDetector(config: config.detector)
        self.vault = SecretVault(ttl: config.ttl, exposureWindow: config.exposureWindow)
        self.engine = SuspicionEngine(alertThreshold: config.alertThreshold,
                                      alertCooldown: config.alertCooldown)
        self.log = log
        self.pasteboard = PasteboardController()
        self.visibility = AppVisibilityWatcher()
        self.eventTap = InputEventTap()
        self.notifier = UserNotifier(log: log)
    }

    // MARK: 生命周期

    public func start() {
        // 前后台切换
        visibility.onChange = { [weak self] newApp, prev in
            self?.handleAppSwitch(new: newApp, previous: prev)
        }
        visibility.start()

        // 全局手势（权限不足则降级）
        eventTap.onCopyGesture = { [weak self] in self?.handleCopyGesture() }
        eventTap.onPasteGesture = { [weak self] in self?.handlePasteGesture() }
        tapActive = eventTap.start()
        if tapActive {
            log.append(.info, "辅助功能权限已授权：启用精确 ⌘V 粘贴模式，暴露窗口 \(config.exposureWindow)s")
        } else {
            log.append(.warning,
                "未授予辅助功能权限：降级为 App 切换模式（切到目标 App 即恢复，窗口 \(config.fallbackExposureWindow)s）。" +
                "可在系统设置 → 隐私与安全性 → 辅助功能 中授权以获得更短暴露窗口。")
        }

        // 剪贴板轮询
        let poll = Timer(timeInterval: config.pollInterval, repeats: true) { [weak self] _ in
            self?.tick()
        }
        RunLoop.main.add(poll, forMode: .common)
        pollTimer = poll

        // 菜单状态刷新
        let ui = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            self?.onStatusChange?()
        }
        RunLoop.main.add(ui, forMode: .common)
        uiTimer = ui

        log.append(.info, "ClipGuard 已启动，TTL=\(Int(config.ttl))s，检测类别：\(enabledKinds())")
    }

    public func stop() {
        pollTimer?.invalidate()
        uiTimer?.invalidate()
        eventTap.stop()
        visibility.stop()
    }

    private func enabledKinds() -> String {
        let d = config.detector
        var parts: [String] = []
        if d.detectBankCard { parts.append("银行卡") }
        if d.detectPrivateKey { parts.append("私钥") }
        if d.detectMnemonic { parts.append("助记词") }
        if d.detectApiToken { parts.append("API令牌") }
        if d.detectPassword { parts.append("口令") }
        if d.detectOneTimeCode { parts.append("验证码") }
        return parts.joined(separator: "/")
    }

    // MARK: 轮询：TTL / 暴露窗口 / 外部写入

    private func tick() {
        guard !paused else { return }

        // 1) 优先消费外部剪贴板写入。
        //    必须先于 TTL/窗口写回：若用户恰好在 TTL 到期的同一轮复制了新内容，
        //    先写占位符会把用户的新复制覆盖掉。
        if pasteboard.pollForExternalChange() {
            handleExternalPasteboardWrite()
        }

        // 2) 保险箱时间驱动（此时剪贴板上若已有新的用户内容，保险箱通常已被 handleExternal 清空）
        let changes = vault.tick()
        if changes.ttlExpired {
            currentSnapshot = nil
            pasteboard.writePlainText(ClipGuardMeta.placeholder)
            log.append(.protected, "受保护内容已到 TTL（\(Int(config.ttl))s），从内存与剪贴板清除")
            onStatusChange?()
        } else if changes.exposureEnded {
            pasteboard.writePlainText(ClipGuardMeta.placeholder)
            if config.soundOnRehide { NSSound(named: .init("Tink"))?.play() }
            log.append(.protected, "粘贴窗口结束，内容已重新隐藏")
            onStatusChange?()
        }
    }

    private func handleExternalPasteboardWrite() {
        guard pasteboard.hasTextualContent(),
              let snapshot = pasteboard.currentSnapshot() else {
            // 文件 / 图片等非文本：放弃当前保护，不干预用户正常使用
            if vault.secret != nil {
                vault.clear()
                currentSnapshot = nil
                log.append(.info, "检测到非文本拷贝，解除当前保护")
                onStatusChange?()
            }
            return
        }

        // 推断写入来源：系统不公开写入者，只能归因于当前前台 App
        let front = visibility.frontmost
        let appId = front?.id ?? "unknown"

        // 用户复制手势后 2 秒内的变更视为用户自己的复制；其余为「无手势写入」
        let isUserCopy: Bool
        if let last = lastUserCopyAt, Date().timeIntervalSince(last) <= 2.0 {
            isUserCopy = true
            lastUserCopyAt = nil
        } else {
            isUserCopy = false
        }

        // 受保护槽位被外部覆盖 —— 无论如何都算异常信号
        let overwroteProtectedSlot = vault.state == .exposed

        if !isUserCopy {
            recordSuspicion(.init(app: appId, kind: .unexpectedWrite, time: Date()))
            log.append(.warning,
                "检测到无复制手势的剪贴板写入（归因前台 App：\(front?.name ?? appId)）。系统不公开写入者身份，已计入可疑评分。",
                app: appId)
            if overwroteProtectedSlot {
                recordSuspicion(.init(app: appId, kind: .copyGesture, time: Date().addingTimeInterval(-0.4)))
            }
        }

        // 内容分析
        if let result = detector.analyze(snapshot.string) {
            vault.stash(.init(text: snapshot.string, result: result, capturedAt: Date()))
            currentSnapshot = snapshot
            pasteboard.writePlainText(ClipGuardMeta.placeholder)
            if config.soundOnCapture { NSSound(named: .init("Glass"))?.play() }
            log.append(.protected,
                "捕获敏感内容【\(result.kind.label)，置信度 \(Int(result.confidence * 100))%】\(result.preview)，已接管并隐藏，\(Int(config.ttl))s 后自动清除",
                app: appId)
        } else {
            // 普通内容：如果此前有受保护内容，说明用户复制了新东西，旧保护解除
            if vault.secret != nil {
                vault.clear()
                currentSnapshot = nil
                log.append(.info, "新的普通复制内容取代受保护内容，解除保护", app: appId)
            }
        }
        onStatusChange?()
    }

    // MARK: 用户手势

    private func handleCopyGesture() {
        lastUserCopyAt = Date()
        if let front = visibility.frontmost {
            recordSuspicion(.init(app: front.id, kind: .copyGesture, time: Date()))
        }
    }

    private func handlePasteGesture() {
        guard vault.state == .protected, let secret = vault.secret else { return }
        let app = visibility.frontmost
        vault.expose(window: config.exposureWindow)
        if let snapshot = currentSnapshot {
            pasteboard.write(snapshot: snapshot)
        } else {
            pasteboard.writePlainText(secret.text)
        }
        let appName = app?.name ?? "未知 App"
        log.append(.paste, "⌘V 触发：向【\(appName)】临时暴露【\(secret.result.kind.label)】，\(config.exposureWindow)s 后自动收回",
                   app: app?.id)
        if let app {
            recordSuspicion(.init(app: app.id, kind: .protectedExposure, time: Date()))
        }
        onStatusChange?()
    }

    // MARK: App 切换（降级模式的粘贴意图来源 + 高频切换信号）

    private func handleAppSwitch(new: AppVisibilityWatcher.FrontApp,
                                 previous: AppVisibilityWatcher.FrontApp?) {
        recordSuspicion(.init(app: new.id, kind: .appSwitch, time: Date()))

        guard !paused, vault.state == .protected, let secret = vault.secret else { return }
        if tapActive {
            // 精确模式：切换不恢复，等用户真正按 ⌘V
            return
        }
        // 降级模式：切到新 App 即视为粘贴意图
        vault.expose(window: config.fallbackExposureWindow)
        if let snapshot = currentSnapshot {
            pasteboard.write(snapshot: snapshot)
        } else {
            pasteboard.writePlainText(secret.text)
        }
        log.append(.paste,
            "切换到【\(new.name)】，临时暴露【\(secret.result.kind.label)】\(config.fallbackExposureWindow)s（无辅助功能权限的降级模式）",
            app: new.id)
        recordSuspicion(.init(app: new.id, kind: .protectedExposure, time: Date()))
        onStatusChange?()
    }

    // MARK: 菜单栏手动操作

    public func manualRestore() {
        guard vault.state == .protected, let secret = vault.secret else { return }
        vault.expose(window: config.exposureWindow)
        if let snapshot = currentSnapshot {
            pasteboard.write(snapshot: snapshot)
        } else {
            pasteboard.writePlainText(secret.text)
        }
        log.append(.paste, "手动恢复：内容暴露 \(config.exposureWindow)s，请立即 ⌘V")
        onStatusChange?()
    }

    public func manualClear() {
        guard vault.secret != nil else { return }
        vault.clear()
        currentSnapshot = nil
        pasteboard.writePlainText(ClipGuardMeta.placeholder)
        log.append(.protected, "用户手动清除受保护内容")
        onStatusChange?()
    }

    public func togglePause() {
        paused.toggle()
        if paused {
            log.append(.warning, "保护已暂停：剪贴板不再被接管（监控仍记录 App 切换）")
        } else {
            log.append(.info, "保护已恢复")
            pasteboard.resync()
        }
        onStatusChange?()
    }

    public var remainingTTLText: String? {
        guard let s = vault.remainingTTL else { return nil }
        return String(format: "%ds", Int(ceil(s)))
    }

    public var remainingExposureText: String? {
        guard let s = vault.remainingExposure else { return nil }
        return String(format: "%.1fs", s)
    }

    // MARK: 可疑推断

    private func recordSuspicion(_ event: AppEvent) {
        if let alert = engine.record(event) {
            lastAlert = alert
            let front = visibility.frontmost
            let title = "可疑剪贴板访问：\(front?.name ?? alert.app)（\(alert.severity.label) \(alert.score)分）"
            notifier.alert(title: title, body: alert.reasonText)
            onStatusChange?()
        }
    }

    public func scoreForFrontApp() -> Int? {
        guard let app = visibility.frontmost else { return nil }
        return engine.currentScore(app: app.id).score
    }
}
