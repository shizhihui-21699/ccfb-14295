import Foundation

/// 保险箱当前状态
public enum VaultState: String, Sendable, Equatable {
    case empty        // 没有受保护内容
    case protected    // 内容在内存中，剪贴板上是占位符
    case exposed      // 内容暂时回到剪贴板，等待用户粘贴
    case expired      // 内容已到期清除
}

/// 受保护的一条敏感内容。只存在内存里，从不落盘。
public struct ProtectedSecret: Sendable, Equatable {
    public let text: String
    public let result: SensitivityResult
    public let capturedAt: Date

    public init(text: String, result: SensitivityResult, capturedAt: Date) {
        self.text = text
        self.result = result
        self.capturedAt = capturedAt
    }
}

/// 内存保险箱 + 暴露窗口状态机（纯逻辑 + 显式注入时间，便于单测）
public final class SecretVault {
    public private(set) var secret: ProtectedSecret?
    public private(set) var state: VaultState = .empty
    /// 进入 exposed 的时刻；protected/empty 时为 nil
    public private(set) var exposedAt: Date?
    /// 本次暴露实际使用的窗口（降级模式下比默认窗口长）
    private var activeExposureWindow: TimeInterval?
    private let ttl: TimeInterval
    private let exposureWindow: TimeInterval
    private let now: () -> Date

    public init(ttl: TimeInterval,
                exposureWindow: TimeInterval,
                clock: @escaping () -> Date = Date.init) {
        self.ttl = ttl
        self.exposureWindow = exposureWindow
        self.now = clock
    }

    /// 保存新的敏感内容（重复复制同类内容会覆盖并刷新 TTL）
    public func stash(_ secret: ProtectedSecret) {
        self.secret = secret
        self.state = .protected
        self.exposedAt = nil
    }

    /// 暂时把内容放回剪贴板；window 为 nil 时使用默认暴露窗口
    public func expose(window: TimeInterval? = nil) {
        guard secret != nil else { return }
        state = .exposed
        exposedAt = now()
        activeExposureWindow = window
    }

    /// 粘贴窗口结束 / 切换到别的 App，重新藏起来
    public func rehide() {
        guard secret != nil else { return }
        if state == .exposed { state = .protected }
        exposedAt = nil
        activeExposureWindow = nil
    }

    /// 立即清除
    public func clear() {
        secret = nil
        state = .empty
        exposedAt = nil
        activeExposureWindow = nil
    }

    /// 重置为全新实例的状态（测试 / 场景切换用，等价于重新创建）
    public func reset() {
        clear()
    }

    /// 周期性驱动：返回 true 表示刚刚发生了到期 / 窗口结束，调用方需要相应处理剪贴板
    @discardableResult
    public func tick() -> (ttlExpired: Bool, exposureEnded: Bool) {
        guard secret != nil else { return (false, false) }
        let current = now()
        if current.timeIntervalSince(secret!.capturedAt) >= ttl {
            clear()
            return (true, false)
        }
        if state == .exposed, let exposedAt {
            let window = activeExposureWindow ?? exposureWindow
            if current.timeIntervalSince(exposedAt) >= window {
                state = .protected
                self.exposedAt = nil
                activeExposureWindow = nil
                return (false, true)
            }
        }
        return (false, false)
    }

    /// 剩余 TTL 秒数（用于菜单栏倒计时）
    public var remainingTTL: TimeInterval? {
        guard let secret else { return nil }
        return max(0, ttl - now().timeIntervalSince(secret.capturedAt))
    }

    /// 剩余暴露窗口秒数
    public var remainingExposure: TimeInterval? {
        guard state == .exposed, let exposedAt else { return nil }
        let window = activeExposureWindow ?? exposureWindow
        return max(0, window - now().timeIntervalSince(exposedAt))
    }
}
