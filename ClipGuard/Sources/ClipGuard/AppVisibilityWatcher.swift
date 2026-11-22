import AppKit
import ClipGuardCore

/// 前后台 App 监视器。
/// macOS 不提供「剪贴板读取者」通知，前台 App 切换是推断用户粘贴意图的主要间接信号。
public final class AppVisibilityWatcher {
    public struct FrontApp: Equatable, Sendable {
        public let id: String        // bundle id，拿不到时用 pid:xxx
        public let name: String      // 展示名
        public let pid: pid_t
    }

    private var timer: Timer?
    private(set) var frontmost: FrontApp?
    /// 切换回调：newApp, previousApp
    public var onChange: ((FrontApp, FrontApp?) -> Void)?

    public static func current() -> FrontApp? {
        guard let app = NSWorkspace.shared.frontmostApplication else { return nil }
        let id = app.bundleIdentifier ?? "pid:\(app.processIdentifier)"
        return FrontApp(id: id, name: app.localizedName ?? id, pid: app.processIdentifier)
    }

    public func start(interval: TimeInterval = 0.25) {
        frontmost = Self.current()
        let t = Timer(timeInterval: interval, repeats: true) { [weak self] _ in
            self?.check()
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    public func stop() { timer?.invalidate(); timer = nil }

    private func check() {
        guard let current = Self.current() else { return }
        guard current != frontmost else { return }
        let previous = frontmost
        frontmost = current
        onChange?(current, previous)
    }
}
