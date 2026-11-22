import Foundation

/// 可观测的间接信号类型。
/// 注意：macOS 没有任何公开 API 告知「哪个进程读取了剪贴板」，
/// 因此本引擎只使用这些能被第三方 App 观测到的信号做推断。
public enum AppEventKind: String, Sendable {
    /// 用户按下了 ⌘C / ⌘X（需要辅助功能权限；没有权限时该类事件缺失）
    case copyGesture
    /// 用户按下了 ⌘V
    case pasteGesture
    /// 前台 App 发生切换
    case appSwitch
    /// changeCount 增加，但近期没有对应的用户复制手势 —— 某个程序自己写了剪贴板
    case unexpectedWrite
    /// 受保护内容对该 App 进入过暴露窗口
    case protectedExposure
}

public struct AppEvent: Sendable, Equatable {
    public let app: String
    public let kind: AppEventKind
    public let time: Date

    public init(app: String, kind: AppEventKind, time: Date) {
        self.app = app
        self.kind = kind
        self.time = time
    }
}

public enum SuspicionSeverity: String, Codable, Sendable {
    case info, medium, high, critical

    public var label: String {
        switch self {
        case .info: return "观察"
        case .medium: return "可疑"
        case .high: return "高度可疑"
        case .critical: return "严重"
        }
    }
}

public struct RuleHit: Equatable, Sendable {
    public let rule: String
    public let delta: Int
    public let severity: SuspicionSeverity
    public let reason: String
}

public struct SuspicionAlert: Identifiable, Sendable, Equatable {
    public let id: UUID
    public let app: String
    public let score: Int
    public let severity: SuspicionSeverity
    public let hits: [RuleHit]
    public let at: Date

    public init(id: UUID = UUID(), app: String, score: Int,
                severity: SuspicionSeverity, hits: [RuleHit], at: Date) {
        self.id = id
        self.app = app
        self.score = score
        self.severity = severity
        self.hits = hits
        self.at = at
    }

    public var reasonText: String {
        hits.map { "· [\($0.rule) +\($0.delta)] \($0.reason)" }.joined(separator: "\n")
    }
}

/// 可疑行为推断引擎（纯逻辑，时间显式注入）
///
/// 评分窗口固定 10 分钟，分数完全由窗口内事件重算，天然具备时间衰减；
/// 超过阈值且过了冷却时间才产出一条提醒，避免骚扰。
public final class SuspicionEngine {
    /// 评分窗口
    public let window: TimeInterval = 600
    private var events: [AppEvent] = []
    private var lastAlertAt: [String: Date] = [:]
    private let alertThreshold: Int
    private let alertCooldown: TimeInterval
    private let clock: () -> Date

    public init(alertThreshold: Int = 60,
                alertCooldown: TimeInterval = 300,
                clock: @escaping () -> Date = Date.init) {
        self.alertThreshold = alertThreshold
        self.alertCooldown = alertCooldown
        self.clock = clock
    }

    /// 记录一个事件并按需产出提醒
    @discardableResult
    public func record(_ event: AppEvent) -> SuspicionAlert? {
        let now = clock()
        events.append(event)
        prune(now: now)
        let (score, hits) = Self.evaluate(app: event.app, events: events, now: now)
        guard score >= alertThreshold, !hits.isEmpty else { return nil }
        if let last = lastAlertAt[event.app],
           now.timeIntervalSince(last) < alertCooldown { return nil }
        lastAlertAt[event.app] = now
        let severity: SuspicionSeverity =
            score >= 90 ? .critical : score >= 60 ? .high : .medium
        return SuspicionAlert(app: event.app, score: score,
                              severity: severity, hits: hits, at: now)
    }

    /// 查询当前某 App 的分数（菜单栏 / 测试用）
    public func currentScore(app: String) -> (score: Int, hits: [RuleHit]) {
        Self.evaluate(app: app, events: events, now: clock())
    }

    private func prune(now: Date) {
        let cutoff = now.addingTimeInterval(-window)
        // 保留窗口内（time > cutoff）的事件，丢弃过期事件
        events.removeAll { $0.time <= cutoff }
    }

    // MARK: - 规则评估（静态纯函数，便于单测）

    public static func evaluate(app: String, events all: [AppEvent], now: Date)
    -> (score: Int, hits: [RuleHit]) {
        let mine = all.filter { $0.app == app && $0.time <= now }
        var hits: [RuleHit] = []

        // 规则 1：短时间内高频前后台切换 —— 剪贴板爬虫的典型行为模式
        let switches60 = mine.filter {
            $0.kind == .appSwitch && now.timeIntervalSince($0.time) <= 60
        }.count
        if switches60 >= 8 {
            hits.append(RuleHit(rule: "高频切换", delta: 60, severity: .high,
                                reason: "60 秒内前后台切换 \(switches60) 次，符合剪贴板爬虫轮询特征"))
        } else if switches60 >= 5 {
            hits.append(RuleHit(rule: "高频切换", delta: 30, severity: .medium,
                                reason: "60 秒内前后台切换 \(switches60) 次"))
        }

        // 规则 2：没有用户复制手势，剪贴板却被改写 —— 程序自行写入（剪贴板劫持 / 投毒前兆）
        let unexpected = mine.filter { $0.kind == .unexpectedWrite }
        if !unexpected.isEmpty {
            let recent = unexpected.filter { now.timeIntervalSince($0.time) <= 300 }
            let delta = min(70, recent.count * 30)
            hits.append(RuleHit(
                rule: "无手势写入", delta: delta,
                severity: recent.count >= 2 ? .high : .medium,
                reason: "5 分钟内发现 \(recent.count) 次剪贴板变更无法对应任何 ⌘C/⌘X 操作，疑似后台程序写入（系统不公开写入者身份，当前前台为 \(app)）"
            ))
        }

        // 规则 3：写入紧贴用户复制动作（0.3~1.5 秒内）—— 劫持/替换用户复制内容
        let copyTimes = all.filter { $0.kind == .copyGesture }.map(\.time)
        let hijack = unexpected.filter { u in
            copyTimes.contains { c in
                let gap = u.time.timeIntervalSince(c)
                return gap >= 0.3 && gap <= 1.5
            }
        }.count
        if hijack > 0 {
            let delta = min(60, hijack * 30)
            hits.append(RuleHit(rule: "复制劫持", delta: delta, severity: .high,
                                reason: "\(hijack) 次剪贴板改写紧跟在用户 ⌘C 之后 1.5 秒内，疑似劫持复制内容"))
        }

        // 规则 4：受保护内容对该 App 的暴露次数异常（用户不会在 60 秒内粘贴这么多次）
        let exposures60 = mine.filter {
            $0.kind == .protectedExposure && now.timeIntervalSince($0.time) <= 60
        }.count
        if exposures60 >= 5 {
            hits.append(RuleHit(rule: "频繁暴露", delta: 60, severity: .high,
                                reason: "60 秒内受保护内容对该 App 暴露 \(exposures60) 次，疑似借窗口反复读取"))
        } else if exposures60 >= 3 {
            hits.append(RuleHit(rule: "频繁暴露", delta: 30, severity: .medium,
                                reason: "60 秒内受保护内容对该 App 暴露 \(exposures60) 次"))
        }

        let score = min(100, hits.reduce(0) { $0 + $1.delta })
        return (score, hits)
    }
}
