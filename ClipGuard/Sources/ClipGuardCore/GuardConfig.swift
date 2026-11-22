import Foundation

/// 工具运行配置。可通过 JSON 文件覆盖默认值（~/.clipguard/config.json）。
public struct GuardConfig: Codable, Equatable, Sendable {    /// 敏感内容在内存中的存活时间（秒）
    public var ttl: TimeInterval
    /// 按 ⌘V / 切到目标 App 后，内容在剪贴板上的暴露窗口（秒）
    public var exposureWindow: TimeInterval
    /// 无辅助功能权限时，App 切换后的暴露窗口（秒，通常略长以保证粘贴成功）
    public var fallbackExposureWindow: TimeInterval
    /// 轮询 NSPasteboard.changeCount 的间隔（秒）
    public var pollInterval: TimeInterval
    /// 可疑评分达到多少分弹提醒
    public var alertThreshold: Int
    /// 同一 App 同一规则的提醒冷却时间（秒）
    public var alertCooldown: TimeInterval
    /// 检测开关
    public var detector: DetectorConfig
    /// 是否在检测到敏感内容时播放系统提示音
    public var soundOnCapture: Bool
    /// 是否在暴露窗口结束时播放轻微提示音
    public var soundOnRehide: Bool

    public init(ttl: TimeInterval = 45,
                exposureWindow: TimeInterval = 1.2,
                fallbackExposureWindow: TimeInterval = 3.0,
                pollInterval: TimeInterval = 0.5,
                alertThreshold: Int = 60,
                alertCooldown: TimeInterval = 300,
                detector: DetectorConfig = .init(),
                soundOnCapture: Bool = true,
                soundOnRehide: Bool = false) {
        self.ttl = ttl
        self.exposureWindow = exposureWindow
        self.fallbackExposureWindow = fallbackExposureWindow
        self.pollInterval = pollInterval
        self.alertThreshold = alertThreshold
        self.alertCooldown = alertCooldown
        self.detector = detector
        self.soundOnCapture = soundOnCapture
        self.soundOnRehide = soundOnRehide
    }

    enum CodingKeys: String, CodingKey {
        case ttl, exposureWindow, fallbackExposureWindow, pollInterval
        case alertThreshold, alertCooldown, detector
        case soundOnCapture, soundOnRehide
    }

    /// 默认配置文件路径
    public static func defaultFileURL() -> URL {
        ClipGuardPaths.configURL()
    }

    /// 加载配置；文件不存在 / 解析失败时返回默认值（失败原因通过 error 回调给日志）
    public static func load(from url: URL = GuardConfig.defaultFileURL(),
                            onError: ((String) -> Void)? = nil) -> GuardConfig {
        guard FileManager.default.fileExists(atPath: url.path) else { return .init() }
        do {
            let data = try Data(contentsOf: url)
            return try JSONDecoder().decode(GuardConfig.self, from: data)
        } catch {
            onError?("配置文件解析失败，使用默认配置：\(error.localizedDescription)")
            return .init()
        }
    }

    public func save(to url: URL = GuardConfig.defaultFileURL()) throws {
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(self).write(to: url, options: .atomic)
    }
}
