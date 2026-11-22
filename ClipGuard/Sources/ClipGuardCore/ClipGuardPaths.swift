import Foundation

/// 运行期文件存储位置解析。
/// 默认 ~/.clipguard；设置 CLIPGUARD_HOME 环境变量可整体重定向
/// （用于企业集中部署、隔离测试与多实例运行）。
public enum ClipGuardPaths {
    /// 环境变量名
    public static let envOverride = "CLIPGUARD_HOME"

    /// 配置 / 日志所在目录
    public static func directory() -> URL {
        if let custom = ProcessInfo.processInfo.environment[envOverride], !custom.isEmpty {
            return URL(fileURLWithPath: custom, isDirectory: true)
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".clipguard", isDirectory: true)
    }

    public static func configURL() -> URL {
        directory().appendingPathComponent("config.json")
    }

    public static func eventsURL() -> URL {
        directory().appendingPathComponent("events.jsonl")
    }

    public static func ensureDirectoryExists() {
        try? FileManager.default.createDirectory(at: directory(),
                                                 withIntermediateDirectories: true)
    }
}
