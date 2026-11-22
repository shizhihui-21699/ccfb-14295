import Foundation

public enum EventLevel: String, Codable, Sendable {
    case info, protected, paste, alert, warning
}

/// 一条审计事件。敏感内容一律以脱敏预览形式出现，绝不记录明文。
public struct EventEntry: Codable, Sendable, Identifiable, Equatable {
    public let id: UUID
    public let timestamp: Date
    public let level: EventLevel
    public let message: String
    /// 涉及的 App（bundle id 优先，拿不到时用进程名）
    public let app: String?

    public init(id: UUID = UUID(),
                timestamp: Date = Date(),
                level: EventLevel,
                message: String,
                app: String? = nil) {
        self.id = id
        self.timestamp = timestamp
        self.level = level
        self.message = message
        self.app = app
    }
}

/// 环形内存日志 + 可选 JSONL 落盘（只落脱敏事件，不落敏感明文）
public final class EventLog {
    private let capacity: Int
    private let fileURL: URL?
    private let queue = DispatchQueue(label: "clipguard.eventlog")
    private var entries: [EventEntry] = []
    private let isoFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    public init(capacity: Int = 500, fileURL: URL? = nil) {
        self.capacity = capacity
        self.fileURL = fileURL
        if let fileURL {
            try? FileManager.default.createDirectory(
                at: fileURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
        }
    }

    public static func defaultFileURL() -> URL {
        ClipGuardPaths.eventsURL()
    }

    public func append(_ level: EventLevel, _ message: String, app: String? = nil) {
        let entry = EventEntry(level: level, message: message, app: app)
        queue.sync {
            entries.append(entry)
            if entries.count > capacity { entries.removeFirst(entries.count - capacity) }
            guard let fileURL else { return }
            guard let data = try? JSONEncoder().encode(entry) else { return }
            let line = data + Data([0x0A])
            if FileManager.default.fileExists(atPath: fileURL.path) {
                if let handle = try? FileHandle(forWritingTo: fileURL) {
                    defer { try? handle.close() }
                    _ = try? handle.seekToEnd()
                    try? handle.write(contentsOf: line)
                }
            } else {
                try? line.write(to: fileURL, options: .atomic)
            }
        }
    }

    public func snapshot() -> [EventEntry] {
        queue.sync { entries }
    }

    /// 导出最近 limit 条为文本（供 --log 查看）
    public func recentText(limit: Int = 30) -> String {
        let rows = Array(snapshot().suffix(limit))
        let df = DateFormatter()
        df.dateFormat = "MM-dd HH:mm:ss"
        return rows.map { e in
            let tag: String
            switch e.level {
            case .info: tag = "ℹ️ "
            case .protected: tag = "🔒"
            case .paste: tag = "📋"
            case .alert: tag = "🚨"
            case .warning: tag = "⚠️ "
            }
            let app = e.app.map { "[\($0)] " } ?? ""
            return "\(df.string(from: e.timestamp)) \(tag) \(app)\(e.message)"
        }.joined(separator: "\n")
    }
}
