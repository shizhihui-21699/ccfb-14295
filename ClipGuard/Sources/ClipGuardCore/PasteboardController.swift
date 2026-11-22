import AppKit

/// NSPasteboard 封装：
/// 1) 区分「自己写入」与「外部写入」—— changeCount 是唯一可用的变化信号
/// 2) 快照 / 恢复富文本类型，保证粘贴时不丢格式
public final class PasteboardController {
    private let pb = NSPasteboard.general
    /// 已处理过的最新 changeCount
    public private(set) var lastSeenChangeCount: Int
    /// 自己写入产生的 changeCount 集合，用于排除自触发
    private var selfWrites = Set<Int>()

    /// 可快照的文本类类型（文件 URL 等非文本内容不纳入保护）
    private let supportedTypes: Set<NSPasteboard.PasteboardType> = [
        .string, .rtf, .rtfd, .html, .tabularText, .URL
    ]

    public struct Snapshot: Sendable {
        public let string: String
        public let items: [(type: String, data: Data)]

        public var hasRichContent: Bool {
            items.contains { $0.type != NSPasteboard.PasteboardType.string.rawValue }
        }
    }

    public init() {
        lastSeenChangeCount = pb.changeCount
    }

    /// 把基线同步到当前 changeCount（恢复保护时跳过暂停期间的变更）
    public func resync() {
        selfWrites.removeAll()
        lastSeenChangeCount = pb.changeCount
    }

    /// 轮询 changeCount；返回 true 表示发生了「外部」写入
    public func pollForExternalChange() -> Bool {
        let cc = pb.changeCount
        guard cc != lastSeenChangeCount else { return false }
        lastSeenChangeCount = cc
        if selfWrites.remove(cc) != nil {
            return false // 是我们自己的写入
        }
        // 外部写入可能跨过了自写计数（对方在我们之后又写了一次），清理残留
        selfWrites.removeAll()
        return true
    }

    /// 当前剪贴板是否为可分析的文本内容（文件 / 图片拷贝不干预）
    public func hasTextualContent() -> Bool {
        guard let items = pb.pasteboardItems, !items.isEmpty else { return false }
        if pb.types?.contains(.fileURL) == true || pb.types?.contains(.png) == true
            || pb.types?.contains(.tiff) == true {
            return false
        }
        return pb.string(forType: .string) != nil
    }

    public func currentSnapshot() -> Snapshot? {
        guard let item = pb.pasteboardItems?.first,
              let string = pb.string(forType: .string) else { return nil }
        var collected: [(type: String, data: Data)] = []
        for type in item.types where supportedTypes.contains(type) {
            if let data = item.data(forType: type) {
                collected.append((type.rawValue, data))
            }
        }
        // 至少保证有纯文本
        if !collected.contains(where: { $0.type == NSPasteboard.PasteboardType.string.rawValue }),
           let data = string.data(using: .utf8) {
            collected.append((NSPasteboard.PasteboardType.string.rawValue, data))
        }
        return Snapshot(string: string, items: collected)
    }

    /// 写入纯文本（占位符用）
    public func writePlainText(_ text: String) {
        pb.clearContents()
        pb.setString(text, forType: .string)
        markSelfWrite()
    }

    /// 按快照完整恢复（保留 RTF/HTML 等富文本格式）
    public func write(snapshot: Snapshot) {
        pb.clearContents()
        if snapshot.hasRichContent, let item = NSPasteboardItem() as NSPasteboardItem? {
            for entry in snapshot.items {
                item.setData(entry.data, forType: NSPasteboard.PasteboardType(entry.type))
            }
            pb.writeObjects([item])
        } else {
            pb.setString(snapshot.string, forType: .string)
        }
        markSelfWrite()
    }

    private func markSelfWrite() {
        selfWrites.insert(pb.changeCount)
        lastSeenChangeCount = pb.changeCount
    }
}
