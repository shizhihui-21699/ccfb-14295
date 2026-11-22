import Foundation

/// 剪贴板保护工具的全局常量
public enum ClipGuardMeta {
    /// 写入剪贴板占位内容时使用的固定文案。
    /// 检测逻辑会跳过与该文案完全相同的内容，避免把占位符误判为敏感数据。
    public static let placeholder =
        "🔒 ClipGuard 已保护该敏感内容：切换到目标 App 后按 ⌘V 粘贴，或点击菜单栏图标选择「立即恢复」"
}
