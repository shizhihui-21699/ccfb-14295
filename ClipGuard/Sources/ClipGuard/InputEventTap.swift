import AppKit
import ClipGuardCore
import CoreGraphics

/// 通过 CGEventTap 监听全局 ⌘C / ⌘X / ⌘V。
/// 需要「辅助功能」权限（用户在系统设置里授权，不需要 root / 管理员）。
/// 事件只做手势识别，永远 passThrough，不拦截、不修改，不影响正常复制粘贴。
public final class InputEventTap {
    public var onCopyGesture: (() -> Void)?
    public var onPasteGesture: (() -> Void)?

    private var eventTap: CFMachPort?
    private var runLoopSource: CFRunLoopSource?
    private var commandDown = false

    public static var isTrusted: Bool { AXIsProcessTrusted() }

    /// 启动监听；权限不足或创建失败返回 false（调用方降级为 App 切换模式）
    @discardableResult
    public func start() -> Bool {
        guard Self.isTrusted else { return false }

        let mask = (1 << CGEventType.keyDown.rawValue)
            | (1 << CGEventType.flagsChanged.rawValue)
            | (1 << CGEventType.tapDisabledByTimeout.rawValue)

        // self 在回调期间由 coordinator 强持有，tap 停止前不会释放
        let userInfo = Unmanaged.passUnretained(self).toOpaque()
        guard let tap = CGEvent.tapCreate(
            tap: .cgSessionEventTap,
            place: .headInsertEventTap,
            options: .listenOnly,       // 只听，不拦截
            eventsOfInterest: CGEventMask(mask),
            callback: { _, type, event, refcon in
                guard let refcon else { return Unmanaged.passUnretained(event) }
                let owner = Unmanaged<InputEventTap>.fromOpaque(refcon).takeUnretainedValue()
                owner.handle(type: type, event: event)
                return Unmanaged.passUnretained(event) // 原样放行
            },
            userInfo: userInfo
        ) else { return false }

        eventTap = tap
        let source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0)
        runLoopSource = source
        CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes)
        CGEvent.tapEnable(tap: tap, enable: true)
        return true
    }

    public func stop() {
        if let tap = eventTap { CGEvent.tapEnable(tap: tap, enable: false) }
        if let source = runLoopSource { CFRunLoopRemoveSource(CFRunLoopGetMain(), source, .commonModes) }
        eventTap = nil
        runLoopSource = nil
    }

    private func handle(type: CGEventType, event: CGEvent) {
        if type == .tapDisabledByTimeout, let tap = eventTap {
            CGEvent.tapEnable(tap: tap, enable: true)
            return
        }
        guard type == .keyDown || type == .flagsChanged else { return }

        let flags = event.flags
        commandDown = flags.contains(.maskCommand)

        guard type == .keyDown, commandDown else { return }
        let keyCode = event.getIntegerValueField(.keyboardEventKeycode)
        // 虚拟键码：0=C, 7=X, 9=V
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            switch keyCode {
            case 0, 7: self.onCopyGesture?()
            case 9: self.onPasteGesture?()
            default: break
            }
        }
    }
}
