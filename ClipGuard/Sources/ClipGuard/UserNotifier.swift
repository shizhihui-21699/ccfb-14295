import AppKit
import UserNotifications
import ClipGuardCore

/// 提醒通道：优先 UserNotifications 系统通知；
/// 未打包成 .app（SPM 裸二进制）时系统通知无法投递，自动降级为提示音 + 日志 + 菜单栏红点，
/// 保证信息不丢且绝不使用模态弹窗阻塞主线程（避免影响复制粘贴）。
public protocol AlertNotifying: AnyObject {
    func alert(title: String, body: String)
}

public final class UserNotifier: AlertNotifying {
    private let log: EventLog
    private var notificationAvailable = false

    public init(log: EventLog) {
        self.log = log
        prepare()
    }

    private var isBundled: Bool {
        Bundle.main.bundleIdentifier != nil
    }

    private func prepare() {
        guard isBundled else {
            log.append(.warning, "当前为裸命令行二进制，系统通知不可用；告警将以提示音 + 菜单栏红点 + 日志呈现。打包成 .app 后可获得完整通知。")
            return
        }
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { [weak self] granted, error in
            DispatchQueue.main.async {
                self?.notificationAvailable = granted
                if let error {
                    self?.log.append(.warning, "通知授权失败：\(error.localizedDescription)")
                } else if !granted {
                    self?.log.append(.warning, "未授予通知权限，告警仅在菜单栏展示")
                }
            }
        }
    }

    public func alert(title: String, body: String) {
        log.append(.alert, "\(title) — \(body.replacingOccurrences(of: "\n", with: " | "))")
        // 非阻塞提示音，不占用 RunLoop
        NSSound(named: .init("Basso"))?.play()

        guard isBundled, notificationAvailable else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let request = UNNotificationRequest(
            identifier: UUID().uuidString, content: content,
            trigger: UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)
        )
        UNUserNotificationCenter.current().add(request)
    }
}
