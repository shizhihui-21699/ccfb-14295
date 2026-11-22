import AppKit
import ClipGuardCore

// ClipGuard 主入口：菜单栏常驻代理，无 Dock 图标
@MainActor
enum Main {

    struct Options {
        var printLog = false
        var showConfig = false
        var writeDefaultConfig = false
        var help = false
    }

    static func parse() -> Options {
        var opts = Options()
        for arg in CommandLine.arguments.dropFirst() {
            switch arg {
            case "--log", "-l": opts.printLog = true
            case "--config": opts.showConfig = true
            case "--init-config": opts.writeDefaultConfig = true
            case "--help", "-h": opts.help = true
            default: break
            }
        }
        return opts
    }

    static func usage() {
        print("""
        ClipGuard — macOS 剪贴板敏感内容保护工具

        用法:
          clipguard                 启动菜单栏守护代理
          clipguard --log           打印最近审计事件后退出
          clipguard --config        打印当前配置后退出
          clipguard --init-config   写出默认配置到 ~/.clipguard/config.json
          clipguard --help          显示本帮助

        权限:
          无需管理员权限。授予「辅助功能」可启用精确 ⌘V 模式；
          不授权则自动降级为 App 切换模式。
        """)
    }

    static func run() async {
        let opts = parse()
        if opts.help { usage(); return }

        if opts.writeDefaultConfig {
            do {
                try GuardConfig().save()
                print("默认配置已写入 \(GuardConfig.defaultFileURL().path)")
            } catch {
                fputs("写配置失败：\(error.localizedDescription)\n", stderr)
                exit(1)
            }
            return
        }

        let log = EventLog(fileURL: EventLog.defaultFileURL())

        if opts.printLog {
            print(log.recentText(limit: 50))
            return
        }

        let config = GuardConfig.load { warning in
            log.append(.warning, warning)
        }

        if opts.showConfig {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            if let data = try? encoder.encode(config),
               let text = String(data: data, encoding: .utf8) {
                print(text)
            }
            return
        }

        // 菜单栏代理：不显示 Dock 图标
        NSApplication.shared.setActivationPolicy(.accessory)
        let app = NSApplication.shared
        let coordinator = ProtectionCoordinator(config: config, log: log)
        let statusBar = StatusBarController(coordinator: coordinator, log: log)
        coordinator.onStatusChange = { [weak statusBar] in
            statusBar?.refresh()
        }
        coordinator.start()
        statusBar.refresh()

        // 信号处理：退出前不需要特殊清理（内存中的秘密随进程消失）
        signal(SIGTERM) { _ in
            DispatchQueue.main.async { NSApp.terminate(nil) }
        }
        signal(SIGINT) { _ in
            DispatchQueue.main.async { NSApp.terminate(nil) }
        }

        app.run()
    }
}

await Main.run()
