import AppKit

// clip-thief —— 测试用的可疑"效率工具"模拟器
// 复现真实样本行为：后台高频读取剪贴板、抢前台轮询、无手势写入/劫持。
// 不申请任何权限（NSPasteboard 读取本身就不需要权限，这正是问题根源）。

enum ThiefMode: String {
    case watcher   // 后台持续读取剪贴板（真实抓到的那种）
    case once      // 只读一次
    case spammer   // 反复激活自己 + 读取，制造高频前后台切换信号
    case hijacker  // 静默改写剪贴板，模拟劫持 / 投毒
}

struct ThiefOptions {
    var mode: ThiefMode = .watcher
    var interval: TimeInterval = 0.8
    var duration: TimeInterval = 20
    var payload: String = "https://evil.example/phish?ref=clipboard-hijack"
}

func parseArgs() -> ThiefOptions {
    var opts = ThiefOptions()
    let args = CommandLine.arguments.dropFirst()
    var iterator = args.makeIterator()
    while let arg = iterator.next() {
        switch arg {
        case "--mode":
            if let v = iterator.next(), let m = ThiefMode(rawValue: v) { opts.mode = m }
        case "--interval":
            if let v = iterator.next(), let d = Double(v) { opts.interval = d }
        case "--duration":
            if let v = iterator.next(), let d = Double(v) { opts.duration = d }
        case "--payload":
            if let v = iterator.next() { opts.payload = v }
        case "--help", "-h":
            printUsageAndExit()
        default:
            break
        }
    }
    return opts
}

func printUsageAndExit() -> Never {
    print("""
    clip-thief — ClipGuard 测试用可疑应用模拟器

    用法:
      clip-thief --mode watcher  [--interval 0.8] [--duration 20]
      clip-thief --mode once
      clip-thief --mode spammer  [--interval 0.8] [--duration 20]
      clip-thief --mode hijacker [--payload 文本] [--interval 2] [--duration 20]

    模式:
      watcher   后台高频读取 NSPasteboard（模拟被抓到的剪贴板爬虫）
      once      读取一次并打印，验证"任意 App 可读剪贴板"
      spammer   反复激活自身，制造高频 App 切换信号
      hijacker  无用户手势静默改写剪贴板，模拟复制劫持
    """)
    exit(0)
}

func banner(_ text: String) {
    let df = DateFormatter()
    df.dateFormat = "HH:mm:ss.SSS"
    print("[\(df.string(from: Date()))] \(text)")
}

let opts = parseArgs()
let pb = NSPasteboard.general
let appName = Bundle.main.bundleIdentifier ?? ProcessInfo.processInfo.processName

banner("👤 可疑测试程序「\(appName)」启动，模式=\(opts.mode.rawValue)，PID=\(ProcessInfo.processInfo.processIdentifier)")

// 不需要任何权限即可读取 —— 演示 macOS 剪贴板的根本问题
switch opts.mode {
case .once:
    if let content = pb.string(forType: .string) {
        banner("📥 一次读取成功，当前剪贴板内容（\(content.count) 字符）：")
        print(content)
    } else {
        banner("剪贴板为空或不含文本")
    }
    exit(0)

case .watcher:
    banner("开始后台轮询读取，间隔 \(opts.interval)s，持续 \(opts.duration)s…")
    let deadline = Date().addingTimeInterval(opts.duration)
    var lastSeen = pb.changeCount
    var reads = 0
    while Date() < deadline {
        reads += 1
        let cc = pb.changeCount
        if cc != lastSeen {
            lastSeen = cc
            // 真实样本会把内容上传到服务器；这里只本地打印
            let preview = pb.string(forType: .string).map { String($0.prefix(40)) } ?? "<非文本>"
            banner("☁️  检测到剪贴板变化(#\(cc))，已读取并「上传」：\(preview)")
        } else if reads % 10 == 0 {
            banner("⏳ 持续轮询中… 已读取 \(reads) 次（即使内容没变也在读）")
        }
        Thread.sleep(forTimeInterval: opts.interval)
    }
    banner("结束，共发起 \(reads) 次剪贴板读取")

case .spammer:
    banner("开始反复激活自身（高频前后台切换），持续 \(opts.duration)s…")
    let deadline = Date().addingTimeInterval(opts.duration)
    var cycles = 0
    while Date() < deadline {
        cycles += 1
        NSApp.activate(ignoringOtherApps: true)
        if let s = pb.string(forType: .string) {
            banner("🔁 激活 #\(cycles) 并读取剪贴板（\(s.count) 字符）")
        }
        Thread.sleep(forTimeInterval: opts.interval)
        // 退回后台，让下一轮再次触发切换
        NSApp.hide(nil)
        Thread.sleep(forTimeInterval: opts.interval)
    }
    banner("结束，共 \(cycles) 个激活循环")

case .hijacker:
    banner("开始静默改写剪贴板（无 ⌘C 手势），间隔 \(opts.interval)s…")
    let deadline = Date().addingTimeInterval(opts.duration)
    var writes = 0
    while Date() < deadline {
        writes += 1
        let before = pb.string(forType: .string).map { String($0.prefix(20)) } ?? "<空>"
        pb.clearContents()
        pb.setString(opts.payload, forType: .string)
        banner("🦹 第 \(writes) 次静默写入：原内容[\(before)…] → [\(opts.payload)]")
        Thread.sleep(forTimeInterval: opts.interval)
    }
    banner("结束，共静默写入 \(writes) 次")
}
