import Foundation

/// 零依赖迷你测试框架（机器上只有 Command Line Tools，没有 XCTest）
/// 用法：Check.test("名称") { 闭包内用 try Check.expect(...) 断言 }

enum Check {
    private(set) static var passed = 0
    private(set) static var failed = 0
    private static var failures: [String] = []

    static func test(_ name: String, _ body: () throws -> Void) {
        do {
            try body()
            passed += 1
            print("  ✓ \(name)")
        } catch {
            failed += 1
            failures.append("✗ \(name) — \(error.localizedDescription)")
            print("  ✗ \(name) — \(error.localizedDescription)")
        }
    }

    static func expect(_ condition: Bool, _ message: String = "",
                       file: String = #fileID, line: Int = #line) throws {
        if !condition { throw CheckError("\(message)（\(file):\(line)）") }
    }

    static func expectEqual<T: Equatable>(_ a: T, _ b: T, _ message: String = "",
                                          file: String = #fileID, line: Int = #line) throws {
        if a != b {
            throw CheckError("期望 \(b)，实际 \(a) \(message)（\(file):\(line)）")
        }
    }

    static func expectNil<T>(_ a: T?, _ message: String = "",
                             file: String = #fileID, line: Int = #line) throws {
        if a != nil { throw CheckError("期望为 nil，实际 \(String(describing: a!)) \(message)（\(file):\(line)）") }
    }

    static func expectNotNil<T>(_ a: T?, _ message: String = "",
                                file: String = #fileID, line: Int = #line) throws {
        if a == nil { throw CheckError("期望非 nil \(message)（\(file):\(line)）") }
    }

    static func finish() -> Never {
        print("\n────────────")
        if failed == 0 {
            print("全部通过：\(passed) 个用例 ✅")
            exit(0)
        } else {
            print("失败 \(failed) / 共 \(passed + failed)：")
            failures.forEach { print("  \($0)") }
            exit(1)
        }
    }
}

struct CheckError: Error, CustomStringConvertible, LocalizedError {
    let description: String
    init(_ description: String) { self.description = description }
    var errorDescription: String? { description }
}

/// 可控时钟，让时间相关逻辑可确定性测试
final class ControlledClock {
    var now: Date
    init(now: Date) { self.now = now }
    func advance(_ seconds: TimeInterval) {
        now = now.addingTimeInterval(seconds)
    }
}
