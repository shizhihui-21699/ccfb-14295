import Foundation
import ClipGuardCore

let detector = SensitivityDetector()

print("▌敏感内容识别")

Check.test("Luhn 合法卡号（含空格分组）") {
    try Check.expect(SensitivityDetector.luhnValid("4532015112830366"), "Visa 测试号应通过")
    try Check.expect(SensitivityDetector.luhnValid("5425233430109903"), "MC 测试号应通过")
    try Check.expect(SensitivityDetector.luhnValid("374245455400126"), "Amex 测试号应通过")
    try Check.expect(SensitivityDetector.luhnValid("6011000990139424"), "Discover 测试号应通过")
    try Check.expectEqual(detector.analyze("4532 0151 1283 0366")?.kind, .bankCard)
}

Check.test("随机数字与手机号不误报") {
    try Check.expect(!SensitivityDetector.luhnValid("1234567890123456"), "随机串应失败")
    try Check.expectNil(detector.analyze("1234567890123456"))
    try Check.expectNil(detector.analyze("13800138000"), "11 位 1 开头按手机号处理")
}

Check.test("PEM / 十六进制 / WIF / JWK 私钥") {
    let pem = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEAxxxxfakefakefakefakefakefakefakefakefakefake
    -----END RSA PRIVATE KEY-----
    """
    try Check.expectEqual(detector.analyze(pem)?.kind, .privateKey)
    let key = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
    let hex = detector.analyze(key)
    try Check.expectEqual(hex?.kind, .privateKey)
    try Check.expect(hex?.preview.contains("•") == true, "预览必须脱敏")
    try Check.expectEqual(detector.analyze("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")?.kind, .privateKey)
    let jwk = #"{"kty":"EC","crv":"P-256","x":"abc","y":"def","d":"secret-d"}"#
    try Check.expectEqual(detector.analyze(jwk)?.kind, .privateKey)
}

Check.test("BIP39 助记词与普通英文句子") {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    try Check.expectEqual(detector.analyze(mnemonic)?.kind, .mnemonic)
    let sentence = "the quick brown fox jumps over the lazy dog and runs away quickly today"
    try Check.expectNil(detector.analyze(sentence), "普通句子不应误报")
}

Check.test("各厂商 API Token 与 JWT") {
    try Check.expectEqual(detector.analyze("sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789")?.kind, .apiToken)
    try Check.expectEqual(detector.analyze("ghp_0123456789abcdefghijklmnopqrstuvwxyzAB")?.kind, .apiToken)
    try Check.expectEqual(detector.analyze("AKIAIOSFODNN7EXAMPLE")?.kind, .apiToken)
    try Check.expectEqual(detector.analyze("xoxb-1234567890-abcdefghij")?.kind, .apiToken)
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    try Check.expectEqual(detector.analyze(jwt)?.kind, .apiToken)
}

Check.test("口令：高熵 / 中文混合 / 单词短语") {
    try Check.expectEqual(detector.analyze("Tr0ub4dour&3x!")?.kind, .password)
    try Check.expectEqual(detector.analyze("青山依旧@2026")?.kind, .password, "汉字+符号混合判为口令")
    try Check.expectEqual(detector.analyze("correct horse battery staple")?.kind, .password)
}

Check.test("正常文本与占位符不干预") {
    try Check.expectNil(detector.analyze("明天下午三点会议室见"))
    try Check.expectNil(detector.analyze("晚上一起吃饭吗"), "纯中文短句不得误报为口令")
    try Check.expectNil(detector.analyze("hello world"))
    try Check.expectNil(detector.analyze("https://www.apple.com/cn/"))
    try Check.expectNil(detector.analyze(ClipGuardMeta.placeholder))
}

Check.test("验证码默认关闭，可开关") {
    try Check.expectNil(detector.analyze("483920"))
    let on = SensitivityDetector(config: .init(detectOneTimeCode: true))
    try Check.expectEqual(on.analyze("483920")?.kind, .oneTimeCode)
}

Check.test("脱敏函数") {
    try Check.expectEqual(
        SensitivityDetector.mask("1234567890123456", visiblePrefix: 4, visibleSuffix: 4),
        "1234••••••••3456")
    let short = SensitivityDetector.mask("ab", visiblePrefix: 4, visibleSuffix: 4)
    try Check.expect(short.allSatisfy { $0 == "•" }, "短串全部打码")
}

print("▌保险箱状态机")

func makeVault(ttl: TimeInterval = 45, window: TimeInterval = 2,
               start: Date = Date(timeIntervalSince1970: 1000)) -> (SecretVault, ControlledClock) {
    let clock = ControlledClock(now: start)
    let vault = SecretVault(ttl: ttl, exposureWindow: window, clock: { clock.now })
    return (vault, clock)
}
func makeSecret(_ text: String = "Tr0ub4dour&3x!") -> ProtectedSecret {
    ProtectedSecret(text: text,
                    result: SensitivityResult(kind: .password, confidence: 0.7, preview: "••"),
                    capturedAt: Date(timeIntervalSince1970: 1000))
}

Check.test("protected → exposed → 自动收回") {
    let (vault, clock) = makeVault()
    try Check.expectEqual(vault.state, .empty)
    vault.stash(makeSecret())
    try Check.expectEqual(vault.state, .protected)
    vault.expose()
    try Check.expectEqual(vault.state, .exposed)
    clock.advance(1)
    try Check.expect(!vault.tick().exposureEnded, "窗口内不结束")
    clock.advance(1.1)
    try Check.expect(vault.tick().exposureEnded, "超窗口应结束")
    try Check.expectEqual(vault.state, .protected)
}

Check.test("TTL 到期清除明文") {
    let (vault, clock) = makeVault(ttl: 10)
    vault.stash(makeSecret())
    clock.advance(9)
    try Check.expect(!vault.tick().ttlExpired)
    try Check.expectNotNil(vault.secret)
    clock.advance(1.1)
    try Check.expect(vault.tick().ttlExpired)
    try Check.expectEqual(vault.state, .empty)
    try Check.expectNil(vault.secret, "明文必须被释放")
}

Check.test("rehide 取消暴露") {
    let (vault, clock) = makeVault()
    vault.stash(makeSecret())
    vault.expose()
    vault.rehide()
    try Check.expectEqual(vault.state, .protected)
    clock.advance(100)
    try Check.expect(!vault.tick().exposureEnded, "rehide 后不再触发窗口结束")
}

Check.test("降级模式自定义暴露窗口") {
    let (vault, clock) = makeVault(window: 1.2)
    vault.stash(makeSecret())
    vault.expose(window: 3.0)
    clock.advance(2)
    try Check.expect(!vault.tick().exposureEnded, "3s 窗口在 2s 时不应结束")
    clock.advance(1.1)
    try Check.expect(vault.tick().exposureEnded)
}

print("▌可疑行为推断引擎")

let evil = "com.evil.helper"
let base = Date(timeIntervalSince1970: 10_000)

func makeEngine(threshold: Int = 60, cooldown: TimeInterval = 0) -> (SuspicionEngine, ControlledClock) {
    let clock = ControlledClock(now: base)
    let engine = SuspicionEngine(alertThreshold: threshold, alertCooldown: cooldown, clock: { clock.now })
    return (engine, clock)
}

Check.test("高频前后台切换触发告警") {
    let (engine, clock) = makeEngine()
    var alert: SuspicionAlert?
    for i in 0..<9 {
        clock.advance(2)
        alert = engine.record(AppEvent(app: evil, kind: .appSwitch, time: clock.now)) ?? alert
    }
    try Check.expectNotNil(alert)
    try Check.expect(alert?.hits.contains { $0.rule == "高频切换" } == true)
}

Check.test("单次无手势写入计分但不告警") {
    let (engine, _) = makeEngine()
    try Check.expectNil(engine.record(AppEvent(app: evil, kind: .unexpectedWrite, time: base)))
    try Check.expectEqual(engine.currentScore(app: evil).score, 30)
}

Check.test("多次无手势写入越过阈值") {
    let (engine, clock) = makeEngine()
    var alert: SuspicionAlert?
    for _ in 0..<3 {
        clock.advance(10)
        alert = engine.record(AppEvent(app: evil, kind: .unexpectedWrite, time: clock.now)) ?? alert
    }
    try Check.expectNotNil(alert, "第 2 次即达 60 分应告警")
    try Check.expectEqual(alert?.app, evil)
}

Check.test("复制劫持：⌘C 后 1.5 秒内被改写") {
    let (engine, clock) = makeEngine(threshold: 40)
    _ = engine.record(AppEvent(app: "com.legit.editor", kind: .copyGesture, time: clock.now))
    clock.advance(0.5)
    let alert = engine.record(AppEvent(app: evil, kind: .unexpectedWrite, time: clock.now))
    try Check.expectNotNil(alert)
    try Check.expect(alert?.hits.contains { $0.rule == "复制劫持" } == true)
}

Check.test("冷却期抑制重复告警，过期后恢复") {
    let clock = ControlledClock(now: base)
    let engine = SuspicionEngine(alertThreshold: 20, alertCooldown: 60, clock: { clock.now })
    try Check.expectNotNil(engine.record(AppEvent(app: evil, kind: .unexpectedWrite, time: clock.now)))
    clock.advance(10)
    try Check.expectNil(engine.record(AppEvent(app: evil, kind: .unexpectedWrite, time: clock.now)),
                        "冷却期内不重复")
    clock.advance(55)
    try Check.expectNotNil(engine.record(AppEvent(app: evil, kind: .unexpectedWrite, time: clock.now)))
}

Check.test("评分随 10 分钟窗口衰减归零") {
    let (engine, clock) = makeEngine(threshold: 1000)
    engine.record(AppEvent(app: evil, kind: .unexpectedWrite, time: clock.now))
    try Check.expectEqual(engine.currentScore(app: evil).score, 30)
    clock.advance(601)
    try Check.expectEqual(engine.currentScore(app: evil).score, 0)
}

Check.test("受保护内容频繁暴露计分") {
    let (engine, clock) = makeEngine()
    var alert: SuspicionAlert?
    for _ in 0..<6 {
        clock.advance(1)
        alert = engine.record(AppEvent(app: evil, kind: .protectedExposure, time: clock.now)) ?? alert
    }
    try Check.expectNotNil(alert, "5 次暴露即达 60 分")
    try Check.expect(alert?.hits.contains { $0.rule == "频繁暴露" } == true)
}

print("▌审计日志")

Check.test("环形缓冲与 JSONL 落盘") {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let file = dir.appendingPathComponent("events.jsonl")
    let log = EventLog(capacity: 5, fileURL: file)
    for i in 0..<10 { log.append(.info, "事件 \(i)") }
    try Check.expectEqual(log.snapshot().count, 5)
    try Check.expectEqual(log.snapshot().first?.message, "事件 5")
    let lines = try Data(contentsOf: file).split(separator: 0x0A)
    try Check.expectEqual(lines.count, 10)
    for line in lines {
        let obj = try JSONSerialization.jsonObject(with: Data(line)) as? [String: Any]
        try Check.expectNotNil(obj?["message"])
    }
    try FileManager.default.removeItem(at: dir)
}

print("▌配置文件")

Check.test("默认配置可序列化往返") {
    let cfg = GuardConfig()
    let encoder = JSONEncoder()
    let data = try encoder.encode(cfg)
    let back = try JSONDecoder().decode(GuardConfig.self, from: data)
    try Check.expectEqual(back, cfg)
    try Check.expectEqual(back.detector.detectBankCard, true)
    try Check.expectEqual(back.detector.detectOneTimeCode, false)
}

Check.finish()
