# ClipGuard — macOS 剪贴板敏感内容保护工具

识别被复制的**银行卡号、私钥、助记词、API Token、口令**，把明文从剪贴板撤回到内存保险箱，
只在用户真正要粘贴的瞬间短暂恢复，到期自动清除；同时基于间接信号推断可疑 App 的频繁读取行为并告警。

**不需要管理员权限（无 root / 无 sudo）。** 辅助功能权限是可选的，不授权会自动降级运行。

---

## 它解决的问题

macOS 的 `NSPasteboard` 对任何正在运行的进程都是开放的：读取剪贴板**不需要任何权限、不会有任何提示**。
一个看似正常的效率工具，可以在后台持续轮询读取并上传你复制的口令、卡号、私钥——本仓库的 `clip-thief`
就复现了这种行为（`--mode once` 可立刻验证：零权限读到剪贴板全文）。

系统**不会告诉你是哪个进程读取了剪贴板**，也没有"读取者"通知。ClipGuard 不假装能拿到这个不存在的信息，
而是：

1. **让恶意程序读不到明文**——敏感内容平时不在剪贴板上，只在用户主动粘贴的一两秒内出现；
2. **用可观测的间接信号做行为推断**——见下文"可疑推断引擎"。

---

## 工作原理

### 1. 敏感内容识别（`SensitivityDetector`，纯逻辑可单测）

| 类别 | 识别方式 |
|---|---|
| 银行卡号 | 13–19 位数字 + **Luhn/Mod10 校验**，排除手机号、要求数字占比，误报率低 |
| 私钥 | PEM 块、含 `d` 参数的 JWK、OpenSSH 单行、32/20 字节裸十六进制、Base58 WIF |
| 助记词 | BIP39 词表命中率（内置高频词样本），普通英文句子不会误报 |
| API Token | OpenAI/Anthropic/GitHub/AWS/Slack/Stripe/Google/GitLab 前缀、JWT 结构、通用高熵令牌 |
| 口令 | 多字符类高熵口令、中文+数字/符号混合、`correct horse battery staple` 式词短语 |
| 验证码 | 6 位数字，**默认关闭**（误报多），可在配置打开 |

所有日志/通知里的内容都经过 `mask()` 脱敏，**明文绝不落盘、绝不进日志**。

### 2. 内存保险箱与暴露窗口（`SecretVault`）

```
用户 ⌘C 敏感内容
   └─ 识别命中 → 明文存入内存保险箱，剪贴板替换为占位符（state = protected）
用户 ⌘V（精确模式）/ 切换到目标 App（降级模式）
   └─ 明文短暂写回剪贴板（state = exposed，默认 1.5s / 降级 3s）
窗口结束 → 占位符重新覆盖（state = protected）
TTL 到期（默认 45s）→ 明文从内存释放，剪贴板只留占位符（state = empty）
```

- 明文只存在进程内存，进程退出即消失；
- 富文本（RTF/HTML 等）会做完整快照，粘贴时不丢格式；
- 文件、图片等非文本拷贝不干预，保证正常使用。

### 3. 两种粘贴模式

- **精确 ⌘V 模式**（授予辅助功能权限）：用 `CGEventTap` **只监听不拦截**全局 ⌘C/⌘V，
  用户真正按下 ⌘V 的瞬间才恢复明文，暴露窗口可短至 1.2s。
- **App 切换降级模式**（不授权也能用）：监听到前台 App 切换即视为粘贴意图，用稍长的 3s 窗口保证粘贴成功。

### 4. 可疑推断引擎（`SuspicionEngine`）—— 难点所在

系统不公开读取者身份，引擎只使用四类**可观测间接信号**，在 10 分钟滚动窗口内对每个 App 累计评分：

| 规则 | 信号 | 分值 |
|---|---|---|
| 高频切换 | 60s 内前后台切换 ≥8 次（爬虫轮询特征） | +60 |
| 无手势写入 | changeCount 增加但近期无 ⌘C/⌘X 手势 | 每次 +30（上限 70） |
| 复制劫持 | 写入紧贴用户 ⌘C 之后 0.3–1.5s | +30~60 |
| 频繁暴露 | 60s 内受保护内容对该 App 暴露 ≥5 次 | +60 |

达到阈值（默认 60）且过了冷却时间才告警，避免骚扰。分数随窗口自然衰减归零。

> **诚实的局限**：macOS 没有任何公开 API 能定位剪贴板读取者，所以"无手势写入"只能归因到**当前前台 App**，
> 真实的后台写入者可能是别的进程。ClipGuard 的首要防线是"让明文根本不在剪贴板上"，行为推断是第二层补充，
> 不会把推断结果当成确凿事实呈现。

---

## 目录结构

```
ClipGuard/
├── Package.swift
├── Sources/
│   ├── ClipGuardCore/          # 纯逻辑核心（可跨平台单测，AppKit 仅 PasteboardController 用到）
│   │   ├── SensitivityDetector.swift   # 敏感内容识别
│   │   ├── SecretVault.swift           # 保险箱 + 暴露窗口状态机
│   │   ├── SuspicionEngine.swift       # 可疑行为推断
│   │   ├── PasteboardController.swift  # changeCount 轮询 / 自写排除 / 富文本快照
│   │   ├── EventLog.swift / GuardConfig.swift / ClipGuardPaths.swift / ClipGuardMeta.swift
│   ├── ClipGuard/              # 菜单栏代理（协调器、事件 Tap、状态栏 UI、通知）
│   ├── ClipThief/              # 测试用可疑应用模拟器（四种模式）
│   ├── ClipGuardCoreCheck/     # 22 个核心逻辑用例（零依赖断言，不依赖 XCTest）
│   └── ClipGuardIntegration/   # 6 个真机 NSPasteboard 集成场景
├── demo.sh                     # 一键端到端演示
└── package-app.sh              # 打包成 ad-hoc 签名的 .app
```

---

## 构建与测试

```bash
swift build                                   # 构建全部目标
.build/debug/ClipGuardCoreCheck               # 22 个核心逻辑用例
.build/debug/ClipGuardIntegration             # 6 个真机剪贴板集成场景
.build/debug/clip-thief --mode once           # 验证"任意 App 零权限读剪贴板"
./demo.sh                                     # 完整端到端演示（隔离的临时数据目录）
./package-app.sh                              # 产出 dist/ClipGuard.app（ad-hoc 签名）
```

> 本机只有 Command Line Tools、没有完整 Xcode，因此测试没有用 XCTest，
> 而是用 `Sources/ClipGuardCoreCheck/Check.swift` 这个零依赖迷你断言框架，可直接 `swift build` 后运行。

## 运行

```bash
# 裸二进制（菜单栏常驻，无 Dock 图标；通知降级为声音 + 红点 + 日志）
.build/release/clipguard

# 或打包后用完整系统通知
./package-app.sh && open dist/ClipGuard.app

clipguard --help          # 命令行参数
clipguard --log           # 查看最近审计事件
clipguard --init-config   # 写出默认配置 ~/.clipguard/config.json
```

- 配置与日志默认在 `~/.clipguard/`，设置环境变量 `CLIPGUARD_HOME` 可整体重定向（企业部署/测试用）。
- 首次使用建议在 **系统设置 → 隐私与安全性 → 辅助功能** 授权，启用精确 ⌘V 模式；不授权也能以降级模式运行。

## clip-thief：测试用可疑应用

专门用来对抗测试，**不需要任何权限**：

```bash
clip-thief --mode watcher    # 后台高频轮询读取（复现被抓到的爬虫）
clip-thief --mode once       # 读一次并打印
clip-thief --mode spammer    # 反复抢前台，制造高频 App 切换信号
clip-thief --mode hijacker   # 无手势静默改写剪贴板，模拟复制劫持/投毒
```

---

## 安全设计要点

- **最小权限**：不申请 root；辅助功能权限可选，缺失时自动降级。
- **明文不落盘**：敏感内容只在内存，日志只记脱敏预览，TTL 到期或退出即清除。
- **不破坏正常体验**：事件 Tap 只听不拦；普通文本、文件、图片拷贝不干预；暴露窗口自动收回。
- **不自欺欺人**：明确标注行为推断的归因局限，不声称能识别系统根本不提供的"读取者"。

## 已知边界

- 行为推断对**纯后台、从不抢前台、只读不写**的爬虫可观测信号较弱——这类程序的主要威慑仍来自第一层
  （明文平时不在剪贴板）。
- 通用高熵令牌/中文口令是启发式判断，存在漏报与少量误报的权衡；高置信度类别（Luhn 卡号、PEM/JWK、厂商前缀 Token）优先保证准确。
- 裸命令行二进制无法投递 UserNotifications，需打包成 `.app` 才能获得系统通知（已提供打包脚本）。
