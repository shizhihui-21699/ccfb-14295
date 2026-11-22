// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "ClipGuard",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "ClipGuardCore", targets: ["ClipGuardCore"]),
        .executable(name: "clipguard", targets: ["ClipGuard"]),
        .executable(name: "clip-thief", targets: ["ClipThief"]),
    ],
    targets: [
        .target(name: "ClipGuardCore"),
        .executableTarget(name: "ClipGuard", dependencies: ["ClipGuardCore"]),
        .executableTarget(name: "ClipThief"),
        .executableTarget(name: "ClipGuardCoreCheck", dependencies: ["ClipGuardCore"]),
        .executableTarget(name: "ClipGuardIntegration", dependencies: ["ClipGuardCore"]),
    ],
    swiftLanguageModes: [.v5]
)
