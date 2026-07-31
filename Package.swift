// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "Sequester",
    platforms: [.macOS(.v26)],
    targets: [
        .target(name: "SequesterCore"),
        .executableTarget(
            name: "Sequester",
            dependencies: ["SequesterCore"],
            exclude: ["Info.plist", "Sequester.entitlements"],
            plugins: [.plugin(name: "BuildMetadata")]
        ),
        .testTarget(
            name: "SequesterCoreTests",
            dependencies: ["SequesterCore"]
        ),
        .plugin(
            name: "BuildMetadata",
            capability: .buildTool()
        ),
    ]
)
