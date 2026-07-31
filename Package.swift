// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Sequester",
    platforms: [.macOS(.v15)],
    targets: [
        .target(name: "SequesterCore"),
        .executableTarget(
            name: "Sequester",
            dependencies: ["SequesterCore"],
            exclude: ["Info.plist"],
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
