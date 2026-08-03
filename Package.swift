// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "Sequester",
    platforms: [.macOS(.v26)],
    products: [
        .executable(name: "sequester-cli", targets: ["SequesterCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", exact: "1.8.2"),
    ],
    targets: [
        .target(name: "SecretsWire"),
        .target(name: "SequesterCore", dependencies: ["SecretsWire"]),
        .executableTarget(
            name: "Sequester",
            dependencies: ["SequesterCore"],
            exclude: ["Info.plist", "Sequester.entitlements"],
            plugins: [.plugin(name: "BuildMetadata")]
        ),
        // The CLI links only the wire protocol, never SequesterCore: every
        // keychain and Enclave operation stays in the app, which the CLI
        // reaches over the secrets socket.
        .executableTarget(
            name: "SequesterCLI",
            dependencies: [
                "SecretsWire",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            plugins: [.plugin(name: "BuildMetadata")]
        ),
        .testTarget(
            name: "SequesterCoreTests",
            dependencies: ["SequesterCore", "SecretsWire"]
        ),
        .plugin(
            name: "BuildMetadata",
            capability: .buildTool()
        ),
    ]
)
