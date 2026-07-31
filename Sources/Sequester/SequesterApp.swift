import SwiftUI
import SequesterCore

@main
struct SequesterApp: App {

    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var store = KeyStore()

    init() {
        SelftestCLI.runIfRequested()
    }

    var body: some Scene {
        Window("Sequester", id: "main") {
            KeyListView()
                .environment(store)
        }
        .defaultSize(width: 720, height: 440)

        MenuBarExtra("Sequester", systemImage: "key.fill") {
            MenuContent()
                .environment(store)
                .environment(appDelegate.agentStatus)
        }
    }
}

/// Dispatches the hidden diagnostic flags before any UI exists, and exits.
enum SelftestCLI {
    static func runIfRequested() {
        let arguments = CommandLine.arguments
        if arguments.contains("--selftest") {
            exit(Selftest.run())
        }
        if let index = arguments.firstIndex(of: "--selftest-create-key"),
           index + 1 < arguments.count {
            exit(Selftest.createKey(name: arguments[index + 1]))
        }
        if let index = arguments.firstIndex(of: "--selftest-delete-key"),
           index + 1 < arguments.count {
            exit(Selftest.deleteKey(name: arguments[index + 1]))
        }
    }
}
