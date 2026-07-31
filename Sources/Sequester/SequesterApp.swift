import SwiftUI
import SequesterCore

@main
struct SequesterApp: App {

    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var store = KeyStore()
    @State private var hostNames = HostNameStore()
    @AppStorage("showMenuBarIcon") private var showMenuBarIcon = true

    init() {
        SelftestCLI.runIfRequested()
    }

    var body: some Scene {
        Window("Sequester", id: "main") {
            KeyListView()
                .environment(store)
                .environment(hostNames)
                .onAppear {
                    // Whatever path opened the window, present it like a
                    // regular app: with a menu bar and a Dock icon. The
                    // delegate drops back to accessory on close.
                    NSApp.setActivationPolicy(.regular)
                    NSApp.activate(ignoringOtherApps: true)
                }
        }
        .defaultSize(width: 720, height: 440)
        // Launching (e.g. at login) starts only the agent and the menu bar
        // icon. Relaunching while running reopens this window instead.
        .defaultLaunchBehavior(.suppressed)

        Window("About Sequester", id: "about") {
            AboutView()
        }
        .windowResizability(.contentSize)
        .defaultLaunchBehavior(.suppressed)

        MenuBarExtra("Sequester", systemImage: "key.fill", isInserted: $showMenuBarIcon) {
            MenuContent()
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
