import AppKit
import Observation
import SequesterCore

@Observable
final class AgentStatus {
    var running = false
    var error: String?
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {

    let agentStatus = AgentStatus()
    private var server: AgentServer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        Log.app.log("Sequester launched, login item \(LoginItem.isEnabled, privacy: .public)")
        EnclaveKeyStore.syncPublicKeyFiles()
        let agent = Agent(approver: DialogApprover())
        let server = AgentServer(socketPath: SequesterPaths.socketURL.path, agent: agent)
        do {
            try server.start()
            self.server = server
            agentStatus.running = true
        } catch {
            Log.app.error("Agent failed to start: \(error.localizedDescription, privacy: .public)")
            agentStatus.error = error.localizedDescription
        }

        // The settings window promotes the app to a regular one (menu bar,
        // Dock icon); closing it returns to a plain menu bar accessory.
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(windowWillClose(_:)),
            name: NSWindow.willCloseNotification,
            object: nil
        )
    }

    // NSWindow posts on the main thread; the nonisolated hop exists only to
    // satisfy the selector signature.
    @objc private nonisolated func windowWillClose(_ note: Notification) {
        let window = note.object as? NSWindow
        MainActor.assumeIsolated {
            guard let window, Self.isSettingsWindow(window) else { return }
            DispatchQueue.main.async {
                let stillOpen = NSApp.windows.contains { Self.isSettingsWindow($0) && $0.isVisible }
                if !stillOpen {
                    NSApp.setActivationPolicy(.accessory)
                }
            }
        }
    }

    /// Launching the app while it already runs lands here; show settings
    /// immediately. Returning true also lets SwiftUI recreate the window
    /// when none exists (its launch presentation is suppressed).
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        Log.app.log("Reopen requested, visible windows \(hasVisibleWindows, privacy: .public)")
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        if let window = NSApp.windows.first(where: { Self.isSettingsWindow($0) }) {
            window.makeKeyAndOrderFront(nil)
        }
        return true
    }

    func applicationWillTerminate(_ notification: Notification) {
        Log.app.log("Sequester terminating")
        server?.stop()
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        true
    }

    private static func isSettingsWindow(_ window: NSWindow) -> Bool {
        window.identifier?.rawValue.hasPrefix("main") == true
    }
}
