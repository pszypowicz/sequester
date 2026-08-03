import AppKit
import UserNotifications
import SequesterCore

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {

    private var server: MessageServer<AgentService>?
    private var secretsServer: MessageServer<SecretsService>?

    func applicationDidFinishLaunching(_ notification: Notification) {
        Log.app.log("Sequester launched, login item \(LoginItem.isEnabled, privacy: .public)")
        UNUserNotificationCenter.current().delegate = self
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, error in
            if let error {
                Log.app.error("Notification authorization failed: \(error.localizedDescription, privacy: .public)")
            } else {
                Log.app.log("Notification authorization granted \(granted, privacy: .public)")
            }
        }
        EnclaveKeyStore.syncPublicKeyFiles()
        AuthorizationWindows.shared.startObservingLock()
        let agent = Agent(approver: DialogApprover(), notifier: NotificationNotifier())
        let server = MessageServer(socketPath: SequesterPaths.socketURL.path,
                                   service: AgentService(agent: agent))
        do {
            try server.start()
            self.server = server
        } catch {
            Log.app.error("Agent failed to start: \(error.localizedDescription, privacy: .public)")
        }

        let broker = SecretsBroker(approver: SecretsDialogApprover(),
                                   notifier: SecretsNotificationNotifier())
        let secretsServer = MessageServer(socketPath: SequesterPaths.secretsSocketURL.path,
                                          service: SecretsService(broker: broker))
        do {
            try secretsServer.start()
            self.secretsServer = secretsServer
        } catch {
            Log.app.error("Secrets service failed to start: \(error.localizedDescription, privacy: .public)")
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
        secretsServer?.stop()
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        true
    }

    private static func isSettingsWindow(_ window: NSWindow) -> Bool {
        window.identifier?.rawValue.hasPrefix("main") == true
    }
}

extension AppDelegate: UNUserNotificationCenterDelegate {

    /// Show banners even when Sequester is frontmost, so a refusal is not
    /// swallowed while the settings window has focus.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }

    /// Clicking a notification jumps to the key or profile it names. Only
    /// the name travels in the request's userInfo; nothing else is captured,
    /// so the non-Sendable response never crosses to the main actor.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let userInfo = response.notification.request.content.userInfo
        let keyName = userInfo["keyName"] as? String
        let profileName = userInfo["profileName"] as? String
        Task { @MainActor in
            if let keyName {
                Navigator.shared.showKey(keyName)
            } else if let profileName {
                Navigator.shared.showProfile(profileName)
            }
        }
        completionHandler()
    }
}
