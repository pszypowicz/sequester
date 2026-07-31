import Foundation
import ServiceManagement
import SequesterCore

/// Thin wrapper over SMAppService for the "start at login" toggle.
enum LoginItem {

    static var isEnabled: Bool {
        SMAppService.mainApp.status == .enabled
    }

    static func setEnabled(_ enabled: Bool) throws {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            Log.app.log("Login item \(enabled ? "registered" : "unregistered", privacy: .public)")
        } catch {
            Log.app.error("Login item change failed: \(error.localizedDescription, privacy: .public)")
            throw error
        }
    }
}
