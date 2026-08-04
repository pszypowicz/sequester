import AppKit
import SwiftUI
import SequesterCore

/// App-wide navigation for jumps that originate outside the view tree - a
/// notification click or the Dock reopen event lands in the AppKit delegate,
/// which has no `openWindow` of its own. The menu bar extra's label view
/// captures its `openWindow` action here at launch, before any window
/// exists, so every such jump can open the settings window cold.
@MainActor
@Observable
final class Navigator {

    static let shared = Navigator()
    private init() {}

    @ObservationIgnored var openWindow: OpenWindowAction?

    /// The sidebar item a pending jump wants selected. `KeyListView` consumes
    /// and clears it, on appear (a window opened cold) or on change (already
    /// open).
    var pendingSelection: SidebarItem?

    /// Bring the settings window forward and select a key. Safe to call from
    /// the AppKit side.
    func showKey(_ name: String) {
        show(.key(name))
    }

    /// Bring the settings window forward and select a secrets profile.
    func showProfile(_ name: String) {
        show(.profile(name))
    }

    /// Open (or bring forward) the settings window, presenting the app as a
    /// regular one. `openWindow` both creates the window when none exists and
    /// fronts the existing one, so this is safe from any state. The guard
    /// keeps the app from promoting to a Dock icon when there is nothing to
    /// show; the action is captured at launch, so a nil here is a bug.
    func showSettings() {
        guard let openWindow else {
            Log.app.error("No openWindow action captured; cannot show settings")
            return
        }
        NSApp.setActivationPolicy(.regular)
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }

    private func show(_ item: SidebarItem) {
        pendingSelection = item
        showSettings()
    }
}
