import AppKit
import SwiftUI

/// App-wide navigation for jumps that originate outside the view tree - a
/// notification click lands in the AppKit delegate, which has no `openWindow`
/// of its own. `KeyListView` hands its `openWindow` action here while it is
/// on screen; since a key can only exist after the settings window has been
/// opened to create it, that action is always captured before any signature
/// (and so any notification) can occur.
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

    private func show(_ item: SidebarItem) {
        pendingSelection = item
        NSApp.setActivationPolicy(.regular)
        openWindow?(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }
}
