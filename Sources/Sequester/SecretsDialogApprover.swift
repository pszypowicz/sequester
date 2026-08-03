import AppKit
import SwiftUI
import SequesterCore

/// Presents secrets approval as a modal dialog. Concurrent requests
/// serialize on the main actor, matching the signing dialog.
struct SecretsDialogApprover: SecretsApprover {

    func approve(_ request: SecretsApprovalRequest) async -> SecretsApprovalDecision {
        Log.app.log("Secrets dialog for profile \(request.profileName, privacy: .public), kind \(String(describing: request.kind), privacy: .public), requester \(request.requester, privacy: .public)")
        let decision = await MainActor.run { present(request) }
        Log.app.log("Secrets dialog result for \(request.profileName, privacy: .public): allowed \(decision.allowed, privacy: .public)")
        return decision
    }

    @MainActor
    private func present(_ request: SecretsApprovalRequest) -> SecretsApprovalDecision {
        NSApp.activate(ignoringOtherApps: true)

        var decision = SecretsApprovalDecision.deny
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 400, height: 240),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.title = windowTitle(for: request.kind)
        window.isReleasedWhenClosed = false
        window.level = .modalPanel

        let view = SecretsApprovalView(
            kind: request.kind,
            profileName: request.profileName,
            tier: request.tier,
            variableNames: request.variableNames,
            requester: request.requester,
            offersGrace: request.offersGrace,
            graceSeconds: request.graceSeconds
        ) { result in
            decision = result
            NSApp.stopModal()
        }

        let hosting = NSHostingController(rootView: view)
        window.contentViewController = hosting
        window.setContentSize(hosting.view.fittingSize)
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.runModal(for: window)
        window.orderOut(nil)
        return decision
    }

    private func windowTitle(for kind: SecretsApprovalRequest.Kind) -> String {
        switch kind {
        case .read: "Secrets Request"
        case .create: "Create Profile"
        case .update: "Update Profile"
        case .delete: "Delete Profile"
        }
    }
}
