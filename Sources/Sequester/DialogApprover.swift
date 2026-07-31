import AppKit
import SwiftUI
import SequesterCore

/// Presents signing approval as a modal route dialog. Concurrent requests
/// serialize on the main actor, which is the behavior a human answering
/// dialogs wants anyway.
struct DialogApprover: SigningApprover {

    func approve(_ request: ApprovalRequest) async -> ApprovalDecision {
        Log.app.log("Approval dialog for key \(request.keyName, privacy: .public), requester \(request.provenance.displayName, privacy: .public)")
        let decision = await MainActor.run { present(request) }
        Log.app.log("Approval dialog result for \(request.keyName, privacy: .public): allowed \(decision.allowed, privacy: .public), remember \(decision.remember, privacy: .public)")
        return decision
    }

    @MainActor
    private func present(_ request: ApprovalRequest) -> ApprovalDecision {
        NSApp.activate(ignoringOtherApps: true)

        let hops = request.bindingChain.enumerated().map { index, hop in
            ApprovalView.Hop(
                name: HostNames.shared.name(for: hop.fingerprint),
                fingerprint: hop.fingerprint,
                forwarded: hop.forwarding,
                isDestination: index == request.bindingChain.count - 1
            )
        }

        var decision = ApprovalDecision.deny
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 400, height: 240),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.title = "Sequester"
        window.isReleasedWhenClosed = false
        window.level = .modalPanel

        let view = ApprovalView(
            keyName: request.keyName,
            requester: "\(request.provenance.displayName) (pid \(request.provenance.pid))",
            verified: request.provenance.identityKey != nil,
            appDecisionNeeded: request.appStanding == .unknown,
            hops: hops,
            canName: !request.bindingChain.isEmpty,
            canRemember: request.canRemember
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
}
