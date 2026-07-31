import AppKit
import SequesterCore

/// Implements signing approval as a modal alert. Concurrent requests
/// serialize on the main actor, which is the behavior a human answering
/// dialogs wants anyway.
struct DialogApprover: SigningApprover {

    func approve(_ request: ApprovalRequest) async -> ApprovalDecision {
        Log.app.log("Approval dialog for key \(request.keyName, privacy: .public), requester \(request.provenance.displayName, privacy: .public)")
        let decision: ApprovalDecision = await MainActor.run {
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Allow SSH signature with \"\(request.keyName)\"?"
            alert.informativeText = Self.details(request)
            alert.addButton(withTitle: "Allow")
            alert.addButton(withTitle: "Deny")

            // Naming the destination while answering is the moment the user
            // knows what it is, so the field is offered here rather than
            // only in settings.
            let destination = request.chain.last
            let unnamed = destination.map { HostNames.shared.name(for: $0.fingerprint) == nil } ?? false
            var nameField: NSTextField?
            if unnamed {
                let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
                field.placeholderString = "Name this host (optional), e.g. github"
                alert.accessoryView = field
                nameField = field
            }
            if request.canRemember {
                alert.showsSuppressionButton = true
                alert.suppressionButton?.title = "Don't ask again for this destination"
            }

            guard alert.runModal() == .alertFirstButtonReturn else { return .deny }
            return ApprovalDecision(
                allowed: true,
                remember: request.canRemember && alert.suppressionButton?.state == .on,
                destinationName: nameField?.stringValue
            )
        }
        Log.app.log("Approval dialog result for \(request.keyName, privacy: .public): allowed \(decision.allowed, privacy: .public), remember \(decision.remember, privacy: .public)")
        return decision
    }

    private static func details(_ request: ApprovalRequest) -> String {
        var lines = ["Requested by \(request.provenance.displayName) (pid \(request.provenance.pid))."]
        if request.chain.isEmpty {
            lines.append("The connection is not bound to any SSH session, so the destination is unknown.")
        }
        for hop in request.chain {
            let kind = hop.forwarding ? "FORWARDED via" : "bound to"
            lines.append("Session \(kind) \(HostNames.shared.label(for: hop.fingerprint)).")
        }
        return lines.joined(separator: "\n")
    }
}
