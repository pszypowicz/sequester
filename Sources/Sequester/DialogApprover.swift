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
            if request.canRemember {
                alert.showsSuppressionButton = true
                alert.suppressionButton?.title = "Don't ask again for this destination"
            }
            guard alert.runModal() == .alertFirstButtonReturn else { return .deny }
            if request.canRemember, alert.suppressionButton?.state == .on {
                return .allowAndRemember
            }
            return .allow
        }
        Log.app.log("Approval dialog result for \(request.keyName, privacy: .public): \(String(describing: decision), privacy: .public)")
        return decision
    }

    private static func details(_ request: ApprovalRequest) -> String {
        var lines = ["Requested by \(request.provenance.displayName) (pid \(request.provenance.pid))."]
        if request.chain.isEmpty {
            lines.append("The connection is not bound to any SSH session, so the destination is unknown.")
        }
        for hop in request.chain {
            let kind = hop.forwarding ? "FORWARDED via" : "bound to"
            lines.append("Session \(kind) host key \(hop.fingerprint) (\(hop.algorithm)).")
        }
        return lines.joined(separator: "\n")
    }
}
