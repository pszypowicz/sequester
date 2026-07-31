import AppKit
import SequesterCore

/// Implements signing approval as a modal alert. Concurrent requests
/// serialize on the main actor, which is the behavior a human answering
/// dialogs wants anyway.
struct DialogApprover: SigningApprover {

    func approve(keyName: String, provenance: Provenance, bindings: [SessionBinding]) async -> Bool {
        Log.app.log("Approval dialog for key \(keyName, privacy: .public), requester \(provenance.displayName, privacy: .public)")
        let allowed = await MainActor.run {
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Allow SSH signature with \"\(keyName)\"?"
            alert.informativeText = Self.details(provenance: provenance, bindings: bindings)
            alert.addButton(withTitle: "Allow")
            alert.addButton(withTitle: "Deny")
            return alert.runModal() == .alertFirstButtonReturn
        }
        Log.app.log("Approval dialog result for \(keyName, privacy: .public): \(allowed ? "allowed" : "denied", privacy: .public)")
        return allowed
    }

    private static func details(provenance: Provenance, bindings: [SessionBinding]) -> String {
        var lines = ["Requested by \(provenance.displayName) (pid \(provenance.pid))."]
        if bindings.isEmpty {
            lines.append("The connection is not bound to any SSH session, so the destination is unknown.")
        }
        for binding in bindings {
            let kind = binding.isForwarding ? "FORWARDED via" : "bound to"
            lines.append("Session \(kind) host key \(binding.hostKeyFingerprint) (\(binding.hostKeyAlgorithm)).")
        }
        return lines.joined(separator: "\n")
    }
}
