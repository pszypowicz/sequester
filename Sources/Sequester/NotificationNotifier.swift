import UserNotifications
import SequesterCore

/// Posts a user notification after every signature. A silent signature
/// (no dialog, no Touch ID) is the one worth noticing, so its notification
/// is worded to stand out.
struct NotificationNotifier: SigningNotifier {

    func signed(keyName: String, chain: [ChainHop], silent: Bool) {
        let content = UNMutableNotificationContent()
        content.title = silent ? "Signed without a prompt: \(keyName)" : "Signed: \(keyName)"

        var parts: [String] = []
        if let destination = chain.last {
            parts.append("for \(HostNames.shared.label(for: destination.fingerprint))")
        }
        if chain.contains(where: { $0.forwarding }) {
            parts.append("(forwarded)")
        }
        content.body = parts.isEmpty ? "SSH signature" : parts.joined(separator: " ")
        if silent {
            content.interruptionLevel = .timeSensitive
        }

        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request)
    }
}
