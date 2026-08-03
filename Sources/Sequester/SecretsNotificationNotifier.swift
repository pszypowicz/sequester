import UserNotifications
import SequesterCore
import SecretsWire

/// Posts a user notification after every secrets operation, and after a
/// refusal that happens before any prompt. A silent read (no dialog, no
/// Touch ID) is the case worth noticing, since the terminal shows nothing.
///
/// Same three-line convention as signing notifications: what happened,
/// which profile, and who asked. Emoji stand in for SF Symbols, which
/// cannot render in notification text.
struct SecretsNotificationNotifier: SecretsNotifier {

    func read(profile: String, tier: SecretTier, requester: String, silent: Bool) {
        let content = UNMutableNotificationContent()
        content.title = silent ? "Secrets read without a prompt" : "Secrets read"
        content.subtitle = profileLine(profile, tier: tier)
        content.body = "\u{1F5A5}\u{FE0F} \(requester)"
        content.userInfo = ["profileName": profile]
        // A unique id per read keeps each access visible in the stack.
        post(content, identifier: UUID().uuidString)
    }

    func changed(profile: String, change: ProfileChange, requester: String) {
        let content = UNMutableNotificationContent()
        content.title = "Secrets profile \(change.rawValue)"
        content.subtitle = "\u{1F510} \(profile)"
        content.body = "\u{1F5A5}\u{FE0F} \(requester)"
        if change != .deleted {
            content.userInfo = ["profileName": profile]
        }
        post(content, identifier: UUID().uuidString)
    }

    func denied(profile: String?, requester: String) {
        let content = UNMutableNotificationContent()
        content.title = "Secrets access refused"
        if let profile {
            content.subtitle = "\u{1F510} \(profile)"
            content.userInfo = ["profileName": profile]
        }
        content.body = "\u{1F6AB} Blocked app: \(requester)"
        // A stable id per (profile, requester) collapses a retry storm into
        // one banner instead of stacking a copy per rejected attempt.
        post(content, identifier: "secrets-denied:\(profile ?? "-"):\(requester)")
    }

    /// Second line: the profile, prefixed with a Touch ID or lock glyph.
    private func profileLine(_ profile: String, tier: SecretTier) -> String {
        "\(tier == .everyRead ? "\u{261D}\u{FE0F}" : "\u{1F510}") \(profile)"
    }

    private func post(_ content: UNMutableNotificationContent, identifier: String) {
        let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}
