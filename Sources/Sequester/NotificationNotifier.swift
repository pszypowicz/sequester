import UserNotifications
import SequesterCore

/// Posts a user notification after every signature, and after a refusal that
/// happens before any prompt. A silent signature (no dialog, no Touch ID) and
/// a silent refusal are the ones worth noticing, since neither shows any UI on
/// its own - the terminal only reports "agent refused operation".
///
/// Each notification is three lines: what happened, which key, and where.
/// SF Symbols cannot be drawn inside notification text, so the glyphs are
/// emoji standing in for the app's touchid/key/mappin icons. A glyph is
/// joined to its text with a no-break space, and an unnamed destination is
/// shown as an abbreviated fingerprint, so the line fits the banner instead
/// of breaking after the glyph.
struct NotificationNotifier: SigningNotifier {

    func signed(keyName: String, authRequired: Bool, bindingChain: [BindingHop],
                silent: Bool, reusedAuthorization: Bool, firstUse: Bool,
                overrides: KeyNotificationOverride?) {
        let preferences = NotificationSettings.current.applying(overrides)
        guard let kind = preferences.signedKind(silent: silent, firstUse: firstUse) else { return }
        let content = UNMutableNotificationContent()
        switch kind {
        case .newDestination:
            content.title = "Signed for a new destination"
        case .silent:
            content.title = reusedAuthorization ? "Signed with a remembered tap" : "Signed without a prompt"
        case .afterPrompt:
            content.title = "Signed"
        }
        content.subtitle = keyLine(keyName, authRequired: authRequired)
        content.body = destinationLine(bindingChain) ?? "\u{1F4CD}\u{00A0}No destination bound"
        content.userInfo = ["keyName": keyName]
        // A unique id per signature keeps each success visible in the stack.
        post(content, identifier: UUID().uuidString)
    }

    func denied(keyName: String, authRequired: Bool, requester: String,
                bindingChain: [BindingHop], reason: PolicyEngine.DenialReason,
                overrides: KeyNotificationOverride?) {
        guard NotificationSettings.current.applying(overrides).allows(reason) else { return }
        let content = UNMutableNotificationContent()
        content.title = "Signature refused"
        content.subtitle = keyLine(keyName, authRequired: authRequired)

        let destination = bindingChain.last.map { destinationLabel($0.fingerprint) }
        switch reason {
        case .appBlocked:
            content.body = "\u{1F6AB}\u{00A0}Blocked app: \(requester)"
        case .destinationBlocked:
            content.body = "\u{1F6AB}\u{00A0}Destination blocked: \(destination ?? "unknown")"
        case .keyLocked:
            content.body = destination.map { "\u{1F512}\u{00A0}Key locked; \($0) is not a known destination" }
                ?? "\u{1F512}\u{00A0}Key locked; destination not known"
        }
        content.userInfo = ["keyName": keyName]

        // A stable id per (key, reason, destination) collapses a retry storm
        // into one banner instead of stacking a copy per rejected attempt.
        let fingerprint = bindingChain.last?.fingerprint ?? "none"
        post(content, identifier: "denied:\(keyName):\(reason):\(fingerprint)")
    }

    /// Second line: the key, prefixed with a Touch ID or key glyph.
    private func keyLine(_ keyName: String, authRequired: Bool) -> String {
        "\(authRequired ? "\u{261D}\u{FE0F}" : "\u{1F511}")\u{00A0}\(keyName)"
    }

    /// The host's name when one is set, otherwise the fingerprint cut down
    /// to fit one banner line. The full fingerprint is one click away in
    /// the key's detail view.
    private func destinationLabel(_ fingerprint: String) -> String {
        HostNames.shared.name(for: fingerprint) ?? OpenSSH.abbreviatedFingerprint(fingerprint)
    }

    /// Third line for a signature: the destination, with a mappin glyph and a
    /// forwarded tag. Nil when the request carried no binding.
    private func destinationLine(_ bindingChain: [BindingHop]) -> String? {
        guard let destination = bindingChain.last else { return nil }
        var line = "\u{1F4CD}\u{00A0}\(destinationLabel(destination.fingerprint))"
        if bindingChain.contains(where: { $0.forwarding }) {
            line += " (forwarded)"
        }
        return line
    }

    private func post(_ content: UNMutableNotificationContent, identifier: String) {
        let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}
