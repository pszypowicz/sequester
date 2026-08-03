/// How a profile read is confirmed, fixed when the profile is created.
///
/// The choice is between hardware enforcement and an app-level check; it
/// never depends on which app is asking. A local process can always run the
/// CLI, and the process a request is attributed to (the terminal or IDE) is
/// a presentation detail macOS derives for its own UI, not a boundary an
/// attacker is bound by. So the requester is shown for context and never
/// consulted for the decision.
public enum SecretTier: String, Codable, Sendable, CaseIterable {
    /// userPresence baked into the Enclave key's access control: the
    /// Enclave itself refuses to decrypt without Touch ID.
    case everyRead
    /// Sequester asks for confirmation in a dialog before decrypting, with
    /// an optional grace window after an approval.
    case confirmEveryRead
    /// No confirmation. The read still posts a notification.
    case noPrompt

    public var displayLabel: String {
        switch self {
        case .everyRead: "Touch ID on every read"
        case .confirmEveryRead: "Confirm every read"
        case .noPrompt: "No prompt"
        }
    }

    /// Which component refuses when a read is not confirmed. Surfaced
    /// verbatim in the UI and CLI so the softer tiers never read as
    /// hardware-enforced.
    public var enforcementLabel: String {
        switch self {
        case .everyRead: "Enforced by the Secure Enclave"
        case .confirmEveryRead: "Enforced by Sequester"
        case .noPrompt: "Notification only"
        }
    }

}
