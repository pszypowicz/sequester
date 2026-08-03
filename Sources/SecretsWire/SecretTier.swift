/// A profile's Touch ID requirement, fixed when the profile is created. The
/// Enclave's access control is all-or-nothing per key and cannot exempt a
/// single caller, so only `everyRead` is enforced by hardware; the softer
/// tiers are app-level gates in front of a key the app can use without them.
public enum SecretTier: String, Codable, Sendable, CaseIterable {
    /// userPresence baked into the Enclave key's access control: every read
    /// prompts, even for approved callers.
    case everyRead
    /// Approved callers read silently; every other caller must pass a
    /// biometric check the app evaluates before decrypting.
    case unapprovedOnly
    /// No biometry: unknown callers get a plain approval dialog.
    case policyOnly

    public var displayLabel: String {
        switch self {
        case .everyRead: "Touch ID on every read"
        case .unapprovedOnly: "Touch ID for unapproved callers"
        case .policyOnly: "Policy only"
        }
    }

    /// Which component refuses when access is not granted. Surfaced verbatim
    /// in the UI and CLI so the softer tiers never read as hardware-enforced.
    public var enforcementLabel: String {
        switch self {
        case .everyRead: "Enforced by the Secure Enclave"
        case .unapprovedOnly, .policyOnly: "Enforced by Sequester"
        }
    }
}
