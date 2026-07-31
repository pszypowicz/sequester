import Foundation

public enum SigningDecision: Equatable, Sendable {
    /// Sign without an app dialog. Keys with the Touch ID requirement
    /// still get the Enclave's own prompt.
    case allow
    /// Confirmation needed: the app dialog, or for Touch ID keys the
    /// Enclave prompt itself.
    case ask
    /// Refuse before any prompt is shown.
    case deny
}

/// Pure decision logic over a key's settings and the binding chain of the
/// requesting connection. Unknown paths ask; only an explicit standing or
/// the key-level forwarding block changes that.
public enum PolicyEngine {

    public static func evaluate(key: KeyMetadata, chain: [ChainHop]) -> SigningDecision {
        if key.blockForwarded && chain.contains(where: { $0.forwarding }) {
            return .deny
        }
        guard let record = key.destinations.first(where: { $0.hops == chain }) else {
            return .ask
        }
        switch record.state {
        case .blocked:
            return .deny
        case .approved:
            return .allow
        case .neutral:
            return .ask
        }
    }
}
