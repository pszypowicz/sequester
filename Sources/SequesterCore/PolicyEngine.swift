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
/// requesting connection.
///
/// A block anywhere on the path wins; otherwise the most specific standing
/// applies, where the exact binding chain beats a branch rule. A locked key then
/// denies anything not already approved. An unlocked key auto-approves
/// local (non-forwarded) use if configured, and otherwise asks.
public enum PolicyEngine {

    public static func evaluate(key: KeyMetadata, bindingChain: [BindingHop]) -> SigningDecision {
        if key.blockForwarded && bindingChain.contains(where: { $0.forwarding }) {
            return .deny
        }
        let record = key.destinations.first { $0.hops == bindingChain }
        if record?.state == .blocked {
            return .deny
        }
        let branchRules = key.branchRules.filter { $0.matches(bindingChain) }
        if branchRules.contains(where: { $0.state == .blocked }) {
            return .deny
        }
        if record?.state == .approved {
            return .allow
        }
        if branchRules.contains(where: { $0.state == .approved }) {
            return .allow
        }
        // Approve-all signs anything not blocked above, forwarded included.
        if key.approveAll {
            return .allow
        }
        // A locked key learns nothing new: only pre-approved paths sign,
        // everything else is denied without asking.
        if key.locked {
            return .deny
        }
        if key.autoApprove && !bindingChain.isEmpty && !bindingChain.contains(where: { $0.forwarding }) {
            return .allow
        }
        return .ask
    }
}
