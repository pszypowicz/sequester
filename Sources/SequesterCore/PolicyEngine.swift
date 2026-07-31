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

/// Pure decision logic over a key's settings, the requesting app's standing,
/// and the binding chain of the requesting connection.
///
/// Precedence: a blocked app, or a block anywhere on the path (the exact
/// chain, a branch rule, or block-forwarded), wins and denies. Otherwise an
/// app that has never been authorized is asked (so the user can authorize or
/// block it). Otherwise the destination axis decides as before - an approval
/// (exact chain, branch rule, or approve-all) allows, a locked key denies, an
/// unlocked key auto-approves local use if configured, everything else asks -
/// except that an unverified requester is never signed for silently.
/// Block-wins is the safe default for a security tool.
public enum PolicyEngine {

    public static func evaluate(key: KeyMetadata, bindingChain: [BindingHop],
                                appStanding: AppStanding,
                                trust: Provenance.Trust) -> SigningDecision {
        // A blocked app is refused outright, like a destination block.
        if appStanding == .blocked {
            return .deny
        }

        // Destination-axis blocks still win over any approval.
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

        // Resolve the destination axis before the app gate. A destination-level
        // deny - a locked key facing a path it has not already approved - is
        // absolute: authorizing the app must not reopen it, and a denied
        // request must not grow the destination list, so it wins over the
        // app gate's ask.
        let destination = destinationDecision(key: key, bindingChain: bindingChain,
                                              record: record, branchRules: branchRules)
        if destination == .deny {
            return .deny
        }

        // The app must be authorized before anything signs. An app that has
        // never been seen is asked, so the user can authorize or block it -
        // even for a Touch ID key, whose Enclave prompt cannot capture that
        // choice.
        if appStanding == .unknown {
            return .ask
        }

        // A silent signature requires a verified requester; an unverified peer
        // that would otherwise sign silently is downgraded to asking.
        if trust == .unverified && destination == .allow {
            return .ask
        }
        return destination
    }

    private static func destinationDecision(key: KeyMetadata, bindingChain: [BindingHop],
                                            record: DestinationRecord?,
                                            branchRules: [BranchRule]) -> SigningDecision {
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
