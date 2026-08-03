import Foundation
import SecretsWire

/// Pure decision logic for one secrets request, over the profile's tier and
/// settings and the requesting app's standing. Dialogs and the biometric
/// check stay outside so this is unit-testable.
///
/// Precedence: a blocked app wins and denies any operation. Management
/// operations (set, rm) always confirm, since approve-all and app approval
/// govern reads, not changes to the profile itself. For reads, an allowed
/// app or an approve-all profile proceeds silently; an unknown caller is
/// asked, and the tier decides how the ask is enforced.
public enum SecretsPolicy {

    public enum Operation: Equatable, Sendable {
        case get
        case set
        case rm
    }

    /// Why a request was refused before any prompt.
    public enum DenialReason: Equatable, Sendable {
        case appBlocked
    }

    public enum Outcome: Equatable, Sendable {
        /// Proceed without an app dialog. An everyRead profile still gets
        /// the Enclave's own prompt during decryption.
        case silentAllow
        /// Show the approval dialog when a scope decision can be captured,
        /// then require the app-evaluated biometric check before decrypting.
        case biometricGate
        /// Show the approval dialog; on allow, proceed per tier.
        case dialogAsk
        /// Refuse before any prompt.
        case deny(DenialReason)
    }

    public static func outcome(tier: SecretTier, standing: AppStanding,
                               operation: Operation, approveAll: Bool) -> Outcome {
        if standing == .blocked {
            return .deny(.appBlocked)
        }
        guard operation == .get else {
            return .dialogAsk
        }
        if standing == .allowed || approveAll {
            return .silentAllow
        }
        switch tier {
        case .unapprovedOnly:
            return .biometricGate
        case .everyRead, .policyOnly:
            return .dialogAsk
        }
    }
}
