import Foundation

/// Which classes of key notification the user wants to see. Held here as
/// plain values so the choice is decided by pure logic the tests can reach;
/// the app owns where they are persisted.
public struct NotificationPreferences: Equatable, Sendable {

    /// A signature that showed no UI at all. The only evidence such a use
    /// happened, which is why turning it off is a deliberate act in the UI
    /// rather than an ordinary toggle.
    public var signedSilently: Bool
    /// A signature the user just approved at a dialog or a Touch ID prompt,
    /// so the notification repeats what they have already seen.
    public var signedAfterPrompt: Bool
    /// The first signature a key makes for a binding chain, whatever
    /// prompting it involved.
    public var signedNewDestination: Bool
    public var refusedAppBlocked: Bool
    public var refusedDestinationBlocked: Bool
    public var refusedKeyLocked: Bool

    public init(signedSilently: Bool = true,
                signedAfterPrompt: Bool = false,
                signedNewDestination: Bool = true,
                refusedAppBlocked: Bool = true,
                refusedDestinationBlocked: Bool = true,
                refusedKeyLocked: Bool = true) {
        self.signedSilently = signedSilently
        self.signedAfterPrompt = signedAfterPrompt
        self.signedNewDestination = signedNewDestination
        self.refusedAppBlocked = refusedAppBlocked
        self.refusedDestinationBlocked = refusedDestinationBlocked
        self.refusedKeyLocked = refusedKeyLocked
    }

    /// What a signature notification should announce, or nil when the user
    /// has turned that class off.
    ///
    /// A first signature for a destination outranks the other two: it says
    /// something they cannot, and it happens once per chain, so it is worth
    /// hearing even from someone who has silenced routine signatures.
    public func signedKind(silent: Bool, firstUse: Bool) -> SignedNotification? {
        if firstUse && signedNewDestination {
            return .newDestination
        }
        if silent {
            return signedSilently ? .silent : nil
        }
        return signedAfterPrompt ? .afterPrompt : nil
    }

    /// Whether a refusal of this kind should be announced.
    public func allows(_ reason: PolicyEngine.DenialReason) -> Bool {
        switch reason {
        case .appBlocked: refusedAppBlocked
        case .destinationBlocked: refusedDestinationBlocked
        case .keyLocked: refusedKeyLocked
        }
    }
}

/// What a signature notification is about, once preferences have been
/// applied.
public enum SignedNotification: Equatable, Sendable {
    /// The key's first signature for this destination.
    case newDestination
    /// A signature that showed no UI.
    case silent
    /// A signature the user approved at a prompt.
    case afterPrompt
}
