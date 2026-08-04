import Foundation

/// Which classes of notification the user wants to see. Held here as plain
/// values so the choice is decided by pure logic the tests can reach; the
/// app owns where the global copy is persisted, and a key or profile can
/// carry its own.
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
    /// A profile read that showed no UI, either because its tier asks for
    /// none or because a remembered tap covered it.
    public var secretsReadSilently: Bool
    public var secretsReadAfterPrompt: Bool

    public init(signedSilently: Bool = true,
                signedAfterPrompt: Bool = false,
                signedNewDestination: Bool = true,
                refusedAppBlocked: Bool = true,
                refusedDestinationBlocked: Bool = true,
                refusedKeyLocked: Bool = true,
                secretsReadSilently: Bool = true,
                secretsReadAfterPrompt: Bool = false) {
        self.signedSilently = signedSilently
        self.signedAfterPrompt = signedAfterPrompt
        self.signedNewDestination = signedNewDestination
        self.refusedAppBlocked = refusedAppBlocked
        self.refusedDestinationBlocked = refusedDestinationBlocked
        self.refusedKeyLocked = refusedKeyLocked
        self.secretsReadSilently = secretsReadSilently
        self.secretsReadAfterPrompt = secretsReadAfterPrompt
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

    public func allowsSecretsRead(silent: Bool) -> Bool {
        silent ? secretsReadSilently : secretsReadAfterPrompt
    }

    /// The settings a key's own choices produce, leaving the classes a key
    /// has no say over untouched.
    public func applying(_ override: KeyNotificationOverride?) -> NotificationPreferences {
        guard let override else { return self }
        var resolved = self
        resolved.signedSilently = override.signedSilently
        resolved.signedAfterPrompt = override.signedAfterPrompt
        resolved.signedNewDestination = override.signedNewDestination
        resolved.refusedAppBlocked = override.refusedAppBlocked
        resolved.refusedDestinationBlocked = override.refusedDestinationBlocked
        resolved.refusedKeyLocked = override.refusedKeyLocked
        return resolved
    }

    /// The settings a profile's own choices produce.
    public func applying(_ override: ProfileNotificationOverride?) -> NotificationPreferences {
        guard let override else { return self }
        var resolved = self
        resolved.secretsReadSilently = override.readSilently
        resolved.secretsReadAfterPrompt = override.readAfterPrompt
        return resolved
    }

    /// The classes a key governs, as its starting point when the user moves
    /// it off the global settings.
    public var keyOverride: KeyNotificationOverride {
        KeyNotificationOverride(
            signedSilently: signedSilently, signedAfterPrompt: signedAfterPrompt,
            signedNewDestination: signedNewDestination, refusedAppBlocked: refusedAppBlocked,
            refusedDestinationBlocked: refusedDestinationBlocked, refusedKeyLocked: refusedKeyLocked
        )
    }

    /// The classes a profile governs, as its starting point when the user
    /// moves it off the global settings.
    public var profileOverride: ProfileNotificationOverride {
        ProfileNotificationOverride(
            readSilently: secretsReadSilently, readAfterPrompt: secretsReadAfterPrompt
        )
    }
}

/// One key's own notification settings, replacing the global ones for the
/// events that key produces. Absent means it follows the global settings.
public struct KeyNotificationOverride: Codable, Hashable, Sendable {
    public var signedSilently: Bool
    public var signedAfterPrompt: Bool
    public var signedNewDestination: Bool
    public var refusedAppBlocked: Bool
    public var refusedDestinationBlocked: Bool
    public var refusedKeyLocked: Bool

    public init(signedSilently: Bool, signedAfterPrompt: Bool, signedNewDestination: Bool,
                refusedAppBlocked: Bool, refusedDestinationBlocked: Bool, refusedKeyLocked: Bool) {
        self.signedSilently = signedSilently
        self.signedAfterPrompt = signedAfterPrompt
        self.signedNewDestination = signedNewDestination
        self.refusedAppBlocked = refusedAppBlocked
        self.refusedDestinationBlocked = refusedDestinationBlocked
        self.refusedKeyLocked = refusedKeyLocked
    }
}

/// One profile's own notification settings. Absent means it follows the
/// global settings.
public struct ProfileNotificationOverride: Codable, Hashable, Sendable {
    public var readSilently: Bool
    public var readAfterPrompt: Bool

    public init(readSilently: Bool, readAfterPrompt: Bool) {
        self.readSilently = readSilently
        self.readAfterPrompt = readAfterPrompt
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
