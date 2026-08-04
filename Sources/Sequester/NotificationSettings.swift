import Foundation
import SequesterCore

/// Where the notification preferences live. The defaults are named once
/// here so the settings toggles and the notifier cannot drift apart, and
/// the notifier reads them per notification, so a change takes effect
/// without restarting the app.
enum NotificationSettings {

    enum Key {
        static let signedSilently = "notifySignedSilently"
        static let signedAfterPrompt = "notifySignedAfterPrompt"
        static let signedNewDestination = "notifySignedNewDestination"
        static let refusedAppBlocked = "notifyRefusedAppBlocked"
        static let refusedDestinationBlocked = "notifyRefusedDestinationBlocked"
        static let refusedKeyLocked = "notifyRefusedKeyLocked"
        static let secretsReadSilently = "notifySecretsReadSilently"
        static let secretsReadAfterPrompt = "notifySecretsReadAfterPrompt"
    }

    /// A signature the user just approved repeats a prompt they answered
    /// seconds ago, so it starts off. Everything else starts on: each one
    /// reports something that showed no UI of its own.
    enum Default {
        static let signedSilently = true
        static let signedAfterPrompt = false
        static let signedNewDestination = true
        static let refusedAppBlocked = true
        static let refusedDestinationBlocked = true
        static let refusedKeyLocked = true
        static let secretsReadSilently = true
        static let secretsReadAfterPrompt = false
    }

    static var current: NotificationPreferences {
        let defaults = UserDefaults.standard
        return NotificationPreferences(
            signedSilently: defaults.bool(Key.signedSilently, default: Default.signedSilently),
            signedAfterPrompt: defaults.bool(Key.signedAfterPrompt, default: Default.signedAfterPrompt),
            signedNewDestination: defaults.bool(Key.signedNewDestination, default: Default.signedNewDestination),
            refusedAppBlocked: defaults.bool(Key.refusedAppBlocked, default: Default.refusedAppBlocked),
            refusedDestinationBlocked: defaults.bool(Key.refusedDestinationBlocked, default: Default.refusedDestinationBlocked),
            refusedKeyLocked: defaults.bool(Key.refusedKeyLocked, default: Default.refusedKeyLocked),
            secretsReadSilently: defaults.bool(Key.secretsReadSilently, default: Default.secretsReadSilently),
            secretsReadAfterPrompt: defaults.bool(Key.secretsReadAfterPrompt, default: Default.secretsReadAfterPrompt)
        )
    }
}

private extension UserDefaults {
    /// `bool(forKey:)` reports false for a key nobody has written, which
    /// would turn every unset preference off instead of leaving it at its
    /// default.
    func bool(_ key: String, default fallback: Bool) -> Bool {
        object(forKey: key) as? Bool ?? fallback
    }
}
