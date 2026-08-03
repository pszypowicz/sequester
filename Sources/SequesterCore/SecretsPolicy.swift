import Foundation
import SecretsWire

/// Pure decision logic for one secrets request.
///
/// The only inputs are the profile's own settings and whether the user
/// recently approved a read of it. There is deliberately no app axis: the
/// caller of a profile read is whatever ran the CLI, and the terminal or
/// IDE macOS attributes that run to is a presentation detail rather than
/// something an attacker is bound by, so it is shown in prompts and never
/// consulted for the decision.
///
/// Management operations always confirm, since creating, replacing, or
/// destroying a profile is exactly what a user should never learn about
/// only from a notification.
public enum SecretsPolicy {

    public enum Operation: Equatable, Sendable {
        case get
        case set
        case rm
    }

    public enum Outcome: Equatable, Sendable {
        /// Decrypt without an app dialog. An everyRead profile still gets
        /// the Enclave's own Touch ID prompt.
        case proceed
        /// Confirm in a dialog first.
        case dialogAsk
    }

    public static func outcome(tier: SecretTier, operation: Operation, graceActive: Bool) -> Outcome {
        guard operation == .get else { return .dialogAsk }
        switch tier {
        case .everyRead, .noPrompt:
            return .proceed
        case .confirmEveryRead:
            return graceActive ? .proceed : .dialogAsk
        }
    }
}

/// In-memory, per-profile grace windows: after confirming a read the user
/// can waive the next few minutes of confirmations for that profile.
///
/// This replaces the earlier "allow this app for the session" grant, which
/// promised something the app cannot verify. A window is scoped to time
/// alone, so nothing about it can be forged; the honest caveat is that
/// anything running during the window rides along. Nothing is persisted, so
/// windows evaporate when the app restarts.
public final class SecretsGraceWindows: @unchecked Sendable {

    public static let shared = SecretsGraceWindows()

    /// Long enough to cover a burst of commands, short enough that a
    /// forgotten window closes on its own.
    public static let duration: TimeInterval = 300

    private let lock = NSLock()
    private var expiries: [String: Date] = [:]

    public init() {}

    public func grant(profile: String, now: Date = Date()) {
        lock.lock(); defer { lock.unlock() }
        expiries[profile] = now.addingTimeInterval(Self.duration)
    }

    public func isActive(profile: String, now: Date = Date()) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard let expiry = expiries[profile] else { return false }
        if expiry <= now {
            expiries.removeValue(forKey: profile)
            return false
        }
        return true
    }

    /// Dropped when a profile's values or settings change, so a window
    /// opened for the old contents does not carry over to the new ones.
    public func revoke(profile: String) {
        lock.lock(); defer { lock.unlock() }
        expiries.removeValue(forKey: profile)
    }

    public func reset() {
        lock.lock(); defer { lock.unlock() }
        expiries.removeAll()
    }
}
