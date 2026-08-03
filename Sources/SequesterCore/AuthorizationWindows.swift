import Foundation
import LocalAuthentication
import CoreGraphics

/// Holds an authenticated LAContext for a while so a burst of operations
/// costs one Touch ID tap instead of one per operation.
///
/// A context that has satisfied a key's access control keeps that
/// authorization for every later operation handed the same instance, and it
/// carries no expiry of its own: it survives a screen lock, and the system
/// will not discard it. Every bound is therefore enforced here. Deadlines
/// come from the monotonic clock so moving the system clock back cannot
/// extend a window, and the whole store is emptied whenever the screen
/// locks.
///
/// Windows are opt-in per key and per profile and are off by default.
public final class AuthorizationWindows: @unchecked Sendable {

    public static let shared = AuthorizationWindows()

    private struct Entry {
        let context: LAContext
        let deadline: UInt64
    }

    private let lock = NSLock()
    private var entries: [String: Entry] = [:]
    private let now: @Sendable () -> UInt64
    private var observers: [any NSObjectProtocol] = []

    public init(now: @escaping @Sendable () -> UInt64 = { clock_gettime_nsec_np(CLOCK_MONOTONIC) }) {
        self.now = now
    }

    /// The context remembered for this scope, or nil when none is held or
    /// the window has run out. An expired entry is discarded on the way.
    public func existing(scope: String) -> LAContext? {
        lock.lock()
        defer { lock.unlock() }
        guard let entry = entries[scope] else { return nil }
        guard now() < entry.deadline else {
            entry.context.invalidate()
            entries.removeValue(forKey: scope)
            return nil
        }
        return entry.context
    }

    /// Remembers an authenticated context for `seconds`. A duration of zero
    /// or less remembers nothing, which is the default everywhere.
    public func remember(scope: String, context: LAContext, seconds: TimeInterval) {
        guard seconds > 0 else { return }
        lock.lock()
        defer { lock.unlock() }
        if let existing = entries[scope], existing.context !== context {
            existing.context.invalidate()
        }
        entries[scope] = Entry(context: context, deadline: now() + UInt64(seconds * 1_000_000_000))
    }

    /// Drops every window whose scope starts with this prefix, used when a
    /// credential's settings or contents change under a held authorization.
    public func invalidate(prefix: String) {
        lock.lock()
        defer { lock.unlock() }
        for (scope, entry) in entries where scope.hasPrefix(prefix) {
            entry.context.invalidate()
            entries.removeValue(forKey: scope)
        }
    }

    public func invalidateAll() {
        lock.lock()
        defer { lock.unlock() }
        guard !entries.isEmpty else { return }
        for entry in entries.values {
            entry.context.invalidate()
        }
        entries.removeAll()
        Log.store.log("Discarded all remembered authorizations")
    }

    /// Starts discarding held authorizations when the screen locks. Both
    /// signals are watched because a held context outlives a lock on its
    /// own, so missing the event would leave an authorization alive for
    /// whoever gets in next.
    public func startObservingLock() {
        lock.lock()
        defer { lock.unlock() }
        guard observers.isEmpty else { return }
        let center = DistributedNotificationCenter.default()
        for name in ["com.apple.screenIsLocked", "com.apple.sessionDidMoveOffConsole"] {
            observers.append(center.addObserver(
                forName: Notification.Name(name), object: nil, queue: nil
            ) { [weak self] _ in
                self?.invalidateAll()
            })
        }
    }

    /// True when the login session reports the screen as locked, checked
    /// before reusing a context so a missed notification cannot leave one
    /// usable.
    public static func screenIsLocked() -> Bool {
        guard let session = CGSessionCopyCurrentDictionary() as? [String: Any] else { return false }
        return session["CGSSessionScreenIsLocked"] as? Bool ?? false
    }
}

/// Builds the scope strings that windows are keyed on, and decides where a
/// window may be opened at all.
public enum AuthorizationScope {

    public static func profile(_ name: String) -> String {
        "profile:\(name)"
    }

    public static func profilePrefix(_ name: String) -> String {
        "profile:\(name)"
    }

    /// A signing window covers one key reaching one destination over one
    /// exact path, so a tap for a host says nothing about the same host
    /// reached another way.
    ///
    /// Returns nil when no window may be opened: an unbound request has no
    /// destination to scope to, and a chain with a forwarding hop is a
    /// request arriving from a remote host, where the Touch ID prompt is
    /// the last human gate and must not be skipped.
    public static func key(_ name: String, bindingChain: [BindingHop]) -> String? {
        guard !bindingChain.isEmpty else { return nil }
        guard !bindingChain.contains(where: { $0.forwarding }) else { return nil }
        return "key:\(name):\(DestinationRecord.bindingChainID(bindingChain))"
    }

    public static func keyPrefix(_ name: String) -> String {
        "key:\(name):"
    }
}
