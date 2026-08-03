import Foundation

/// Standing for a requesting app as a policy subject, mirroring the
/// per-destination standings but keyed on the app's verified code identity.
public enum AppState: String, Codable, Sendable {
    case allowed
    case blocked
}

/// A persisted global authorization for an app, keyed by its verified code
/// identity (`Provenance.identityKey`), which is stable across app updates.
public struct AppAuthorization: Codable, Hashable, Sendable, Identifiable {
    public var identity: String
    /// The label last seen for this identity, for the management UI. Not part
    /// of the identity, so a spoofed name can never match a stored rule.
    public var displayName: String
    public var state: AppState
    public var firstSeen: Date
    public var lastUsed: Date

    public var id: String { identity }

    public init(identity: String, displayName: String, state: AppState, firstSeen: Date, lastUsed: Date) {
        self.identity = identity
        self.displayName = displayName
        self.state = state
        self.firstSeen = firstSeen
        self.lastUsed = lastUsed
    }
}

/// A per-key override of an app's standing, taking precedence over the global
/// authorization for that key.
public struct AppRule: Codable, Hashable, Sendable, Identifiable {
    public var identity: String
    public var displayName: String
    public var state: AppState

    public var id: String { identity }

    public init(identity: String, displayName: String, state: AppState) {
        self.identity = identity
        self.displayName = displayName
        self.state = state
    }
}

/// The effective standing of the requesting app for one request, after
/// resolving the per-key override, the global authorization, and any
/// in-memory session grant.
public enum AppStanding: Equatable, Sendable {
    /// Blocked globally, per key, or for this session: deny outright.
    case blocked
    /// Permanently allowed (global or per-key) or allowed for this session.
    case allowed
    /// Never authorized: an authorization decision is needed, so ask.
    case unknown
}

/// What the user chose to remember about the requesting app when answering
/// the approval dialog, beyond the single signature.
public enum AppScope: String, Sendable {
    /// Sign this once; remember nothing about the app.
    case once
    /// Allow every request from this app instance until it (its responsible
    /// process) exits or the agent restarts.
    case session
    /// Permanently allow this app. Verified peers only.
    case always
    /// Permanently block this app (verified), or block this session (unverified).
    case block
}

/// In-memory, agent-lifetime session grants. A verified app can be allowed for
/// the lifetime of its responsible process (the terminal or IDE that launched
/// the ssh client); an unverified peer can be blocked for that lifetime to
/// silence a burst of prompts. Nothing here is persisted, so it evaporates on
/// restart, matching the "this session" promise.
public final class AppSessionGrants: @unchecked Sendable {

    public static let shared = AppSessionGrants()

    private let lock = NSLock()
    private var allowed: Set<String> = []   // "<identityKey>@<instance>"
    private var blocked: Set<String> = []   // "<instance>"

    public init() {}

    public func allow(identity: String, instance: String) {
        lock.lock(); defer { lock.unlock() }
        allowed.insert("\(identity)@\(instance)")
    }

    public func isAllowed(identity: String, instance: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return allowed.contains("\(identity)@\(instance)")
    }

    public func block(instance: String) {
        lock.lock(); defer { lock.unlock() }
        blocked.insert(instance)
    }

    public func isBlocked(instance: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return blocked.contains(instance)
    }

    public func reset() {
        lock.lock(); defer { lock.unlock() }
        allowed.removeAll()
        blocked.removeAll()
    }
}

/// Persists what a user chose to remember about a requesting app when
/// answering an approval dialog. A permanent allow or block needs a verified
/// identity; an unverified peer can only be blocked for the session. Shared
/// by the agent and the secrets broker so both record scope decisions
/// identically.
public enum AppDecisionRecorder {
    public static func apply(_ scope: AppScope, provenance: Provenance, instanceID: String?) {
        switch scope {
        case .once:
            break
        case .session:
            if let identity = provenance.identityKey, let instance = instanceID {
                AppSessionGrants.shared.allow(identity: identity, instance: instance)
            }
        case .always:
            if let identity = provenance.identityKey {
                AppAuthorizationStore.setState(identity: identity, displayName: provenance.displayName,
                                               state: .allowed, now: Date())
            }
        case .block:
            if let identity = provenance.identityKey {
                AppAuthorizationStore.setState(identity: identity, displayName: provenance.displayName,
                                               state: .blocked, now: Date())
            } else if let instance = instanceID {
                AppSessionGrants.shared.block(instance: instance)
            }
        }
    }
}

/// Resolves the effective `AppStanding` for a request from the persisted
/// stores plus session grants. Kept as pure data-in/decision-out so it is
/// unit-testable without keychain or live processes.
public enum AppPolicy {

    public static func standing(
        identityKey: String?,
        instance: String?,
        perKeyRules: [AppRule],
        globalLookup: (String) -> AppState?,
        sessionAllowed: (String, String) -> Bool,
        sessionBlocked: (String) -> Bool
    ) -> AppStanding {
        // Verified peer: it has a stable identity that can carry a persisted
        // or session standing.
        if let identityKey {
            if let rule = perKeyRules.first(where: { $0.identity == identityKey }) {
                return rule.state == .blocked ? .blocked : .allowed
            }
            if let global = globalLookup(identityKey) {
                return global == .blocked ? .blocked : .allowed
            }
            if let instance, sessionAllowed(identityKey, instance) {
                return .allowed
            }
            return .unknown
        }
        // Unverified peer: no stable identity, so it can only be blocked for
        // the session (to stop prompt spam); never remembered as allowed.
        if let instance, sessionBlocked(instance) {
            return .blocked
        }
        return .unknown
    }
}
