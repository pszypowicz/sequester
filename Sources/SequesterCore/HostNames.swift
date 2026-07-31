import Foundation
import os

/// Names the user has given to host key fingerprints. The agent protocol
/// conveys only host keys, so a name is something you assign once and then
/// see everywhere that key appears, across every key that talks to it.
public final class HostNames: @unchecked Sendable {

    public static let shared = HostNames()

    private static let defaultsKey = "hostNames"

    private let lock: OSAllocatedUnfairLock<[String: String]>

    private init() {
        let stored = UserDefaults.standard.dictionary(forKey: Self.defaultsKey) as? [String: String] ?? [:]
        lock = OSAllocatedUnfairLock(initialState: stored)
    }

    public func all() -> [String: String] {
        lock.withLock { $0 }
    }

    public func name(for fingerprint: String) -> String? {
        lock.withLock { $0[fingerprint] }
    }

    /// The name when one is set, the fingerprint otherwise.
    public func label(for fingerprint: String) -> String {
        name(for: fingerprint) ?? fingerprint
    }

    public func setName(_ name: String?, for fingerprint: String) {
        let trimmed = name?.trimmingCharacters(in: .whitespacesAndNewlines)
        let updated = lock.withLock { names -> [String: String] in
            if let trimmed, !trimmed.isEmpty {
                names[fingerprint] = trimmed
            } else {
                names.removeValue(forKey: fingerprint)
            }
            return names
        }
        UserDefaults.standard.set(updated, forKey: Self.defaultsKey)
        Log.store.log("Named host \(fingerprint, privacy: .public) as \(name ?? "(cleared)", privacy: .public)")
    }
}
