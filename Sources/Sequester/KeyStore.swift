import Foundation
import AppKit
import Observation
import SequesterCore

/// UI-facing view of the key inventory. All mutations go through
/// EnclaveKeyStore and end in a reload, so this is never more than a cache
/// of the keychain state.
@MainActor
@Observable
final class KeyStore {

    private(set) var keys: [KeyMetadata] = []
    private(set) var unreadable: [UnreadableItem] = []

    var enclaveAvailable: Bool { EnclaveKeyStore.isEnclaveAvailable }

    @ObservationIgnored nonisolated(unsafe) private var observers: [any NSObjectProtocol] = []

    init() {
        reload()
        // Reload live when the agent records or approves a destination on a
        // background thread, so an open key page updates in place.
        observers = [
            NotificationCenter.default.addObserver(
                forName: .sequesterKeysDidChange, object: nil, queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.reload() }
            },
            // The change notification is in-process, so a second
            // instance run from a terminal can edit the keychain
            // without this one hearing it. Refresh whenever the app
            // comes forward, which is when a stale list would show.
            NotificationCenter.default.addObserver(
                forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.reload() }
            },
        ]
    }

    deinit {
        for observer in observers {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    func reload() {
        let inventory = EnclaveKeyStore.inventory()
        keys = inventory.keys
        unreadable = inventory.unreadable
    }

    func create(name: String, description: String, authRequired: Bool, comment: String?) throws {
        try EnclaveKeyStore.create(name: name, description: description, authRequired: authRequired, comment: comment)
        reload()
    }

    func setDescription(name: String, description: String) throws {
        try EnclaveKeyStore.updateDescription(name: name, description: description)
        reload()
    }

    func setComment(name: String, comment: String?) throws {
        try EnclaveKeyStore.updateComment(name: name, comment: comment)
        reload()
    }

    func rename(name: String, to newName: String) throws {
        try EnclaveKeyStore.rename(name: name, to: newName)
        reload()
    }

    func setBlockForwarded(name: String, blocked: Bool) throws {
        try EnclaveKeyStore.setBlockForwarded(name: name, blocked: blocked)
        reload()
    }

    func setApproveAll(name: String, enabled: Bool) throws {
        try EnclaveKeyStore.setApproveAll(name: name, enabled: enabled)
        reload()
    }

    func setAutoApprove(name: String, enabled: Bool) throws {
        try EnclaveKeyStore.setAutoApprove(name: name, enabled: enabled)
        reload()
    }

    func setRememberSeconds(name: String, seconds: TimeInterval) throws {
        try EnclaveKeyStore.setRememberSeconds(name: name, seconds: seconds)
        reload()
    }

    func setNotifications(name: String, override: KeyNotificationOverride?) throws {
        try EnclaveKeyStore.setNotifications(name: name, override: override)
        reload()
    }

    func setLocked(name: String, locked: Bool) throws {
        try EnclaveKeyStore.setLocked(name: name, locked: locked)
        reload()
    }

    func setDestinationState(name: String, id: String, state: DestinationState) {
        EnclaveKeyStore.setDestinationState(name: name, id: id, state: state)
        reload()
    }

    func removeDestination(name: String, id: String) {
        EnclaveKeyStore.removeDestination(name: name, id: id)
        reload()
    }

    func removeDestinationsUnder(name: String, prefix: [BindingHop]) {
        EnclaveKeyStore.removeDestinationsUnder(name: name, prefix: prefix)
        reload()
    }

    func setBranchRule(name: String, hops: [BindingHop], state: DestinationState) {
        EnclaveKeyStore.setBranchRule(name: name, hops: hops, state: state)
        reload()
    }

    func setAppRule(name: String, identity: String, displayName: String, state: AppState) {
        _ = try? EnclaveKeyStore.setAppRule(name: name, identity: identity, displayName: displayName, state: state)
        reload()
    }

    func removeAppRule(name: String, identity: String) {
        EnclaveKeyStore.removeAppRule(name: name, identity: identity)
        reload()
    }

    func delete(name: String) throws {
        try EnclaveKeyStore.delete(name: name)
        reload()
    }

    func deleteUnreadable(name: String) throws {
        try EnclaveKeyStore.deleteUnreadable(name: name)
        reload()
    }
}
