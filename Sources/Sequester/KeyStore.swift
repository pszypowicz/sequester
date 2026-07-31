import Foundation
import Observation
import SequesterCore

/// UI-facing view of the key inventory. All mutations go through
/// EnclaveKeyStore and end in a reload, so this is never more than a cache
/// of the keychain state.
@MainActor
@Observable
final class KeyStore {

    private(set) var keys: [KeyMetadata] = []

    var enclaveAvailable: Bool { EnclaveKeyStore.isEnclaveAvailable }

    @ObservationIgnored nonisolated(unsafe) private var observer: (any NSObjectProtocol)?

    init() {
        reload()
        // Reload live when the agent records or approves a destination on a
        // background thread, so an open key page updates in place.
        observer = NotificationCenter.default.addObserver(
            forName: .sequesterKeysDidChange, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.reload() }
        }
    }

    deinit {
        if let observer {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    func reload() {
        keys = EnclaveKeyStore.list()
    }

    func create(name: String, description: String, authRequired: Bool) throws {
        try EnclaveKeyStore.create(name: name, description: description, authRequired: authRequired)
        reload()
    }

    func setDescription(name: String, description: String) throws {
        try EnclaveKeyStore.updateDescription(name: name, description: description)
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
}
