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

    init() {
        reload()
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

    func setAutoApprove(name: String, enabled: Bool) throws {
        try EnclaveKeyStore.setAutoApprove(name: name, enabled: enabled)
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

    func setBranchRule(name: String, hops: [ChainHop], state: DestinationState) {
        EnclaveKeyStore.setBranchRule(name: name, hops: hops, state: state)
        reload()
    }

    func delete(name: String) throws {
        try EnclaveKeyStore.delete(name: name)
        reload()
    }
}
