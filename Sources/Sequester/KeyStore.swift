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

    func create(name: String, description: String, authRequired: Bool, policy: SigningPolicy) throws {
        try EnclaveKeyStore.create(
            name: name, description: description,
            authRequired: authRequired, policy: policy
        )
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

    func setPolicy(name: String, policy: SigningPolicy) throws {
        try EnclaveKeyStore.updatePolicy(name: name, policy: policy)
        reload()
    }

    func delete(name: String) throws {
        try EnclaveKeyStore.delete(name: name)
        reload()
    }
}
