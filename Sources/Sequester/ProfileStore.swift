import Foundation
import Observation
import SequesterCore
import SecretsWire

/// UI-facing view of the secrets profile inventory. All mutations go
/// through EnclaveProfileStore and end in a reload, so this is never more
/// than a cache of the keychain state.
@MainActor
@Observable
final class ProfileStore {

    private(set) var profiles: [ProfileMetadata] = []

    var enclaveAvailable: Bool { EnclaveProfileStore.isEnclaveAvailable }

    @ObservationIgnored nonisolated(unsafe) private var observer: (any NSObjectProtocol)?

    init() {
        reload()
        // Reload live when the broker records a read or a CLI-driven change
        // on a background thread, so an open profile page updates in place.
        observer = NotificationCenter.default.addObserver(
            forName: .sequesterProfilesDidChange, object: nil, queue: .main
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
        profiles = EnclaveProfileStore.list()
    }

    func create(name: String, tier: SecretTier, exportDisabled: Bool, values: [String: String]) throws {
        try EnclaveProfileStore.create(name: name, tier: tier, exportDisabled: exportDisabled, values: values)
        reload()
    }

    func rename(name: String, to newName: String) throws {
        try EnclaveProfileStore.rename(name: name, to: newName)
        reload()
    }

    func setExportDisabled(name: String, disabled: Bool) throws {
        try EnclaveProfileStore.setExportDisabled(name: name, disabled: disabled)
        reload()
    }

    /// Values edited in settings still decrypt and re-seal, so an everyRead
    /// profile prompts once here.
    func updateValues(name: String, setting: [String: String], removing: Set<String>) throws {
        try EnclaveProfileStore.updateValues(
            name: name, setting: setting, removing: removing,
            reason: "update secrets profile \"\(name)\" from Sequester settings"
        )
        reload()
    }

    func delete(name: String) throws {
        try EnclaveProfileStore.delete(name: name)
        reload()
    }
}
