import Foundation
import AppKit
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
    private(set) var unreadable: [UnreadableItem] = []

    var enclaveAvailable: Bool { EnclaveProfileStore.isEnclaveAvailable }

    @ObservationIgnored nonisolated(unsafe) private var observers: [any NSObjectProtocol] = []

    init() {
        reload()
        // Reload live when the broker records a read or a CLI-driven change
        // on a background thread, so an open profile page updates in place.
        observers = [
            NotificationCenter.default.addObserver(
                forName: .sequesterProfilesDidChange, object: nil, queue: .main
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
        let inventory = EnclaveProfileStore.inventory()
        profiles = inventory.profiles
        unreadable = inventory.unreadable
    }

    func create(name: String, tier: SecretTier, exportDisabled: Bool, values: [String: String]) throws {
        try EnclaveProfileStore.create(name: name, tier: tier, exportDisabled: exportDisabled, values: values)
        reload()
    }

    func rename(name: String, to newName: String) throws {
        try EnclaveProfileStore.rename(name: name, to: newName)
        reload()
    }

    func setRememberSeconds(name: String, seconds: TimeInterval) throws {
        try EnclaveProfileStore.setRememberSeconds(name: name, seconds: seconds)
        reload()
    }

    func setNotifications(name: String, override: ProfileNotificationOverride?) throws {
        try EnclaveProfileStore.setNotifications(name: name, override: override)
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
