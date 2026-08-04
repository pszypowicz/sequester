import Foundation
import CryptoKit
import LocalAuthentication
import SecretsWire

public enum ProfileStoreError: LocalizedError {
    case enclaveUnavailable
    case tooManyVariables
    case valueTooLarge(String)
    case profileTooLarge

    public var errorDescription: String? {
        switch self {
        case .enclaveUnavailable:
            "This Mac has no available Secure Enclave, so Sequester cannot create profiles."
        case .tooManyVariables:
            "A profile can hold at most \(SecretsWireLimits.maxVariables) variables."
        case .valueTooLarge(let name):
            "The value of \(name) exceeds \(SecretsWireLimits.maxValueBytes / 1024) KiB."
        case .profileTooLarge:
            "The profile exceeds \(SecretsWireLimits.maxPlaintextBytes / 1024) KiB of values."
        }
    }
}

/// Stateless operations over the secrets profile inventory. Safe to call
/// from any thread; the observable UI store and the broker both go through
/// here.
public enum EnclaveProfileStore {

    public static var isEnclaveAvailable: Bool {
        SecureEnclave.isAvailable
    }

    /// Validates the names and sizes of values being written. The total
    /// variable count and plaintext size are checked at seal time, after
    /// any merge.
    static func validate(values: [String: String]) throws {
        for (name, value) in values {
            try EnvName.validate(name)
            guard value.utf8.count <= SecretsWireLimits.maxValueBytes else {
                throw ProfileStoreError.valueTooLarge(name)
            }
        }
    }

    private static func sealChecked(_ values: [String: String], to recipient: P256.KeyAgreement.PublicKey) throws -> Data {
        guard values.count <= SecretsWireLimits.maxVariables else {
            throw ProfileStoreError.tooManyVariables
        }
        let plaintext = try ProfileCipher.encodeValues(values)
        guard plaintext.count <= SecretsWireLimits.maxPlaintextBytes else {
            throw ProfileStoreError.profileTooLarge
        }
        return try ProfileCipher.seal(plaintext, to: recipient)
    }

    /// Creates a profile without any prompt: sealing needs only the public
    /// key, and only the everyRead tier bakes userPresence into the Enclave
    /// key's access control.
    @discardableResult
    public static func create(name: String, tier: SecretTier, exportDisabled: Bool,
                              values: [String: String]) throws -> ProfileMetadata {
        try ProfileName.validate(name)
        try validate(values: values)
        guard isEnclaveAvailable else { throw ProfileStoreError.enclaveUnavailable }

        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if tier == .everyRead {
            flags.insert(.userPresence)
        }
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &accessError
        ) else {
            throw accessError!.takeRetainedValue() as Error
        }

        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let sealed = try sealChecked(values, to: key.publicKey)
        let now = Date()
        let metadata = ProfileMetadata(
            name: name,
            tier: tier,
            variableNames: values.keys.sorted(),
            exportDisabled: exportDisabled,
            publicKey: key.publicKey.x963Representation,
            createdAt: now,
            updatedAt: now
        )
        try ProfileStorage.save(value: StoredProfileValue(keyData: key.dataRepresentation, sealed: sealed),
                                metadata: metadata)
        Log.secrets.log("Created profile \(name, privacy: .public), tier \(tier.rawValue, privacy: .public), \(values.count, privacy: .public) variables")
        return metadata
    }

    public static func list() -> [ProfileMetadata] {
        inventory().profiles
    }

    /// The full inventory, including items this version cannot read.
    public static func inventory() -> (profiles: [ProfileMetadata], unreadable: [UnreadableItem]) {
        (try? ProfileStorage.list()) ?? ([], [])
    }

    public static func find(name: String) -> ProfileMetadata? {
        try? ProfileStorage.load(name: name).metadata
    }

    /// Decrypts a profile's values. On an everyRead profile the Enclave
    /// demands user presence here, showing `reason` in its prompt.
    ///
    /// Unless the profile has a remembered-tap window open, the LAContext
    /// must be a fresh one per read. A context that has once satisfied the
    /// key's access control keeps that authorization for every later
    /// operation passed the same instance, with no expiry of its own, so
    /// reusing one outside a window would turn "Touch ID on every read"
    /// into an unbounded waiver.
    public static func readValues(name: String, reason: String) throws -> (values: [String: String], reusedAuthorization: Bool) {
        let stored = try ProfileStorage.load(name: name)
        let scope = stored.metadata.rememberSeconds > 0 && stored.metadata.tier == .everyRead
            ? AuthorizationScope.profile(name) : nil
        // A held authorization outlives a screen lock, so never reuse one
        // while the screen reports itself locked.
        let held = scope.flatMap { AuthorizationWindows.shared.existing(scope: $0) }
        let reused = held != nil && !AuthorizationWindows.screenIsLocked()

        let context = reused ? held! : LAContext()
        if !reused { context.localizedReason = reason }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: stored.value.keyData,
            authenticationContext: context
        )
        let plaintext = try ProfileCipher.open(stored.value.sealed, with: key)
        let values = try ProfileCipher.decodeValues(plaintext)
        if let scope {
            AuthorizationWindows.shared.remember(scope: scope, context: context,
                                                 seconds: stored.metadata.rememberSeconds)
        }
        _ = try? ProfileStorage.mutate(name: name) { $0.lastRead = Date(); return true }
        Log.secrets.debug("Decrypted profile \(name, privacy: .public), tier \(stored.metadata.tier.rawValue, privacy: .public), reused \(reused, privacy: .public)")
        return (values, reused)
    }

    /// Nil follows the global notification settings.
    @discardableResult
    public static func setNotifications(name: String, override: ProfileNotificationOverride?) throws -> ProfileMetadata {
        let metadata = try ProfileStorage.mutate(name: name) { $0.notifications = override; return true }
        Log.secrets.log("Set notification override of \(name, privacy: .public) to \(override != nil, privacy: .public)")
        return metadata
    }

    @discardableResult
    public static func setRememberSeconds(name: String, seconds: TimeInterval) throws -> ProfileMetadata {
        let metadata = try ProfileStorage.mutate(name: name) { $0.rememberSeconds = seconds; return true }
        AuthorizationWindows.shared.invalidate(prefix: AuthorizationScope.profilePrefix(name))
        SecretsGraceWindows.shared.revoke(profile: name)
        Log.secrets.log("Set rememberSeconds of \(name, privacy: .public) to \(seconds, privacy: .public)")
        return metadata
    }

    /// Decrypts, merges, and re-seals: entries in `setting` overwrite, names
    /// in `removing` drop. Only the decrypt touches the Enclave; the re-seal
    /// uses the cached public key.
    @discardableResult
    public static func updateValues(name: String, setting: [String: String],
                                    removing: Set<String> = [], reason: String) throws -> ProfileMetadata {
        try validate(values: setting)
        let stored = try ProfileStorage.load(name: name)
        let context = LAContext()
        context.localizedReason = reason
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: stored.value.keyData,
            authenticationContext: context
        )
        var values = try ProfileCipher.decodeValues(try ProfileCipher.open(stored.value.sealed, with: key))
        AuthorizationWindows.shared.invalidate(prefix: AuthorizationScope.profilePrefix(name))
        for (variable, value) in setting { values[variable] = value }
        for variable in removing { values.removeValue(forKey: variable) }

        let recipient = try P256.KeyAgreement.PublicKey(x963Representation: stored.metadata.publicKey)
        let sealed = try sealChecked(values, to: recipient)
        var metadata = stored.metadata
        metadata.variableNames = values.keys.sorted()
        metadata.updatedAt = Date()
        try ProfileStorage.replace(name: name,
                                   value: StoredProfileValue(keyData: stored.value.keyData, sealed: sealed),
                                   metadata: metadata)
        SecretsGraceWindows.shared.revoke(profile: name)
        Log.secrets.log("Updated values of profile \(name, privacy: .public), now \(values.count, privacy: .public) variables")
        return metadata
    }

    @discardableResult
    public static func rename(name: String, to newName: String) throws -> ProfileMetadata {
        guard newName != name else { return try ProfileStorage.load(name: name).metadata }
        try ProfileName.validate(newName)
        var metadata = try ProfileStorage.load(name: name).metadata
        metadata.name = newName
        try ProfileStorage.rename(from: name, metadata: metadata)
        Log.secrets.log("Renamed profile \(name, privacy: .public) to \(newName, privacy: .public)")
        return metadata
    }

    @discardableResult
    public static func setExportDisabled(name: String, disabled: Bool) throws -> ProfileMetadata {
        let metadata = try ProfileStorage.mutate(name: name) { $0.exportDisabled = disabled; return true }
        AuthorizationWindows.shared.invalidate(prefix: AuthorizationScope.profilePrefix(name))
        SecretsGraceWindows.shared.revoke(profile: name)
        Log.secrets.log("Set exportDisabled of profile \(name, privacy: .public) to \(disabled, privacy: .public)")
        return metadata
    }

    /// Deletes the keychain item, which holds the only copies of the Enclave
    /// key handle and the ciphertext, so the values are unrecoverable.
    public static func delete(name: String) throws {
        try ProfileStorage.delete(name: name)
        AuthorizationWindows.shared.invalidate(prefix: AuthorizationScope.profilePrefix(name))
        SecretsGraceWindows.shared.revoke(profile: name)
        Log.secrets.log("Deleted profile \(name, privacy: .public)")
    }
}
