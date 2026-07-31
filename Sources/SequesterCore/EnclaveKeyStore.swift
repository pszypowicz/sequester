import Foundation
import CryptoKit
import LocalAuthentication

public enum SequesterPaths {

    /// Everything lives in one flat directory: the agent socket and the
    /// public key files. NSHomeDirectory resolves to the app container in
    /// the sandboxed app, so this is
    /// ~/Library/Containers/cz.szypowi.sequester/Data/.sequester. The path
    /// has no spaces, and unsandboxed processes like ssh can follow it
    /// freely; only this app is confined by the sandbox.
    public static var directory: URL {
        URL(filePath: NSHomeDirectory()).appending(path: ".sequester")
    }

    public static var socketURL: URL {
        directory.appending(path: "agent.sock")
    }

    public static func publicKeyURL(stem: String) -> URL {
        directory.appending(path: "\(stem).pub")
    }

    public static func ensureDirectory() throws {
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }
}

public enum EnclaveKeyStoreError: LocalizedError {
    case enclaveUnavailable

    public var errorDescription: String? {
        "This Mac has no available Secure Enclave, so Sequester cannot create keys."
    }
}

/// Stateless operations over the Secure Enclave key inventory. Safe to call
/// from any thread; the observable UI store and the agent both go through
/// here.
public enum EnclaveKeyStore {

    public static var isEnclaveAvailable: Bool {
        SecureEnclave.isAvailable
    }

    @discardableResult
    public static func create(name: String, description: String,
                              authRequired: Bool, policy: SigningPolicy) throws -> KeyMetadata {
        try KeyName.validate(name)
        guard isEnclaveAvailable else { throw EnclaveKeyStoreError.enclaveUnavailable }

        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if authRequired {
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

        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        let metadata = KeyMetadata(
            name: name,
            keyDescription: description,
            authRequired: authRequired,
            policy: policy,
            publicKey: key.publicKey.x963Representation,
            createdAt: Date()
        )
        try KeyStorage.save(dataRepresentation: key.dataRepresentation, metadata: metadata)
        try writePublicKeyFile(metadata)
        Log.store.log("Created key \(name, privacy: .public) (\(metadata.fingerprint, privacy: .public)), Touch ID \(authRequired, privacy: .public), policy \(policy.rawValue, privacy: .public)")
        return metadata
    }

    public static func list() -> [KeyMetadata] {
        (try? KeyStorage.list()) ?? []
    }

    public static func find(publicKeyBlob: Data) -> KeyMetadata? {
        list().first { $0.publicKeyBlob == publicKeyBlob }
    }

    @discardableResult
    public static func updateDescription(name: String, description: String) throws -> KeyMetadata {
        var metadata = try KeyStorage.load(name: name).metadata
        metadata.keyDescription = description
        try KeyStorage.updateMetadata(metadata)
        Log.store.log("Updated description of \(name, privacy: .public)")
        return metadata
    }

    /// Renaming touches only the keychain item and the .pub comment; the
    /// .pub filename is derived from the key and stays put.
    @discardableResult
    public static func rename(name: String, to newName: String) throws -> KeyMetadata {
        guard newName != name else { return try KeyStorage.load(name: name).metadata }
        try KeyName.validate(newName)
        var metadata = try KeyStorage.load(name: name).metadata
        metadata.name = newName
        try KeyStorage.rename(from: name, metadata: metadata)
        try writePublicKeyFile(metadata)
        Log.store.log("Renamed key \(name, privacy: .public) to \(newName, privacy: .public)")
        return metadata
    }

    @discardableResult
    public static func updatePolicy(name: String, policy: SigningPolicy) throws -> KeyMetadata {
        var metadata = try KeyStorage.load(name: name).metadata
        metadata.policy = policy
        try KeyStorage.updateMetadata(metadata)
        Log.store.log("Updated policy of \(name, privacy: .public) to \(policy.rawValue, privacy: .public)")
        return metadata
    }

    public static func delete(name: String) throws {
        let metadata = try KeyStorage.load(name: name).metadata
        try KeyStorage.delete(name: name)
        try? FileManager.default.removeItem(at: metadata.publicKeyFileURL)
        Log.store.log("Deleted key \(name, privacy: .public)")
    }

    /// Signs data the SSH way for ecdsa-sha2-nistp256: SHA-256 digest,
    /// ECDSA signature returned as raw r||s. Keys created with
    /// authRequired trigger the Enclave's own Touch ID prompt here.
    public static func sign(name: String, data: Data, reason: String) throws -> Data {
        let stored = try KeyStorage.load(name: name)
        Log.store.debug("Signing \(data.count, privacy: .public) bytes with \(name, privacy: .public), Touch ID \(stored.metadata.authRequired, privacy: .public)")
        let context = LAContext()
        context.localizedReason = reason
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: stored.dataRepresentation,
            authenticationContext: context
        )
        return try key.signature(for: data).rawRepresentation
    }

    public static func writePublicKeyFile(_ metadata: KeyMetadata) throws {
        try SequesterPaths.ensureDirectory()
        let url = metadata.publicKeyFileURL
        try Data((metadata.publicKeyLine + "\n").utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
        Log.store.debug("Wrote \(url.path, privacy: .public)")
    }

    /// Reconciles ~/.sequester with the keychain: every key gets its
    /// current .pub file (content includes the comment, which follows the
    /// name), and .pub files with no matching key are removed. The
    /// directory is app-managed, so stray .pub files are treated as stale,
    /// never as user data.
    public static func syncPublicKeyFiles() {
        let keys = list()
        for key in keys {
            let line = key.publicKeyLine + "\n"
            let existing = try? String(contentsOf: key.publicKeyFileURL, encoding: .utf8)
            if existing != line {
                try? writePublicKeyFile(key)
            }
        }
        let expected = Set(keys.map { "\($0.publicKeyFileStem).pub" })
        let contents = (try? FileManager.default.contentsOfDirectory(atPath: SequesterPaths.directory.path)) ?? []
        for file in contents where file.hasSuffix(".pub") && !expected.contains(file) {
            try? FileManager.default.removeItem(at: SequesterPaths.directory.appending(path: file))
            Log.store.log("Removed stale public key file \(file, privacy: .public)")
        }
    }
}
