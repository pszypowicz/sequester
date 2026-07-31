import Foundation
import CryptoKit
import LocalAuthentication

public enum SequesterPaths {

    /// Everything lives in one flat directory: the agent socket and the
    /// public key files. Short and space-free so ssh config stays clean.
    public static var directory: URL {
        FileManager.default.homeDirectoryForCurrentUser.appending(path: ".sequester")
    }

    public static var socketURL: URL {
        directory.appending(path: "agent.sock")
    }

    public static func publicKeyURL(name: String) -> URL {
        directory.appending(path: "\(name).pub")
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
        return metadata
    }

    @discardableResult
    public static func updatePolicy(name: String, policy: SigningPolicy) throws -> KeyMetadata {
        var metadata = try KeyStorage.load(name: name).metadata
        metadata.policy = policy
        try KeyStorage.updateMetadata(metadata)
        return metadata
    }

    public static func delete(name: String) throws {
        try KeyStorage.delete(name: name)
        try? FileManager.default.removeItem(at: SequesterPaths.publicKeyURL(name: name))
    }

    /// Signs data the SSH way for ecdsa-sha2-nistp256: SHA-256 digest,
    /// ECDSA signature returned as raw r||s. Keys created with
    /// authRequired trigger the Enclave's own Touch ID prompt here.
    public static func sign(name: String, data: Data, reason: String) throws -> Data {
        let stored = try KeyStorage.load(name: name)
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
        let url = SequesterPaths.publicKeyURL(name: metadata.name)
        try Data((metadata.publicKeyLine + "\n").utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
    }
}
