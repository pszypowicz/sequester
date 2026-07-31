import Foundation
import CryptoKit

/// Headless diagnostics behind hidden launch flags, so the signed app can
/// verify its keychain entitlement and Enclave access from a terminal
/// without any UI. Run the binary inside the bundle directly:
///   .build/Sequester.app/Contents/MacOS/Sequester --selftest
public enum Selftest {

    private static let temporaryKeyName = "selftest-tmp"

    public static func run() -> Int32 {
        var failed = false
        func check(_ label: String, _ body: () throws -> Void) {
            do {
                try body()
                print("PASS \(label)")
            } catch {
                print("FAIL \(label): \(error.localizedDescription)")
                failed = true
            }
        }

        try? EnclaveKeyStore.delete(name: temporaryKeyName)

        check("secure enclave available") {
            guard EnclaveKeyStore.isEnclaveAvailable else {
                throw EnclaveKeyStoreError.enclaveUnavailable
            }
        }
        check("enclave key generation") {
            var accessError: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage],
                &accessError
            ) else {
                throw accessError!.takeRetainedValue() as Error
            }
            _ = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        }
        check("create key (keychain + enclave)") {
            try EnclaveKeyStore.create(
                name: temporaryKeyName, description: "selftest",
                authRequired: false, policy: .askEveryTime
            )
        }
        check("key listed") {
            guard EnclaveKeyStore.list().contains(where: { $0.name == temporaryKeyName }) else {
                throw KeychainError.notFound(temporaryKeyName)
            }
        }
        check("sign and verify") {
            let message = Data("sequester selftest".utf8)
            let raw = try EnclaveKeyStore.sign(name: temporaryKeyName, data: message, reason: "selftest")
            let stored = try KeyStorage.load(name: temporaryKeyName).metadata
            let publicKey = try P256.Signing.PublicKey(x963Representation: stored.publicKey)
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: raw)
            guard publicKey.isValidSignature(signature, for: message) else {
                throw CryptoKitError.authenticationFailure
            }
        }
        check("metadata update") {
            try EnclaveKeyStore.updateDescription(name: temporaryKeyName, description: "updated")
            try EnclaveKeyStore.updatePolicy(name: temporaryKeyName, policy: .allowLocalAskForwarded)
            let metadata = try KeyStorage.load(name: temporaryKeyName).metadata
            guard metadata.keyDescription == "updated",
                  metadata.policy == .allowLocalAskForwarded else {
                throw KeychainError.corruptItem
            }
        }
        check("public key file") {
            let url = SequesterPaths.publicKeyURL(name: temporaryKeyName)
            let line = try String(contentsOf: url, encoding: .utf8)
            guard line.hasPrefix("\(OpenSSH.p256Identifier) ") else {
                throw KeychainError.corruptItem
            }
        }
        check("delete key") {
            try EnclaveKeyStore.delete(name: temporaryKeyName)
            guard !EnclaveKeyStore.list().contains(where: { $0.name == temporaryKeyName }) else {
                throw KeychainError.duplicate(temporaryKeyName)
            }
        }

        return failed ? 1 : 0
    }

    public static func createKey(name: String) -> Int32 {
        do {
            let metadata = try EnclaveKeyStore.create(
                name: name, description: "created by --selftest-create-key",
                authRequired: false, policy: .allowLocalAskForwarded
            )
            print("created \(metadata.name) \(metadata.fingerprint)")
            print(SequesterPaths.publicKeyURL(name: name).path)
            return 0
        } catch {
            print("FAIL create \(name): \(error.localizedDescription)")
            return 1
        }
    }

    public static func deleteKey(name: String) -> Int32 {
        do {
            try EnclaveKeyStore.delete(name: name)
            print("deleted \(name)")
            return 0
        } catch {
            print("FAIL delete \(name): \(error.localizedDescription)")
            return 1
        }
    }
}
