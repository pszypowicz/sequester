import Foundation
import CryptoKit
import Darwin

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
                name: temporaryKeyName, description: "selftest", authRequired: false
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
            try EnclaveKeyStore.setBlockForwarded(name: temporaryKeyName, blocked: true)
            let metadata = try KeyStorage.load(name: temporaryKeyName).metadata
            guard metadata.keyDescription == "updated", metadata.blockForwarded else {
                throw KeychainError.corruptItem
            }
        }
        check("approve-all cascade") {
            try EnclaveKeyStore.setBlockForwarded(name: temporaryKeyName, blocked: true)
            try EnclaveKeyStore.setLocked(name: temporaryKeyName, locked: true)
            try EnclaveKeyStore.setApproveAll(name: temporaryKeyName, enabled: true)
            let metadata = try KeyStorage.load(name: temporaryKeyName).metadata
            guard metadata.approveAll, metadata.autoApprove,
                  !metadata.blockForwarded, !metadata.locked else {
                throw KeychainError.corruptItem
            }
            try EnclaveKeyStore.setApproveAll(name: temporaryKeyName, enabled: false)
        }
        check("destination tracking") {
            let hop = BindingHop(fingerprint: "SHA256:selftest", algorithm: "ssh-ed25519", forwarding: false)
            EnclaveKeyStore.recordObservation(name: temporaryKeyName, hops: [hop], createIfNew: true)
            EnclaveKeyStore.recordObservation(name: temporaryKeyName, hops: [hop], createIfNew: true)
            var metadata = try KeyStorage.load(name: temporaryKeyName).metadata
            guard metadata.destinations.count == 1, metadata.destinations[0].count == 2 else {
                throw KeychainError.corruptItem
            }
            EnclaveKeyStore.setDestinationState(
                name: temporaryKeyName, id: DestinationRecord.bindingChainID([hop]), state: .approved
            )
            metadata = try KeyStorage.load(name: temporaryKeyName).metadata
            guard metadata.destinations[0].state == .approved,
                  PolicyEngine.evaluate(key: metadata, bindingChain: [hop]) == .allow else {
                throw KeychainError.corruptItem
            }
            EnclaveKeyStore.removeDestination(name: temporaryKeyName, id: DestinationRecord.bindingChainID([hop]))
            metadata = try KeyStorage.load(name: temporaryKeyName).metadata
            guard metadata.destinations.isEmpty else {
                throw KeychainError.corruptItem
            }
        }
        check("rename") {
            try EnclaveKeyStore.rename(name: temporaryKeyName, to: "selftest-renamed")
            try EnclaveKeyStore.rename(name: "selftest-renamed", to: temporaryKeyName)
        }
        check("public key file") {
            let metadata = try KeyStorage.load(name: temporaryKeyName).metadata
            let line = try String(contentsOf: metadata.publicKeyFileURL, encoding: .utf8)
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
                name: name, description: "created by --selftest-create-key", authRequired: false
            )
            // Auto-approve local use so a scripted, non-forwarded, verified
            // connection (scripts/agent-e2e.py) signs without a dialog.
            try EnclaveKeyStore.setAutoApprove(name: name, enabled: true)
            print("created \(metadata.name) \(metadata.fingerprint)")
            print(metadata.publicKeyFileURL.path)
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

    /// Answers the M0 question: can this build resolve a peer's code
    /// signature? Binds a throwaway socket, waits for one connection, and
    /// prints the full resolution report (including the raw status of the
    /// sandbox-gated SecCode call) for whatever process connects. Drive it
    /// from `/usr/bin/ssh` (expect Apple), a copied/unsigned binary (expect
    /// unverified), and the signed app itself (expect Developer ID).
    public static func provenanceProbe() -> Int32 {
        let path = NSTemporaryDirectory() + "sequester-provenance-\(getpid()).sock"
        unlink(path)

        let listenFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listenFD >= 0 else { print("FAIL socket: \(errnoText())"); return 1 }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            print("FAIL: socket path too long"); close(listenFD); return 1
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: pathBytes) }

        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bindRC = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listenFD, $0, size) }
        }
        guard bindRC == 0 else { print("FAIL bind: \(errnoText())"); close(listenFD); return 1 }
        guard listen(listenFD, 1) == 0 else { print("FAIL listen: \(errnoText())"); close(listenFD); return 1 }

        print("provenance probe listening at \(path)")
        print("connect a client to that socket path (any process), e.g. a client pointed at it")
        // accept() blocks, and stdout is fully buffered when not a tty, so the
        // listening line must be flushed before waiting or a driver never sees
        // the path to connect to.
        fflush(stdout)
        let clientFD = accept(listenFD, nil, nil)
        guard clientFD >= 0 else { print("FAIL accept: \(errnoText())"); close(listenFD); return 1 }

        print("---")
        print(ProvenanceTracer.probeReport(socket: clientFD))
        print("---")

        close(clientFD)
        close(listenFD)
        unlink(path)
        return 0
    }

    private static func errnoText() -> String {
        String(cString: strerror(errno))
    }
}
