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

    /// The secrets protocol lives on its own socket so it is never reachable
    /// through a forwarded SSH_AUTH_SOCK.
    public static var secretsSocketURL: URL {
        directory.appending(path: "secrets.sock")
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
    public static func create(name: String, description: String, authRequired: Bool, comment: String? = nil) throws -> KeyMetadata {
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
            comment: sanitizeComment(comment),
            publicKey: key.publicKey.x963Representation,
            createdAt: Date()
        )
        try KeyStorage.save(dataRepresentation: key.dataRepresentation, metadata: metadata)
        try writePublicKeyFile(metadata)
        Log.store.log("Created key \(name, privacy: .public) (\(metadata.fingerprint, privacy: .public)), Touch ID \(authRequired, privacy: .public)")
        return metadata
    }

    public static func list() -> [KeyMetadata] {
        inventory().keys
    }

    /// The full inventory, including items this version cannot read.
    public static func inventory() -> (keys: [KeyMetadata], unreadable: [UnreadableItem]) {
        (try? KeyStorage.list()) ?? ([], [])
    }

    public static func find(publicKeyBlob: Data) -> KeyMetadata? {
        list().first { $0.publicKeyBlob == publicKeyBlob }
    }

    @discardableResult
    public static func updateDescription(name: String, description: String) throws -> KeyMetadata {
        let metadata = try KeyStorage.mutate(name: name) { $0.keyDescription = description; return true }
        Log.store.log("Updated description of \(name, privacy: .public)")
        return metadata
    }

    /// Sets a key's public key comment (nil or empty restores the
    /// "<name>@sequester" default) and rewrites its .pub file.
    @discardableResult
    public static func updateComment(name: String, comment: String?) throws -> KeyMetadata {
        let metadata = try KeyStorage.mutate(name: name) { $0.comment = sanitizeComment(comment); return true }
        try writePublicKeyFile(metadata)
        Log.store.log("Updated comment of \(name, privacy: .public)")
        return metadata
    }

    /// A key comment becomes the trailing field of a one-line .pub and the
    /// agent identity comment, so newlines and control characters are dropped
    /// and the value trimmed. An empty result means "use the default".
    static func sanitizeComment(_ comment: String?) -> String? {
        guard let comment else { return nil }
        var scalars = String.UnicodeScalarView()
        for scalar in comment.unicodeScalars {
            if scalar == " " { scalars.append(scalar); continue }
            if scalar.properties.isWhitespace { continue }
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator, .surrogate:
                continue
            default:
                scalars.append(scalar)
            }
        }
        let result = String(scalars).trimmingCharacters(in: .whitespaces)
        return result.isEmpty ? nil : result
    }

    /// Renaming touches only the keychain item and the .pub comment; the
    /// .pub filename stays put.
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
    public static func setBlockForwarded(name: String, blocked: Bool) throws -> KeyMetadata {
        let metadata = try KeyStorage.mutate(name: name) { $0.blockForwarded = blocked; return true }
        Log.store.log("Set blockForwarded of \(name, privacy: .public) to \(blocked, privacy: .public)")
        return metadata
    }

    /// Enabling approve-all makes it the sole active control: approve-local
    /// is implied, and the restricting settings (block-forwarded, lock) are
    /// cleared so nothing contradicts it.
    @discardableResult
    public static func setApproveAll(name: String, enabled: Bool) throws -> KeyMetadata {
        let metadata = try KeyStorage.mutate(name: name) { m in
            m.approveAll = enabled
            if enabled {
                m.autoApprove = true
                m.blockForwarded = false
                m.locked = false
            }
            return true
        }
        Log.store.log("Set approveAll of \(name, privacy: .public) to \(enabled, privacy: .public)")
        return metadata
    }

    @discardableResult
    public static func setAutoApprove(name: String, enabled: Bool) throws -> KeyMetadata {
        let metadata = try KeyStorage.mutate(name: name) { $0.autoApprove = enabled; return true }
        Log.store.log("Set autoApprove of \(name, privacy: .public) to \(enabled, privacy: .public)")
        return metadata
    }

    @discardableResult
    public static func setLocked(name: String, locked: Bool) throws -> KeyMetadata {
        let metadata = try KeyStorage.mutate(name: name) { $0.locked = locked; return true }
        Log.store.log("Set locked of \(name, privacy: .public) to \(locked, privacy: .public)")
        return metadata
    }

    /// Updates the usage log for an observed binding chain: bumps counters for a
    /// path that is already listed, and adds a neutral record for a new one
    /// only when `createIfNew` is set. A denied request for an unknown
    /// destination passes `createIfNew: false`, so a locked key or a probe
    /// cannot grow the destinations list. Returns whether anything was
    /// recorded; best effort, the signing flow must not fail on bookkeeping.
    @discardableResult
    public static func recordObservation(name: String, hops: [BindingHop], createIfNew: Bool) -> Bool {
        guard !hops.isEmpty else { return false }
        var recorded = false
        _ = try? KeyStorage.mutate(name: name) { m in
            let now = Date()
            if let index = m.destinations.firstIndex(where: { $0.hops == hops }) {
                m.destinations[index].lastUsed = now
                m.destinations[index].count += 1
            } else if createIfNew {
                m.destinations.append(DestinationRecord(
                    hops: hops, state: .neutral, firstSeen: now, lastUsed: now, count: 1
                ))
            } else {
                return false
            }
            recorded = true
            return true
        }
        return recorded
    }

    public static func setDestinationState(name: String, id: String, state: DestinationState) {
        _ = try? KeyStorage.mutate(name: name) { m in
            guard let index = m.destinations.firstIndex(where: { $0.id == id }) else { return false }
            m.destinations[index].state = state
            return true
        }
        Log.store.log("Set destination \(id, privacy: .public) of \(name, privacy: .public) to \(state.rawValue, privacy: .public)")
    }

    public static func removeDestination(name: String, id: String) {
        _ = try? KeyStorage.mutate(name: name) { m in
            let before = m.destinations.count
            m.destinations.removeAll { $0.id == id }
            return m.destinations.count != before
        }
        Log.store.log("Removed destination \(id, privacy: .public) of \(name, privacy: .public)")
    }

    /// Forgets every observed path whose binding chain starts with these hops, i.e.
    /// the whole subtree rooted at a hop.
    public static func removeDestinationsUnder(name: String, prefix: [BindingHop]) {
        guard !prefix.isEmpty else { return }
        _ = try? KeyStorage.mutate(name: name) { m in
            let before = m.destinations.count
            m.destinations.removeAll { record in
                record.hops.count >= prefix.count && Array(record.hops.prefix(prefix.count)) == prefix
            }
            return m.destinations.count != before
        }
        Log.store.log("Removed destinations under \(DestinationRecord.bindingChainID(prefix), privacy: .public) of \(name, privacy: .public)")
    }

    /// Sets the standing for every path starting with these hops. A
    /// neutral state drops the rule, since neutral is the default.
    public static func setBranchRule(name: String, hops: [BindingHop], state: DestinationState) {
        guard !hops.isEmpty else { return }
        let rule = BranchRule(hops: hops, state: state)
        _ = try? KeyStorage.mutate(name: name) { m in
            m.branchRules.removeAll { $0.id == rule.id }
            if state != .neutral {
                m.branchRules.append(rule)
            }
            return true
        }
        Log.store.log("Set branch \(rule.id, privacy: .public) of \(name, privacy: .public) to \(state.rawValue, privacy: .public)")
    }

    /// Sets a per-key override of an app's standing, taking precedence over
    /// the global authorization for this key.
    @discardableResult
    public static func setAppRule(name: String, identity: String, displayName: String, state: AppState) throws -> KeyMetadata {
        let metadata = try KeyStorage.mutate(name: name) { m in
            if let index = m.appRules.firstIndex(where: { $0.identity == identity }) {
                m.appRules[index].state = state
                m.appRules[index].displayName = displayName
            } else {
                m.appRules.append(AppRule(identity: identity, displayName: displayName, state: state))
            }
            return true
        }
        Log.store.log("Set app rule \(identity, privacy: .public) on \(name, privacy: .public) to \(state.rawValue, privacy: .public)")
        return metadata
    }

    public static func removeAppRule(name: String, identity: String) {
        _ = try? KeyStorage.mutate(name: name) { m in
            let before = m.appRules.count
            m.appRules.removeAll { $0.identity == identity }
            return m.appRules.count != before
        }
        Log.store.log("Removed app rule \(identity, privacy: .public) on \(name, privacy: .public)")
    }

    public static func delete(name: String) throws {
        let metadata = try KeyStorage.load(name: name).metadata
        try KeyStorage.delete(name: name)
        AuthorizationWindows.shared.invalidate(prefix: AuthorizationScope.keyPrefix(name))
        try? FileManager.default.removeItem(at: metadata.publicKeyFileURL)
        Log.store.log("Deleted key \(name, privacy: .public)")
    }

    /// Deletes an unreadable item by name alone. delete(name:) needs the
    /// metadata to find the .pub file, which is exactly what an unreadable
    /// item cannot provide; the sync afterwards prunes the orphaned file
    /// once the inventory reads clean.
    public static func deleteUnreadable(name: String) throws {
        try KeyStorage.delete(name: name)
        AuthorizationWindows.shared.invalidate(prefix: AuthorizationScope.keyPrefix(name))
        Log.store.log("Deleted unreadable key item \(name, privacy: .public)")
        syncPublicKeyFiles()
    }

    /// Signs data the SSH way for ecdsa-sha2-nistp256: SHA-256 digest,
    /// ECDSA signature returned as raw r||s. Keys created with
    /// authRequired trigger the Enclave's own Touch ID prompt here.
    ///
    /// Unless the key has a remembered-tap window open for this exact
    /// destination, the LAContext must be a fresh one per signature. A
    /// context that has once satisfied the key's access control keeps that
    /// authorization for every later operation passed the same instance,
    /// with no expiry of its own, so reusing one outside a window would
    /// silently drop the per-signature prompt.
    ///
    /// `windowScope` is nil wherever a window may not be opened, which
    /// `AuthorizationScope.key` decides.
    @discardableResult
    public static func sign(name: String, data: Data, reason: String,
                            windowScope: String? = nil) throws -> (signature: Data, reusedAuthorization: Bool) {
        let stored = try KeyStorage.load(name: name)
        Log.store.debug("Signing \(data.count, privacy: .public) bytes with \(name, privacy: .public), Touch ID \(stored.metadata.authRequired, privacy: .public)")

        let seconds = stored.metadata.authRequired ? stored.metadata.rememberSeconds : 0
        let scope = seconds > 0 ? windowScope : nil
        // A held authorization outlives a screen lock, so never reuse one
        // while the screen reports itself locked.
        let held = scope.flatMap { AuthorizationWindows.shared.existing(scope: $0) }
        let reused = held != nil && !AuthorizationWindows.screenIsLocked()

        let context = reused ? held! : LAContext()
        if !reused { context.localizedReason = reason }
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: stored.dataRepresentation,
            authenticationContext: context
        )
        let signature = try key.signature(for: data).rawRepresentation
        if let scope {
            AuthorizationWindows.shared.remember(scope: scope, context: context, seconds: seconds)
        }
        return (signature, reused)
    }

    @discardableResult
    public static func setRememberSeconds(name: String, seconds: TimeInterval) throws -> KeyMetadata {
        let metadata = try KeyStorage.mutate(name: name) { $0.rememberSeconds = seconds; return true }
        AuthorizationWindows.shared.invalidate(prefix: AuthorizationScope.keyPrefix(name))
        Log.store.log("Set rememberSeconds of \(name, privacy: .public) to \(seconds, privacy: .public)")
        return metadata
    }

    public static func writePublicKeyFile(_ metadata: KeyMetadata) throws {
        try SequesterPaths.ensureDirectory()
        let url = metadata.publicKeyFileURL
        try Data((metadata.publicKeyLine + "\n").utf8).write(to: url)
        // Owner-only: nothing but ssh running as this user reads the file, and
        // OpenSSH refuses to use a group- or world-readable path as an
        // IdentityFile ("permissions are too open"), so the public convention
        // of 0644 would break the very ssh config this file exists for.
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        Log.store.debug("Wrote \(url.path, privacy: .public)")
    }

    /// Reconciles the key directory with the keychain: every key gets its
    /// current .pub file (content includes the comment, which follows the
    /// name), and .pub files with no matching key are removed. The
    /// directory is app-managed, so stray .pub files are treated as stale,
    /// never as user data.
    public static func syncPublicKeyFiles() {
        // Pruning is driven by the inventory, so it must not run against a
        // partial one: a listing that failed would otherwise make every
        // public key file look stale and delete it.
        guard let inventory = try? KeyStorage.list() else {
            Log.store.error("Skipping public key file sync: the key inventory could not be read")
            return
        }
        for key in inventory.keys {
            let line = key.publicKeyLine + "\n"
            let existing = try? String(contentsOf: key.publicKeyFileURL, encoding: .utf8)
            if existing != line {
                try? writePublicKeyFile(key)
            } else {
                // Content is current, so only the mode needs asserting:
                // ssh refuses a group- or world-readable IdentityFile.
                try? FileManager.default.setAttributes(
                    [.posixPermissions: 0o600], ofItemAtPath: key.publicKeyFileURL.path)
            }
        }
        // An unreadable item may still own a .pub file, but its stem lives
        // in the metadata that did not decode, so pruning cannot tell that
        // file from a stale one. Keep every file until the inventory reads
        // clean.
        guard inventory.unreadable.isEmpty else { return }
        let expected = Set(inventory.keys.map { "\($0.publicKeyFileStem).pub" })
        let contents = (try? FileManager.default.contentsOfDirectory(atPath: SequesterPaths.directory.path)) ?? []
        for file in contents where file.hasSuffix(".pub") && !expected.contains(file) {
            try? FileManager.default.removeItem(at: SequesterPaths.directory.appending(path: file))
            Log.store.log("Removed stale public key file \(file, privacy: .public)")
        }
    }
}
