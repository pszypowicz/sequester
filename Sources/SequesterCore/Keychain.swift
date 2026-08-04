import Foundation
import Security

public extension Notification.Name {
    /// Posted whenever a key's persisted metadata changes, so an open UI can
    /// reload live as destinations are observed or approved.
    static let sequesterKeysDidChange = Notification.Name("cz.szypowi.sequester.keysDidChange")
    /// Posted whenever the global app-authorization list changes.
    static let sequesterAppsDidChange = Notification.Name("cz.szypowi.sequester.appsDidChange")
}

public enum KeychainError: LocalizedError {
    case status(OSStatus)
    case notFound(String)
    case duplicate(String)
    case corruptItem

    public var errorDescription: String? {
        switch self {
        case .status(let code):
            let message = SecCopyErrorMessageString(code, nil) as String? ?? "OSStatus \(code)"
            return "Keychain error: \(message)"
        case .notFound(let name):
            return "No key named \"\(name)\"."
        case .duplicate(let name):
            return "A key named \"\(name)\" already exists."
        case .corruptItem:
            return "A keychain item for Sequester could not be decoded."
        }
    }
}

/// A keychain item whose metadata attribute does not decode, typically one
/// written by a different version of the app. The plain attributes still
/// identify it, so the UI can show it and offer deletion; nothing else can
/// be done with it.
public struct UnreadableItem: Identifiable, Equatable, Sendable {
    public let name: String
    public let createdAt: Date?
    public var id: String { name }

    public init(name: String, createdAt: Date?) {
        self.name = name
        self.createdAt = createdAt
    }
}

/// Persistence for Secure Enclave key handles in the login keychain. Each
/// key is one generic-password item: the account is the key name, the value
/// is the Enclave key's dataRepresentation (an encrypted blob only this
/// Mac's Enclave can use), and the generic attribute carries the
/// KeyMetadata JSON.
public enum KeyStorage {

    static let service = "cz.szypowi.sequester.keys"

    private static func baseQuery(name: String? = nil) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
        ]
        if let name {
            query[kSecAttrAccount] = name
        }
        return query
    }

    /// Serializes every metadata write. The agent (background threads) and
    /// the UI (main actor) mutate the same items; without this a concurrent
    /// read-modify-write could clobber a change - e.g. an observation from a
    /// signature overwriting a block the user just set. Reads are not
    /// serialized; each SecItem call is atomic on its own.
    private static let mutationLock = NSLock()

    /// Atomic read-modify-write of a key's metadata. `body` mutates the
    /// loaded copy and returns whether it changed anything; the item is
    /// written and observers notified only on a real change.
    @discardableResult
    static func mutate(name: String, _ body: (inout KeyMetadata) throws -> Bool) throws -> KeyMetadata {
        mutationLock.lock()
        defer { mutationLock.unlock() }
        var metadata = try load(name: name).metadata
        if try body(&metadata) {
            try writeMetadataLocked(metadata)
            postChange()
        }
        return metadata
    }

    private static func writeMetadataLocked(_ metadata: KeyMetadata) throws {
        let update: [CFString: Any] = [kSecAttrGeneric: try JSONEncoder().encode(metadata)]
        let status = SecItemUpdate(baseQuery(name: metadata.name) as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound { throw KeychainError.notFound(metadata.name) }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
    }

    public static func save(dataRepresentation: Data, metadata: KeyMetadata) throws {
        mutationLock.lock()
        defer { mutationLock.unlock() }
        var attributes = baseQuery(name: metadata.name)
        attributes[kSecAttrLabel] = "Sequester: \(metadata.name)"
        attributes[kSecAttrGeneric] = try JSONEncoder().encode(metadata)
        attributes[kSecValueData] = dataRepresentation
        let status = SecItemAdd(attributes as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            postChange()
        case errSecDuplicateItem:
            throw KeychainError.duplicate(metadata.name)
        default:
            throw KeychainError.status(status)
        }
    }

    private static func postChange() {
        NotificationCenter.default.post(name: .sequesterKeysDidChange, object: nil)
    }

    /// Lists every item under the key service. An item whose metadata does
    /// not decode is still a key - it may hold an Enclave key handle and it
    /// reserves its name - so it comes back as an unreadable stub next to
    /// the decoded ones instead of hiding the whole inventory behind an
    /// error.
    public static func list() throws -> (keys: [KeyMetadata], unreadable: [UnreadableItem]) {
        var query = baseQuery()
        query[kSecMatchLimit] = kSecMatchLimitAll
        query[kSecReturnAttributes] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return ([], []) }
        guard status == errSecSuccess, let items = result as? [[CFString: Any]] else {
            throw KeychainError.status(status)
        }
        let decoder = JSONDecoder()
        var keys: [KeyMetadata] = []
        var unreadable: [UnreadableItem] = []
        for item in items {
            let name = item[kSecAttrAccount] as? String ?? "(unnamed)"
            let createdAt = item[kSecAttrCreationDate] as? Date
            guard let generic = item[kSecAttrGeneric] as? Data else {
                Log.store.error("Key item \(name, privacy: .public) has no metadata attribute")
                unreadable.append(UnreadableItem(name: name, createdAt: createdAt))
                continue
            }
            do {
                keys.append(try decoder.decode(KeyMetadata.self, from: generic))
            } catch {
                Log.store.error("Key item \(name, privacy: .public) could not be decoded: \(error.localizedDescription, privacy: .public)")
                unreadable.append(UnreadableItem(name: name, createdAt: createdAt))
            }
        }
        return (keys.sorted { $0.createdAt < $1.createdAt },
                unreadable.sorted { $0.name < $1.name })
    }

    public static func load(name: String) throws -> (dataRepresentation: Data, metadata: KeyMetadata) {
        var query = baseQuery(name: name)
        query[kSecMatchLimit] = kSecMatchLimitOne
        query[kSecReturnAttributes] = true
        query[kSecReturnData] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { throw KeychainError.notFound(name) }
        guard status == errSecSuccess,
              let item = result as? [CFString: Any],
              let data = item[kSecValueData] as? Data,
              let generic = item[kSecAttrGeneric] as? Data,
              let metadata = try? JSONDecoder().decode(KeyMetadata.self, from: generic) else {
            throw KeychainError.corruptItem
        }
        return (data, metadata)
    }

    /// Moves an item to a new account (the key's new name), updating the
    /// label and metadata with it. The keychain enforces name uniqueness.
    public static func rename(from oldName: String, metadata: KeyMetadata) throws {
        mutationLock.lock()
        defer { mutationLock.unlock() }
        let update: [CFString: Any] = [
            kSecAttrAccount: metadata.name,
            kSecAttrLabel: "Sequester: \(metadata.name)",
            kSecAttrGeneric: try JSONEncoder().encode(metadata),
        ]
        let status = SecItemUpdate(baseQuery(name: oldName) as CFDictionary, update as CFDictionary)
        switch status {
        case errSecSuccess:
            postChange()
        case errSecItemNotFound:
            throw KeychainError.notFound(oldName)
        case errSecDuplicateItem:
            throw KeychainError.duplicate(metadata.name)
        default:
            throw KeychainError.status(status)
        }
    }

    public static func delete(name: String) throws {
        mutationLock.lock()
        defer { mutationLock.unlock() }
        let status = SecItemDelete(baseQuery(name: name) as CFDictionary)
        if status == errSecItemNotFound { throw KeychainError.notFound(name) }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
        postChange()
    }
}

/// Persistence for global app authorizations, in one keychain item so the
/// list is protected by the same code-signature-scoped access as the keys
/// themselves: a co-resident process cannot add itself to the allowlist the
/// way it could edit a plain file in the user-owned container. Stored as a
/// JSON array in the value of a single generic-password item.
public enum AppAuthorizationStore {

    static let service = "cz.szypowi.sequester.apps"
    private static let account = "authorizations"

    private static let mutationLock = NSLock()

    private static let cacheLock = NSLock()
    nonisolated(unsafe) private static var cache: [AppAuthorization]?

    private static func baseQuery() -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
    }

    /// Cached because it is read on the signing hot path (once per request
    /// for a verified app with no per-key rule). This store is the only
    /// writer, so setState and remove keep the cache current.
    public static func list() -> [AppAuthorization] {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        if let cache {
            return cache
        }
        let loaded = load()
        cache = loaded
        return loaded
    }

    public static func state(for identity: String) -> AppState? {
        list().first { $0.identity == identity }?.state
    }

    /// Drops the cache so the next list() re-reads the keychain. The cache
    /// tracks only this process's writes, so an edit made from outside the
    /// app stays invisible until someone calls this.
    public static func invalidateCache() {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        cache = nil
    }

    /// Records or updates an app's global standing and bumps its last-used
    /// timestamp. Serialized so a signature-thread write and a UI edit cannot
    /// clobber each other.
    public static func setState(identity: String, displayName: String, state: AppState, now: Date) {
        mutationLock.lock()
        defer { mutationLock.unlock() }
        var items = load()
        if let index = items.firstIndex(where: { $0.identity == identity }) {
            items[index].state = state
            items[index].displayName = displayName
            items[index].lastUsed = now
        } else {
            items.append(AppAuthorization(
                identity: identity, displayName: displayName, state: state, firstSeen: now, lastUsed: now
            ))
        }
        save(items)
        replaceCache(items)
        postChange()
    }

    public static func remove(identity: String) {
        mutationLock.lock()
        defer { mutationLock.unlock() }
        var items = load()
        let before = items.count
        items.removeAll { $0.identity == identity }
        guard items.count != before else { return }
        save(items)
        replaceCache(items)
        postChange()
    }

    private static func load() -> [AppAuthorization] {
        var query = baseQuery()
        query[kSecMatchLimit] = kSecMatchLimitOne
        query[kSecReturnData] = true
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return [] }
        return (try? JSONDecoder().decode([AppAuthorization].self, from: data)) ?? []
    }

    private static func save(_ items: [AppAuthorization]) {
        guard let data = try? JSONEncoder().encode(items) else { return }
        let update: [CFString: Any] = [kSecValueData: data]
        let status = SecItemUpdate(baseQuery() as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var attributes = baseQuery()
            attributes[kSecValueData] = data
            attributes[kSecAttrLabel] = "Sequester: app authorizations"
            SecItemAdd(attributes as CFDictionary, nil)
        }
    }

    private static func replaceCache(_ items: [AppAuthorization]) {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        cache = items
    }

    private static func postChange() {
        NotificationCenter.default.post(name: .sequesterAppsDidChange, object: nil)
    }
}
