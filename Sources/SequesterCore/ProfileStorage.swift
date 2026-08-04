import Foundation
import Security

public extension Notification.Name {
    /// Posted whenever a profile's persisted state changes, so an open UI
    /// can reload live.
    static let sequesterProfilesDidChange = Notification.Name("cz.szypowi.sequester.profilesDidChange")
}

/// The keychain item value of one profile: the Enclave key handle and the
/// sealed values blob, versioned together so they can only change as a pair.
public struct StoredProfileValue: Codable, Sendable {
    public var v: Int
    /// The Enclave key's dataRepresentation, usable only by this Mac.
    public var keyData: Data
    /// The ProfileCipher blob holding the values.
    public var sealed: Data

    public init(keyData: Data, sealed: Data) {
        self.v = 1
        self.keyData = keyData
        self.sealed = sealed
    }
}

/// Persistence for secrets profiles in the login keychain. Each profile is
/// one generic-password item: the account is the profile name, the value is
/// the Enclave key handle plus the sealed blob, and the generic attribute
/// carries the ProfileMetadata JSON. A keychain item rather than a container
/// file because anyone can encrypt to the Enclave public key: a plain file
/// could be swapped by a co-resident process, while the keychain restricts
/// writes to this app.
public enum ProfileStorage {

    static let service = "cz.szypowi.sequester.profiles"

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

    /// Serializes every write, matching the KeyStorage discipline: the
    /// broker (background threads) and the UI (main actor) mutate the same
    /// items.
    private static let mutationLock = NSLock()

    /// Atomic read-modify-write of a profile's metadata. `body` mutates the
    /// loaded copy and returns whether it changed anything; the item is
    /// written and observers notified only on a real change.
    @discardableResult
    static func mutate(name: String, _ body: (inout ProfileMetadata) throws -> Bool) throws -> ProfileMetadata {
        mutationLock.lock()
        defer { mutationLock.unlock() }
        var metadata = try load(name: name).metadata
        if try body(&metadata) {
            let update: [CFString: Any] = [kSecAttrGeneric: try JSONEncoder().encode(metadata)]
            let status = SecItemUpdate(baseQuery(name: metadata.name) as CFDictionary, update as CFDictionary)
            if status == errSecItemNotFound { throw KeychainError.notFound(metadata.name) }
            guard status == errSecSuccess else { throw KeychainError.status(status) }
            postChange()
        }
        return metadata
    }

    /// Swaps the sealed value and the metadata in one keychain update, so
    /// the ciphertext and the variable-name list can never diverge.
    public static func replace(name: String, value: StoredProfileValue, metadata: ProfileMetadata) throws {
        mutationLock.lock()
        defer { mutationLock.unlock() }
        let update: [CFString: Any] = [
            kSecValueData: try JSONEncoder().encode(value),
            kSecAttrGeneric: try JSONEncoder().encode(metadata),
        ]
        let status = SecItemUpdate(baseQuery(name: name) as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound { throw KeychainError.notFound(name) }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
        postChange()
    }

    public static func save(value: StoredProfileValue, metadata: ProfileMetadata) throws {
        mutationLock.lock()
        defer { mutationLock.unlock() }
        var attributes = baseQuery(name: metadata.name)
        attributes[kSecAttrLabel] = "Sequester profile: \(metadata.name)"
        attributes[kSecAttrGeneric] = try JSONEncoder().encode(metadata)
        attributes[kSecValueData] = try JSONEncoder().encode(value)
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

    /// Lists every item under the profile service. An item whose metadata
    /// does not decode still reserves its name and holds a sealed blob, so
    /// it comes back as an unreadable stub next to the decoded ones rather
    /// than being dropped silently.
    public static func list() throws -> (profiles: [ProfileMetadata], unreadable: [UnreadableItem]) {
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
        var profiles: [ProfileMetadata] = []
        var unreadable: [UnreadableItem] = []
        for item in items {
            let name = item[kSecAttrAccount] as? String ?? "(unnamed)"
            let createdAt = item[kSecAttrCreationDate] as? Date
            guard let generic = item[kSecAttrGeneric] as? Data else {
                Log.secrets.error("Profile item \(name, privacy: .public) has no metadata attribute")
                unreadable.append(UnreadableItem(name: name, createdAt: createdAt))
                continue
            }
            do {
                profiles.append(try decoder.decode(ProfileMetadata.self, from: generic))
            } catch {
                Log.secrets.error("Profile item \(name, privacy: .public) could not be decoded: \(error.localizedDescription, privacy: .public)")
                unreadable.append(UnreadableItem(name: name, createdAt: createdAt))
            }
        }
        return (profiles.sorted { $0.createdAt < $1.createdAt },
                unreadable.sorted { $0.name < $1.name })
    }

    public static func load(name: String) throws -> (value: StoredProfileValue, metadata: ProfileMetadata) {
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
              let value = try? JSONDecoder().decode(StoredProfileValue.self, from: data),
              let generic = item[kSecAttrGeneric] as? Data,
              let metadata = try? JSONDecoder().decode(ProfileMetadata.self, from: generic) else {
            throw KeychainError.corruptItem
        }
        return (value, metadata)
    }

    /// Moves an item to a new account (the profile's new name), updating the
    /// label and metadata with it. The keychain enforces name uniqueness.
    public static func rename(from oldName: String, metadata: ProfileMetadata) throws {
        mutationLock.lock()
        defer { mutationLock.unlock() }
        let update: [CFString: Any] = [
            kSecAttrAccount: metadata.name,
            kSecAttrLabel: "Sequester profile: \(metadata.name)",
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

    private static func postChange() {
        NotificationCenter.default.post(name: .sequesterProfilesDidChange, object: nil)
    }
}
