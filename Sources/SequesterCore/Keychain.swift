import Foundation
import Security

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

/// Persistence for Secure Enclave key handles in the login keychain. Each
/// key is one generic-password item: the account is the key name, the value
/// is the Enclave key's dataRepresentation (an encrypted blob only this
/// Mac's Enclave can use), and the generic attribute carries the
/// KeyMetadata JSON.
///
/// The data protection keychain would be preferable, but on macOS its
/// required keychain-access-groups entitlement is restricted and needs an
/// embedded provisioning profile (AMFI kills the process otherwise); see
/// issue #1. The security-relevant access control lives inside the Enclave
/// key blob either way.
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

    public static func save(dataRepresentation: Data, metadata: KeyMetadata) throws {
        var attributes = baseQuery(name: metadata.name)
        attributes[kSecAttrLabel] = "Sequester: \(metadata.name)"
        attributes[kSecAttrGeneric] = try JSONEncoder().encode(metadata)
        attributes[kSecValueData] = dataRepresentation
        let status = SecItemAdd(attributes as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            throw KeychainError.duplicate(metadata.name)
        default:
            throw KeychainError.status(status)
        }
    }

    public static func list() throws -> [KeyMetadata] {
        var query = baseQuery()
        query[kSecMatchLimit] = kSecMatchLimitAll
        query[kSecReturnAttributes] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let items = result as? [[CFString: Any]] else {
            throw KeychainError.status(status)
        }
        let decoder = JSONDecoder()
        return items.compactMap { item -> KeyMetadata? in
            guard let generic = item[kSecAttrGeneric] as? Data else { return nil }
            return try? decoder.decode(KeyMetadata.self, from: generic)
        }
        .sorted { $0.createdAt < $1.createdAt }
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
        let update: [CFString: Any] = [
            kSecAttrAccount: metadata.name,
            kSecAttrLabel: "Sequester: \(metadata.name)",
            kSecAttrGeneric: try JSONEncoder().encode(metadata),
        ]
        let status = SecItemUpdate(baseQuery(name: oldName) as CFDictionary, update as CFDictionary)
        switch status {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            throw KeychainError.notFound(oldName)
        case errSecDuplicateItem:
            throw KeychainError.duplicate(metadata.name)
        default:
            throw KeychainError.status(status)
        }
    }

    public static func updateMetadata(_ metadata: KeyMetadata) throws {
        let update: [CFString: Any] = [
            kSecAttrGeneric: try JSONEncoder().encode(metadata),
        ]
        let status = SecItemUpdate(baseQuery(name: metadata.name) as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound { throw KeychainError.notFound(metadata.name) }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
    }

    public static func delete(name: String) throws {
        let status = SecItemDelete(baseQuery(name: name) as CFDictionary)
        if status == errSecItemNotFound { throw KeychainError.notFound(name) }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
    }
}
