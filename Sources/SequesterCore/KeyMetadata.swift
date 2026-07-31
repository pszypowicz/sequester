import Foundation

/// Per-destination standing: neutral asks, approved signs silently,
/// blocked denies before any prompt (including Touch ID).
public enum DestinationState: String, Codable, Sendable {
    case neutral
    case approved
    case blocked
}

/// One hop of an observed session-binding chain: the host key the
/// connection was bound to, and whether the client flagged the binding as
/// made on behalf of a forwarded agent.
public struct ChainHop: Codable, Hashable, Sendable {
    public let fingerprint: String
    public let algorithm: String
    public let forwarding: Bool

    public init(fingerprint: String, algorithm: String, forwarding: Bool) {
        self.fingerprint = fingerprint
        self.algorithm = algorithm
        self.forwarding = forwarding
    }
}

/// A path a key has been asked to sign for, keyed by the exact binding
/// chain observed. Serves as both the usage log entry and the per-path
/// policy, so "github reached locally" and "github reached through vm1"
/// are distinct records with independent standing.
public struct DestinationRecord: Codable, Hashable, Sendable, Identifiable {
    public var hops: [ChainHop]
    public var state: DestinationState
    public var firstSeen: Date
    public var lastUsed: Date
    public var count: Int

    public init(hops: [ChainHop], state: DestinationState, firstSeen: Date, lastUsed: Date, count: Int) {
        self.hops = hops
        self.state = state
        self.firstSeen = firstSeen
        self.lastUsed = lastUsed
        self.count = count
    }

    public static func chainID(_ hops: [ChainHop]) -> String {
        hops.map { "\($0.fingerprint)\($0.forwarding ? ">" : "")" }.joined(separator: "|")
    }

    public var id: String { Self.chainID(hops) }

    public var isForwarded: Bool {
        hops.contains { $0.forwarding }
    }

    /// The final target of the chain.
    public var destination: ChainHop? { hops.last }
}

/// Everything Sequester knows about a key besides the Secure Enclave key
/// material itself. Stored as JSON in the keychain item's generic attribute.
public struct KeyMetadata: Codable, Hashable, Sendable, Identifiable {

    /// Renameable presentation label. The on-disk .pub filename is derived
    /// from the key material instead, so ssh config references survive
    /// renames.
    public var name: String
    public var keyDescription: String
    /// Whether the Enclave demands user presence per signature. Baked into
    /// the key's access control at creation and unchangeable afterwards.
    public let authRequired: Bool
    /// Denies every request arriving through a forwarded agent connection,
    /// regardless of per-destination standing.
    public var blockForwarded: Bool
    /// Observed signing paths with their standing.
    public var destinations: [DestinationRecord]
    /// The public key (x9.63 uncompressed point), cached at creation so
    /// listing never has to load Enclave key handles.
    public let publicKey: Data
    public let createdAt: Date

    public var id: String { name }

    public init(name: String, keyDescription: String, authRequired: Bool,
                blockForwarded: Bool = false, destinations: [DestinationRecord] = [],
                publicKey: Data, createdAt: Date) {
        self.name = name
        self.keyDescription = keyDescription
        self.authRequired = authRequired
        self.blockForwarded = blockForwarded
        self.destinations = destinations
        self.publicKey = publicKey
        self.createdAt = createdAt
    }

    enum CodingKeys: String, CodingKey {
        case name, keyDescription, authRequired, blockForwarded, destinations, publicKey, createdAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        keyDescription = try container.decode(String.self, forKey: .keyDescription)
        authRequired = try container.decode(Bool.self, forKey: .authRequired)
        blockForwarded = try container.decodeIfPresent(Bool.self, forKey: .blockForwarded) ?? false
        destinations = try container.decodeIfPresent([DestinationRecord].self, forKey: .destinations) ?? []
        publicKey = try container.decode(Data.self, forKey: .publicKey)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
    }

    public var publicKeyBlob: Data {
        OpenSSH.p256PublicKeyBlob(x963: publicKey)
    }

    public var fingerprint: String {
        OpenSSH.fingerprintSHA256(blob: publicKeyBlob)
    }

    public var fingerprintMD5: String {
        OpenSSH.fingerprintMD5(blob: publicKeyBlob)
    }

    /// Stable stem of the on-disk public key file, derived from the key.
    public var publicKeyFileStem: String {
        OpenSSH.fileStem(blob: publicKeyBlob)
    }

    public var publicKeyFileURL: URL {
        SequesterPaths.publicKeyURL(stem: publicKeyFileStem)
    }

    public var publicKeyLine: String {
        OpenSSH.publicKeyLine(x963: publicKey, comment: name)
    }
}

public enum KeyNameError: LocalizedError {
    case invalid

    public var errorDescription: String? {
        "Key names must be 1-64 characters: letters, digits, dot, dash, or underscore, starting with a letter or digit."
    }
}

public enum KeyName {
    /// The name becomes an ssh config token and a keychain account, so it
    /// is kept to a conservative character set.
    public static func validate(_ name: String) throws {
        let pattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
        guard name.wholeMatch(of: pattern) != nil else {
            throw KeyNameError.invalid
        }
    }
}
