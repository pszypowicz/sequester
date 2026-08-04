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
public struct BindingHop: Codable, Hashable, Sendable {
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
    public var hops: [BindingHop]
    public var state: DestinationState
    public var firstSeen: Date
    public var lastUsed: Date
    public var count: Int

    public init(hops: [BindingHop], state: DestinationState, firstSeen: Date, lastUsed: Date, count: Int) {
        self.hops = hops
        self.state = state
        self.firstSeen = firstSeen
        self.lastUsed = lastUsed
        self.count = count
    }

    public static func bindingChainID(_ hops: [BindingHop]) -> String {
        hops.map { "\($0.fingerprint)\($0.forwarding ? ">" : "")" }.joined(separator: "|")
    }

    public var id: String { Self.bindingChainID(hops) }

    /// The final target of the binding chain.
    public var destination: BindingHop? { hops.last }
}

/// What recording an observed binding chain did to the usage log.
public enum DestinationObservation: Equatable, Sendable {
    /// The chain was already listed; its counter and timestamp advanced.
    case updated
    /// The chain was not listed and has been added as a neutral record, so
    /// this is the key's first use of that destination.
    case added
    /// Nothing was recorded: the chain was unlisted and `createIfNew` was
    /// not set, as for a request policy denied.
    case skipped
}

/// A standing applied to every path whose binding chain starts with these hops,
/// so a whole branch of the destination tree can be governed at once.
public struct BranchRule: Codable, Hashable, Sendable, Identifiable {
    public var hops: [BindingHop]
    public var state: DestinationState

    public init(hops: [BindingHop], state: DestinationState) {
        self.hops = hops
        self.state = state
    }

    public var id: String { DestinationRecord.bindingChainID(hops) }

    public func matches(_ bindingChain: [BindingHop]) -> Bool {
        bindingChain.count >= hops.count && Array(bindingChain.prefix(hops.count)) == hops
    }
}

/// Everything Sequester knows about a key besides the Secure Enclave key
/// material itself. Stored as JSON in the keychain item's generic attribute.
public struct KeyMetadata: Codable, Hashable, Sendable, Identifiable {

    /// Renameable presentation label.
    public var name: String
    public var keyDescription: String
    /// Whether the Enclave demands user presence per signature. Baked into
    /// the key's access control at creation and unchangeable afterwards.
    public let authRequired: Bool
    /// Denies every request arriving through a forwarded agent connection,
    /// regardless of per-destination standing.
    public var blockForwarded: Bool
    /// Signs every request without asking, forwarded or not, except what is
    /// explicitly blocked. Only meaningful for keys without the Touch ID
    /// requirement.
    public var approveAll: Bool
    /// Signs local (non-forwarded) requests without asking. Only meaningful
    /// for keys without the Touch ID requirement, whose Enclave prompt
    /// cannot be skipped.
    public var autoApprove: Bool
    /// Finalizes the key to the destinations it already knows: a recorded
    /// chain keeps its standing, and any chain with no record is denied
    /// without asking, so nothing new is learned.
    public var locked: Bool
    /// Observed signing paths with their standing.
    public var destinations: [DestinationRecord]
    /// Standings applied to whole branches of the destination tree.
    public var branchRules: [BranchRule]
    /// Per-key overrides of an app's standing, taking precedence over the
    /// global authorization for this key.
    public var appRules: [AppRule]
    /// How long a Touch ID tap is remembered for this key, in seconds.
    /// Zero, the default, means every signature prompts. A window only ever
    /// covers the exact destination path it was granted for, and never a
    /// path that arrived through a forwarding hop.
    public var rememberSeconds: TimeInterval
    /// Optional public key comment. When nil or empty the .pub file and the
    /// agent use "<name>@sequester", which tracks renames; a custom value
    /// (such as an email) is used verbatim.
    public var comment: String?
    /// This key's own notification settings. Nil, the default, follows the
    /// global ones.
    public var notifications: KeyNotificationOverride?
    /// The public key (x9.63 uncompressed point), cached at creation so
    /// listing never has to load Enclave key handles.
    public let publicKey: Data
    public let createdAt: Date

    public var id: String { name }

    public init(name: String, keyDescription: String, authRequired: Bool,
                blockForwarded: Bool = false, approveAll: Bool = false,
                autoApprove: Bool = false, locked: Bool = false,
                destinations: [DestinationRecord] = [],
                branchRules: [BranchRule] = [], appRules: [AppRule] = [],
                rememberSeconds: TimeInterval = 0,
                comment: String? = nil,
                notifications: KeyNotificationOverride? = nil,
                publicKey: Data, createdAt: Date) {
        self.name = name
        self.keyDescription = keyDescription
        self.authRequired = authRequired
        self.blockForwarded = blockForwarded
        self.approveAll = approveAll
        self.autoApprove = autoApprove
        self.locked = locked
        self.destinations = destinations
        self.branchRules = branchRules
        self.appRules = appRules
        self.rememberSeconds = rememberSeconds
        self.comment = comment
        self.notifications = notifications
        self.publicKey = publicKey
        self.createdAt = createdAt
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

    /// Stem of the on-disk public key file.
    public var publicKeyFileStem: String {
        OpenSSH.fileStem(blob: publicKeyBlob)
    }

    public var publicKeyFileURL: URL {
        SequesterPaths.publicKeyURL(stem: publicKeyFileStem)
    }

    /// The comment written into the .pub file and offered by the agent.
    public var effectiveComment: String {
        if let comment, !comment.isEmpty { return comment }
        return "\(name)@sequester"
    }

    public var publicKeyLine: String {
        OpenSSH.publicKeyLine(x963: publicKey, comment: effectiveComment)
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
