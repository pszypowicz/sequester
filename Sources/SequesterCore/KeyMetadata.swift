import Foundation

/// Per-key signing behavior. Evaluated by the agent before every signature;
/// editable at any time, unlike the name and the Touch ID requirement.
public enum SigningPolicy: String, Codable, CaseIterable, Sendable {
    /// Every signature needs an in-app approval, local or forwarded.
    case askEveryTime
    /// Requests from sessions bound as local are allowed silently; forwarded
    /// or unbound sessions require approval.
    case allowLocalAskForwarded

    public var displayName: String {
        switch self {
        case .askEveryTime: "Ask every time"
        case .allowLocalAskForwarded: "Allow local, ask when forwarded"
        }
    }
}

/// Everything Sequester knows about a key besides the Secure Enclave key
/// material itself. Stored as JSON in the keychain item's generic attribute.
public struct KeyMetadata: Codable, Hashable, Sendable, Identifiable {

    /// Immutable; doubles as the on-disk public key filename
    /// (~/.sequester/<name>.pub), so ssh config references never break.
    public let name: String
    public var keyDescription: String
    /// Whether the Enclave demands user presence per signature. Baked into
    /// the key's access control at creation and unchangeable afterwards.
    public let authRequired: Bool
    public var policy: SigningPolicy
    /// Reserved for the pinned-destinations policy; unused for now.
    public var pinnedHosts: [String]
    /// The public key (x9.63 uncompressed point), cached at creation so
    /// listing never has to load Enclave key handles.
    public let publicKey: Data
    public let createdAt: Date

    public var id: String { name }

    public init(name: String, keyDescription: String, authRequired: Bool,
                policy: SigningPolicy, pinnedHosts: [String] = [],
                publicKey: Data, createdAt: Date) {
        self.name = name
        self.keyDescription = keyDescription
        self.authRequired = authRequired
        self.policy = policy
        self.pinnedHosts = pinnedHosts
        self.publicKey = publicKey
        self.createdAt = createdAt
    }

    public var publicKeyBlob: Data {
        OpenSSH.p256PublicKeyBlob(x963: publicKey)
    }

    public var fingerprint: String {
        OpenSSH.fingerprintSHA256(blob: publicKeyBlob)
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
    /// The name becomes a filename and an ssh config token, so it is kept to
    /// a conservative character set.
    public static func validate(_ name: String) throws {
        let pattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
        guard name.wholeMatch(of: pattern) != nil else {
            throw KeyNameError.invalid
        }
    }
}
