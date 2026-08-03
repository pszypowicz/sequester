import Foundation

/// Shared constants for the secrets socket protocol. Framing matches the
/// agent socket: a big-endian uint32 length followed by one JSON payload.
public enum SecretsWireLimits {
    public static let version = 1
    public static let maxMessageSize = 1 << 20
    public static let maxVariables = 64
    public static let maxValueBytes = 64 * 1024
    public static let maxPlaintextBytes = 128 * 1024
}

/// What the client intends to do with the values. Client-declared, so it
/// prevents accidents (plaintext printed into a transcript), not a
/// determined caller.
public enum GetPurpose: String, Codable, Sendable {
    case exec
    case export
}

/// Creation-time choices, present only on a `set` that carries explicit
/// creation flags. Both are fixed or defaulted at creation; sending them for
/// an existing profile is an error.
public struct CreateOptions: Codable, Sendable, Equatable {
    public var tier: SecretTier
    public var exportDisabled: Bool

    public init(tier: SecretTier, exportDisabled: Bool) {
        self.tier = tier
        self.exportDisabled = exportDisabled
    }
}

public struct SecretsRequest: Codable, Sendable, Equatable {
    public enum Op: String, Codable, Sendable {
        case list
        case get
        case set
        case rm
    }

    public var v: Int
    public var op: Op
    public var profile: String?
    public var purpose: GetPurpose?
    public var values: [String: String]?
    public var create: CreateOptions?

    public init(op: Op, profile: String? = nil, purpose: GetPurpose? = nil,
                values: [String: String]? = nil, create: CreateOptions? = nil) {
        self.v = SecretsWireLimits.version
        self.op = op
        self.profile = profile
        self.purpose = purpose
        self.values = values
        self.create = create
    }
}

public struct ProfileSummary: Codable, Sendable, Equatable {
    public var name: String
    public var tier: SecretTier
    public var variables: [String]
    public var exportDisabled: Bool
    public var createdAt: Date
    public var updatedAt: Date

    public init(name: String, tier: SecretTier, variables: [String],
                exportDisabled: Bool, createdAt: Date, updatedAt: Date) {
        self.name = name
        self.tier = tier
        self.variables = variables
        self.exportDisabled = exportDisabled
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

/// Stable error codes the CLI maps to exit codes and messages. The raw
/// values are the wire contract; renaming a case must not change them.
public enum SecretsErrorCode: String, Codable, Sendable {
    case invalidRequest
    case unsupportedVersion
    case invalidName
    case invalidVariable
    case tooLarge
    case notFound
    case exists
    case denied
    case authFailed
    case exportDisabled
    case internalError = "internal"
}

public struct SecretsResponse: Codable, Sendable, Equatable {
    public var ok: Bool
    public var error: SecretsErrorCode?
    public var message: String?
    public var profiles: [ProfileSummary]?
    public var values: [String: String]?
    public var exportDisabled: Bool?
    public var created: Bool?
    public var variables: [String]?

    public init(ok: Bool, error: SecretsErrorCode? = nil, message: String? = nil,
                profiles: [ProfileSummary]? = nil, values: [String: String]? = nil,
                exportDisabled: Bool? = nil, created: Bool? = nil,
                variables: [String]? = nil) {
        self.ok = ok
        self.error = error
        self.message = message
        self.profiles = profiles
        self.values = values
        self.exportDisabled = exportDisabled
        self.created = created
        self.variables = variables
    }

    public static func failure(_ error: SecretsErrorCode, _ message: String) -> SecretsResponse {
        SecretsResponse(ok: false, error: error, message: message)
    }
}

/// One codec for both ends of the socket. Dates travel as plain epoch
/// seconds and keys are sorted, so non-Swift clients (the e2e rig) read
/// stable JSON.
public enum SecretsCodec {
    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }()

    public static func encode(_ value: some Encodable) throws -> Data {
        try encoder.encode(value)
    }

    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        try decoder.decode(type, from: data)
    }
}
