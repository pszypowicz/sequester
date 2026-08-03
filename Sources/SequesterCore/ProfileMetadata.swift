import Foundation
import SecretsWire

/// Everything Sequester knows about a secrets profile besides the sealed
/// values and the Enclave key handle. Stored as JSON in the keychain item's
/// generic attribute; variable names live here so listing never decrypts,
/// and only values live in the sealed blob.
public struct ProfileMetadata: Codable, Hashable, Sendable, Identifiable {

    /// Renameable label; also the keychain account and the CLI argument.
    public var name: String
    /// The Touch ID tier. Fixed at creation: everyRead is baked into the
    /// Enclave key's access control, the softer tiers are app-enforced.
    public let tier: SecretTier
    /// Names of the variables in the sealed blob, sorted.
    public var variableNames: [String]
    /// Refuses reads declared as export, keeping plaintext off stdout.
    /// Accident prevention, not a security boundary: the purpose is
    /// client-declared.
    public var exportDisabled: Bool
    /// Reads for unknown callers proceed without asking. Blocked callers
    /// are still denied, and an everyRead profile still prompts in the
    /// Enclave.
    public var approveAll: Bool
    /// Per-profile overrides of an app's standing, taking precedence over
    /// the global authorization for this profile.
    public var appRules: [AppRule]
    /// The recipient public key (x9.63 uncompressed point), cached at
    /// creation so sealing new values never loads the Enclave key handle.
    public let publicKey: Data
    public let createdAt: Date
    public var updatedAt: Date
    public var lastRead: Date?

    public var id: String { name }

    public init(name: String, tier: SecretTier, variableNames: [String],
                exportDisabled: Bool = false, approveAll: Bool = false,
                appRules: [AppRule] = [], publicKey: Data,
                createdAt: Date, updatedAt: Date, lastRead: Date? = nil) {
        self.name = name
        self.tier = tier
        self.variableNames = variableNames
        self.exportDisabled = exportDisabled
        self.approveAll = approveAll
        self.appRules = appRules
        self.publicKey = publicKey
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.lastRead = lastRead
    }

    public var summary: ProfileSummary {
        ProfileSummary(name: name, tier: tier, variables: variableNames,
                       exportDisabled: exportDisabled, createdAt: createdAt,
                       updatedAt: updatedAt)
    }
}

public enum ProfileNameError: LocalizedError {
    case invalid

    public var errorDescription: String? {
        "Profile names must be 1-64 characters: letters, digits, dot, dash, or underscore, starting with a letter or digit."
    }
}

public enum ProfileName {
    /// Same conservative rules as key names: the name is a keychain account
    /// and a CLI token.
    public static func validate(_ name: String) throws {
        do {
            try KeyName.validate(name)
        } catch {
            throw ProfileNameError.invalid
        }
    }
}
