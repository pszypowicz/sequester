import Foundation
import SecretsWire

/// Per-connection state for the secrets socket: the connecting peer (the
/// bundled CLI) and the process macOS holds responsible for it, which is
/// usually the terminal or IDE the command was run from.
///
/// Both are recorded for the prompts, the notifications, and the log, and
/// neither authorizes anything. Any local process can run the CLI, and the
/// responsible process is a presentation detail macOS derives for its own
/// UI, so treating it as a policy subject would promise a boundary the app
/// cannot hold.
public final class SecretsSession: Sendable {
    public let peer: Provenance
    public let responsible: Provenance

    public init(peer: Provenance, responsible: Provenance) {
        self.peer = peer
        self.responsible = responsible
    }

    /// Best-effort label for the requester, shown in prompts and
    /// notifications as context.
    public var requesterLabel: String {
        responsible.displayName
    }
}

/// Adapts the secrets broker to the socket transport.
public struct SecretsService: MessageService {

    private let broker: SecretsBroker

    public var logLabel: String { "secrets" }

    public init(broker: SecretsBroker) {
        self.broker = broker
    }

    public func makeSession(socket fd: Int32) -> SecretsSession {
        let peer = ProvenanceTracer.provenance(socket: fd)
        let (responsible, _) = ProvenanceTracer.responsibleProvenance(forPid: peer.pid)
        Log.secrets.debug("Secrets connection opened by \(peer.displayName, privacy: .public) (pid \(peer.pid, privacy: .public)), attributed to \(responsible.displayName, privacy: .public)")
        return SecretsSession(peer: peer, responsible: responsible)
    }

    public func handle(message: Data, session: SecretsSession) async -> Data {
        await broker.handle(message: message, session: session)
    }
}

/// The facts of a secrets request presented for confirmation.
public struct SecretsApprovalRequest: Sendable {
    public enum Kind: Equatable, Sendable {
        case read
        case create
        case update
        case delete
    }

    public let profileName: String
    public let kind: Kind
    public let variableNames: [String]
    public let tier: SecretTier
    /// Best-effort attribution of the request, for context only.
    public let requester: String
    /// Whether the dialog offers a grace window, which only a read of a
    /// confirm-every-read profile with one configured can use.
    public let offersGrace: Bool
    /// How long that window would last.
    public let graceSeconds: TimeInterval

    public init(profileName: String, kind: Kind, variableNames: [String], tier: SecretTier,
                requester: String, offersGrace: Bool, graceSeconds: TimeInterval = 0) {
        self.profileName = profileName
        self.kind = kind
        self.variableNames = variableNames
        self.tier = tier
        self.requester = requester
        self.offersGrace = offersGrace
        self.graceSeconds = graceSeconds
    }
}

public struct SecretsApprovalDecision: Sendable {
    public var allowed: Bool
    /// Waive confirmation for this profile for the next few minutes.
    public var grantGrace: Bool

    public init(allowed: Bool, grantGrace: Bool = false) {
        self.allowed = allowed
        self.grantGrace = grantGrace
    }

    public static let deny = SecretsApprovalDecision(allowed: false)
}

/// Presented with the facts of a secrets request, returns the user's
/// decision. The app implements this with a dialog.
public protocol SecretsApprover: Sendable {
    func approve(_ request: SecretsApprovalRequest) async -> SecretsApprovalDecision
}

public enum ProfileChange: String, Sendable {
    case created
    case updated
    case deleted
}

/// Notified after every completed secrets operation, which is what makes
/// use visible when no prompt was shown. `silent` is true when values were
/// handed out with no user interaction at all.
public protocol SecretsNotifier: Sendable {
    /// `overrides` carries the profile's own notification settings, since
    /// only the broker has its metadata at hand.
    func read(profile: String, tier: SecretTier, requester: String,
              silent: Bool, reusedAuthorization: Bool,
              overrides: ProfileNotificationOverride?)
    func changed(profile: String, change: ProfileChange, requester: String,
                 overrides: ProfileNotificationOverride?)
}

/// The secrets protocol handler: parses one framed JSON request, applies
/// the profile's own policy, drives the confirmation dialog, and performs
/// the storage operation. Values cross the socket only in `get` responses
/// and `set` requests.
public struct SecretsBroker: Sendable {

    private let approver: any SecretsApprover
    private let notifier: (any SecretsNotifier)?

    public init(approver: any SecretsApprover, notifier: (any SecretsNotifier)? = nil) {
        self.approver = approver
        self.notifier = notifier
    }

    public func handle(message: Data, session: SecretsSession) async -> Data {
        let response = await respond(to: message, session: session)
        if let data = try? SecretsCodec.encode(response) {
            return data
        }
        return Data(#"{"ok":false,"error":"internal"}"#.utf8)
    }

    private func respond(to message: Data, session: SecretsSession) async -> SecretsResponse {
        guard let request = try? SecretsCodec.decode(SecretsRequest.self, from: message) else {
            return .failure(.invalidRequest, "The request could not be parsed.")
        }
        guard request.v == SecretsWireLimits.version else {
            return .failure(.unsupportedVersion, "Protocol version \(request.v) is not supported.")
        }
        switch request.op {
        case .list:
            return handleList(session: session)
        case .get:
            return await handleGet(request, session: session)
        case .set:
            return await handleSet(request, session: session)
        case .rm:
            return await handleRm(request, session: session)
        }
    }

    // MARK: - Operations

    private func handleList(session: SecretsSession) -> SecretsResponse {
        let profiles = EnclaveProfileStore.list().map(\.summary)
        Log.secrets.debug("Listed \(profiles.count, privacy: .public) profiles for \(session.requesterLabel, privacy: .public)")
        return SecretsResponse(ok: true, profiles: profiles)
    }

    private func handleGet(_ request: SecretsRequest, session: SecretsSession) async -> SecretsResponse {
        guard let name = request.profile else {
            return .failure(.invalidRequest, "Missing profile name.")
        }
        guard let metadata = EnclaveProfileStore.find(name: name) else {
            return .failure(.notFound, "No profile named \"\(name)\".")
        }
        // Checked before any prompt so a refused export never costs a tap.
        if request.purpose == .export && metadata.exportDisabled {
            return .failure(.exportDisabled, "Profile \"\(name)\" does not allow env export. Use env exec instead.")
        }

        let graceActive = SecretsGraceWindows.shared.isActive(profile: name)
        let outcome = SecretsPolicy.outcome(tier: metadata.tier, operation: .get, graceActive: graceActive)
        Log.secrets.log("Get request: profile \(name, privacy: .public), tier \(metadata.tier.rawValue, privacy: .public), requester \(session.requesterLabel, privacy: .public), peer \(session.peer.displayName, privacy: .public), grace \(graceActive, privacy: .public), outcome \(String(describing: outcome), privacy: .public)")

        var confirmed = false
        if outcome == .dialogAsk {
            let decision = await approve(kind: .read, metadata: metadata, session: session,
                                         offersGrace: metadata.tier == .confirmEveryRead
                                                      && metadata.rememberSeconds > 0)
            guard decision.allowed else {
                return .failure(.denied, "Refused.")
            }
            if decision.grantGrace {
                SecretsGraceWindows.shared.grant(profile: name, seconds: metadata.rememberSeconds)
            }
            confirmed = true
        }

        do {
            let read = try EnclaveProfileStore.readValues(
                name: name, reason: readReason(metadata: metadata, session: session))
            let silent = !confirmed && (metadata.tier != .everyRead || read.reusedAuthorization)
            notifier?.read(profile: name, tier: metadata.tier,
                           requester: session.requesterLabel, silent: silent,
                           reusedAuthorization: read.reusedAuthorization,
                           overrides: metadata.notifications)
            return SecretsResponse(ok: true, values: read.values, exportDisabled: metadata.exportDisabled)
        } catch {
            return decryptFailure(error, profile: name)
        }
    }

    private func handleSet(_ request: SecretsRequest, session: SecretsSession) async -> SecretsResponse {
        guard let name = request.profile, let values = request.values, !values.isEmpty else {
            return .failure(.invalidRequest, "Missing profile name or values.")
        }
        if let invalid = validate(name: name, values: values) {
            return invalid
        }
        let existing = EnclaveProfileStore.find(name: name)
        if existing != nil && request.create != nil {
            return .failure(.exists, "Profile \"\(name)\" already exists; the confirmation tier and export setting are fixed at creation.")
        }

        let create = request.create ?? CreateOptions(tier: .everyRead, exportDisabled: false)
        let tier = existing?.tier ?? create.tier
        Log.secrets.log("Set request: profile \(name, privacy: .public), \(values.count, privacy: .public) variables, requester \(session.requesterLabel, privacy: .public)")

        let approvalRequest = SecretsApprovalRequest(
            profileName: name,
            kind: existing == nil ? .create : .update,
            variableNames: values.keys.sorted(),
            tier: tier,
            requester: session.requesterLabel,
            offersGrace: false
        )
        guard await approver.approve(approvalRequest).allowed else {
            return .failure(.denied, "Refused.")
        }

        do {
            if existing != nil {
                let metadata = try EnclaveProfileStore.updateValues(
                    name: name, setting: values,
                    reason: "update secrets profile \"\(name)\", requested by \(session.requesterLabel)"
                )
                notifier?.changed(profile: name, change: .updated, requester: session.requesterLabel,
                                  overrides: metadata.notifications)
                return SecretsResponse(ok: true, created: false, variables: metadata.variableNames)
            }
            let metadata = try EnclaveProfileStore.create(
                name: name, tier: create.tier, exportDisabled: create.exportDisabled, values: values
            )
            notifier?.changed(profile: name, change: .created, requester: session.requesterLabel,
                              overrides: metadata.notifications)
            return SecretsResponse(ok: true, created: true, variables: metadata.variableNames)
        } catch let error as ProfileStoreError {
            return .failure(.tooLarge, error.localizedDescription)
        } catch {
            return decryptFailure(error, profile: name)
        }
    }

    private func handleRm(_ request: SecretsRequest, session: SecretsSession) async -> SecretsResponse {
        guard let name = request.profile else {
            return .failure(.invalidRequest, "Missing profile name.")
        }
        guard let metadata = EnclaveProfileStore.find(name: name) else {
            return .failure(.notFound, "No profile named \"\(name)\".")
        }
        Log.secrets.log("Rm request: profile \(name, privacy: .public), requester \(session.requesterLabel, privacy: .public)")
        guard await approve(kind: .delete, metadata: metadata, session: session, offersGrace: false).allowed else {
            return .failure(.denied, "Refused.")
        }
        do {
            try EnclaveProfileStore.delete(name: name)
            notifier?.changed(profile: name, change: .deleted, requester: session.requesterLabel,
                              overrides: metadata.notifications)
            return SecretsResponse(ok: true)
        } catch {
            Log.secrets.error("Deleting profile \(name, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            return .failure(.internalError, error.localizedDescription)
        }
    }

    // MARK: - Helpers

    private func approve(kind: SecretsApprovalRequest.Kind, metadata: ProfileMetadata,
                         session: SecretsSession, offersGrace: Bool) async -> SecretsApprovalDecision {
        let decision = await approver.approve(SecretsApprovalRequest(
            profileName: metadata.name,
            kind: kind,
            variableNames: metadata.variableNames,
            tier: metadata.tier,
            requester: session.requesterLabel,
            offersGrace: offersGrace,
            graceSeconds: metadata.rememberSeconds
        ))
        Log.secrets.log("Dialog for profile \(metadata.name, privacy: .public): allowed \(decision.allowed, privacy: .public), grace \(decision.grantGrace, privacy: .public)")
        return decision
    }

    private func validate(name: String, values: [String: String]) -> SecretsResponse? {
        do {
            try ProfileName.validate(name)
        } catch {
            return .failure(.invalidName, error.localizedDescription)
        }
        do {
            try EnclaveProfileStore.validate(values: values)
        } catch let error as ProfileStoreError {
            return .failure(.tooLarge, error.localizedDescription)
        } catch {
            return .failure(.invalidVariable, error.localizedDescription)
        }
        guard values.count <= SecretsWireLimits.maxVariables else {
            return .failure(.tooLarge, ProfileStoreError.tooManyVariables.localizedDescription)
        }
        return nil
    }

    /// The reason shown in the Enclave prompt. The requester label is
    /// attacker-influenced, so it comes last, after the profile it must not
    /// be able to forge, and it is sanitized in Provenance.displayName.
    private func readReason(metadata: ProfileMetadata, session: SecretsSession) -> String {
        "read secrets profile \"\(metadata.name)\", requested by \(session.requesterLabel)"
    }

    /// Cancelled Touch ID, a locked screen, and a corrupt blob all surface
    /// as decrypt errors; cipher and decoding failures are internal, the
    /// rest are authentication.
    private func decryptFailure(_ error: Error, profile: String) -> SecretsResponse {
        Log.secrets.error("Reading profile \(profile, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
        switch error {
        case is ProfileCipherError, is DecodingError, is KeychainError:
            return .failure(.internalError, error.localizedDescription)
        default:
            return .failure(.authFailed, "Authentication failed or was cancelled.")
        }
    }
}
