import Foundation
import SecretsWire

/// Per-connection state for the secrets socket: the connecting peer
/// (usually the bundled CLI) and the responsible process. Policy keys on
/// the responsible process, because the peer is always the CLI itself and
/// peer identity alone would approve anything that shells out to it.
public final class SecretsSession: Sendable {
    public let peer: Provenance
    public let responsible: Provenance
    public let responsibleInstanceID: String?

    public init(peer: Provenance, responsible: Provenance, responsibleInstanceID: String?) {
        self.peer = peer
        self.responsible = responsible
        self.responsibleInstanceID = responsibleInstanceID
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
        let (responsible, instanceID) = ProvenanceTracer.responsibleProvenance(forPid: peer.pid)
        Log.secrets.debug("Secrets connection opened by \(peer.displayName, privacy: .public) (pid \(peer.pid, privacy: .public)), responsible \(responsible.displayName, privacy: .public)")
        return SecretsSession(peer: peer, responsible: responsible, responsibleInstanceID: instanceID)
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
    /// The responsible process, which is what the user is authorizing.
    public let provenance: Provenance
    public let appStanding: AppStanding
    /// Whether the once/session/always picker is offered: read requests
    /// from a verified responsible process with no standing yet.
    public let offersScope: Bool

    public init(profileName: String, kind: Kind, variableNames: [String], tier: SecretTier,
                provenance: Provenance, appStanding: AppStanding, offersScope: Bool) {
        self.profileName = profileName
        self.kind = kind
        self.variableNames = variableNames
        self.tier = tier
        self.provenance = provenance
        self.appStanding = appStanding
        self.offersScope = offersScope
    }
}

public struct SecretsApprovalDecision: Sendable {
    public var allowed: Bool
    /// What to remember about the requesting app beyond this request.
    public var appScope: AppScope

    public init(allowed: Bool, appScope: AppScope = .once) {
        self.allowed = allowed
        self.appScope = appScope
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

/// Notified after every completed secrets operation so unexpected access
/// surfaces. `silent` is true when values were handed out with no user
/// interaction at all.
public protocol SecretsNotifier: Sendable {
    func read(profile: String, tier: SecretTier, requester: String, silent: Bool)
    func changed(profile: String, change: ProfileChange, requester: String)
    func denied(profile: String?, requester: String)
}

/// The app-evaluated biometric check gating unapprovedOnly reads. Injected
/// so the broker stays testable without LocalAuthentication.
public protocol BiometricGate: Sendable {
    func evaluate(reason: String) async -> Bool
}

/// The secrets protocol handler: parses one framed JSON request, resolves
/// policy against the responsible process, drives the approval dialog and
/// the biometric gate, and performs the storage operation. Values cross the
/// socket only in `get` responses and `set` requests.
public struct SecretsBroker: Sendable {

    private let approver: any SecretsApprover
    private let notifier: (any SecretsNotifier)?
    private let biometric: any BiometricGate

    public init(approver: any SecretsApprover, notifier: (any SecretsNotifier)? = nil,
                biometric: any BiometricGate) {
        self.approver = approver
        self.notifier = notifier
        self.biometric = biometric
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
        if standing(for: session, profile: nil) == .blocked {
            return refuse(profile: nil, session: session, op: "list")
        }
        let profiles = EnclaveProfileStore.list().map(\.summary)
        Log.secrets.debug("Listed \(profiles.count, privacy: .public) profiles for \(session.responsible.displayName, privacy: .public)")
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

        let standing = standing(for: session, profile: metadata)
        let outcome = SecretsPolicy.outcome(tier: metadata.tier, standing: standing,
                                            operation: .get, approveAll: metadata.approveAll)
        Log.secrets.log("Get request: profile \(name, privacy: .public), requester \(session.responsible.displayName, privacy: .public) (pid \(session.responsible.pid, privacy: .public)), peer \(session.peer.displayName, privacy: .public), standing \(String(describing: standing), privacy: .public), outcome \(String(describing: outcome), privacy: .public)")

        var interacted = false
        switch outcome {
        case .deny:
            return refuse(profile: name, session: session, op: "get")
        case .silentAllow:
            break
        case .dialogAsk:
            guard await approve(kind: .read, metadata: metadata, session: session, standing: standing) else {
                return .failure(.denied, "Refused.")
            }
            interacted = true
        case .biometricGate:
            // The dialog runs first when it can capture a standing decision;
            // for an unverified requester the biometric prompt, whose reason
            // names profile and requester, doubles as the approval.
            if standing == .unknown && session.responsible.identityKey != nil {
                guard await approve(kind: .read, metadata: metadata, session: session, standing: standing) else {
                    return .failure(.denied, "Refused.")
                }
            }
            guard await biometric.evaluate(reason: readReason(metadata: metadata, session: session)) else {
                return .failure(.authFailed, "Authentication failed.")
            }
            interacted = true
        }

        do {
            let values = try EnclaveProfileStore.readValues(name: name, reason: readReason(metadata: metadata, session: session))
            let silent = !interacted && metadata.tier != .everyRead
            notifier?.read(profile: name, tier: metadata.tier,
                           requester: session.responsible.displayName, silent: silent)
            return SecretsResponse(ok: true, values: values, exportDisabled: metadata.exportDisabled)
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
            return .failure(.exists, "Profile \"\(name)\" already exists; the Touch ID tier and export setting are fixed at creation.")
        }

        let create = request.create ?? CreateOptions(tier: .everyRead, exportDisabled: false)
        let tier = existing?.tier ?? create.tier
        let standing = standing(for: session, profile: existing)
        let outcome = SecretsPolicy.outcome(tier: tier, standing: standing,
                                            operation: .set, approveAll: existing?.approveAll ?? false)
        Log.secrets.log("Set request: profile \(name, privacy: .public), \(values.count, privacy: .public) variables, requester \(session.responsible.displayName, privacy: .public), standing \(String(describing: standing), privacy: .public), outcome \(String(describing: outcome), privacy: .public)")
        if case .deny = outcome {
            return refuse(profile: name, session: session, op: "set")
        }

        let variableNames = values.keys.sorted()
        let approvalRequest = SecretsApprovalRequest(
            profileName: name,
            kind: existing == nil ? .create : .update,
            variableNames: variableNames,
            tier: tier,
            provenance: session.responsible,
            appStanding: standing,
            offersScope: false
        )
        guard await approver.approve(approvalRequest).allowed else {
            return .failure(.denied, "Refused.")
        }

        do {
            if existing != nil {
                let metadata = try EnclaveProfileStore.updateValues(
                    name: name, setting: values,
                    reason: "update secrets profile \"\(name)\", requested by \(session.responsible.displayName)"
                )
                notifier?.changed(profile: name, change: .updated, requester: session.responsible.displayName)
                return SecretsResponse(ok: true, created: false, variables: metadata.variableNames)
            }
            let metadata = try EnclaveProfileStore.create(
                name: name, tier: create.tier, exportDisabled: create.exportDisabled, values: values
            )
            notifier?.changed(profile: name, change: .created, requester: session.responsible.displayName)
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
        let standing = standing(for: session, profile: metadata)
        let outcome = SecretsPolicy.outcome(tier: metadata.tier, standing: standing,
                                            operation: .rm, approveAll: metadata.approveAll)
        Log.secrets.log("Rm request: profile \(name, privacy: .public), requester \(session.responsible.displayName, privacy: .public), outcome \(String(describing: outcome), privacy: .public)")
        if case .deny = outcome {
            return refuse(profile: name, session: session, op: "rm")
        }
        guard await approve(kind: .delete, metadata: metadata, session: session, standing: standing) else {
            return .failure(.denied, "Refused.")
        }
        do {
            try EnclaveProfileStore.delete(name: name)
            notifier?.changed(profile: name, change: .deleted, requester: session.responsible.displayName)
            return SecretsResponse(ok: true)
        } catch {
            Log.secrets.error("Deleting profile \(name, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            return .failure(.internalError, error.localizedDescription)
        }
    }

    // MARK: - Helpers

    private func standing(for session: SecretsSession, profile: ProfileMetadata?) -> AppStanding {
        AppPolicy.standing(
            identityKey: session.responsible.identityKey,
            instance: session.responsibleInstanceID,
            perKeyRules: profile?.appRules ?? [],
            globalLookup: { AppAuthorizationStore.state(for: $0, domain: .secrets) },
            sessionAllowed: { AppSessionGrants.shared.isAllowed(identity: $0, instance: $1, domain: .secrets) },
            sessionBlocked: { AppSessionGrants.shared.isBlocked(instance: $0) }
        )
    }

    private func approve(kind: SecretsApprovalRequest.Kind, metadata: ProfileMetadata,
                         session: SecretsSession, standing: AppStanding) async -> Bool {
        let request = SecretsApprovalRequest(
            profileName: metadata.name,
            kind: kind,
            variableNames: metadata.variableNames,
            tier: metadata.tier,
            provenance: session.responsible,
            appStanding: standing,
            offersScope: kind == .read && standing == .unknown && session.responsible.identityKey != nil
        )
        let decision = await approver.approve(request)
        AppDecisionRecorder.apply(decision.appScope, provenance: session.responsible,
                                  instanceID: session.responsibleInstanceID, domain: .secrets)
        Log.secrets.log("Approval dialog for profile \(metadata.name, privacy: .public): allowed \(decision.allowed, privacy: .public), scope \(decision.appScope.rawValue, privacy: .public)")
        return decision.allowed
    }

    private func refuse(profile: String?, session: SecretsSession, op: String) -> SecretsResponse {
        Log.secrets.log("Refused \(op, privacy: .public) for \(session.responsible.displayName, privacy: .public): app blocked")
        notifier?.denied(profile: profile, requester: session.responsible.displayName)
        return .failure(.denied, "Refused by policy.")
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

    /// The reason shown in the Enclave prompt or the biometric gate. The
    /// requester name is attacker-influenced, so it comes last, after the
    /// profile it must not be able to forge, and it is sanitized in
    /// Provenance.displayName.
    private func readReason(metadata: ProfileMetadata, session: SecretsSession) -> String {
        "read secrets profile \"\(metadata.name)\", requested by \(session.responsible.displayName)"
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
