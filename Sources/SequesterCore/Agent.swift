import Foundation
import OSLog

/// One verified session-bind@openssh.com record. OpenSSH 8.9+ clients bind
/// every agent connection to the SSH session it serves, flagging
/// connections opened on behalf of a forwarded agent. A forwarded
/// connection accumulates one binding per hop. Only bindings whose
/// signature verified against the host key are ever stored.
public struct SessionBinding: Sendable, Hashable {
    public let hostKeyAlgorithm: String
    public let hostKeyFingerprint: String
    public let isForwarding: Bool
    /// The session identifier the binding is for; a signature is only
    /// issued silently when the request's own session identifier matches
    /// the destination binding.
    public let sessionID: Data
}

/// Per-connection state. A connection's messages are handled strictly
/// serially by one loop, so mutation is single-threaded despite the
/// unchecked conformance.
public final class AgentSession: @unchecked Sendable {
    public let provenance: Provenance
    /// Instance id of the responsible process (the terminal/IDE), for scoping
    /// "allow for this session" grants. Resolved once at connection time.
    public let responsibleInstanceID: String?
    public var bindings: [SessionBinding] = []

    public init(provenance: Provenance) {
        self.provenance = provenance
        self.responsibleInstanceID = ProvenanceTracer.responsibleInstanceID(forPid: provenance.pid)
    }

    public var bindingChain: [BindingHop] {
        bindings.map {
            BindingHop(fingerprint: $0.hostKeyFingerprint, algorithm: $0.hostKeyAlgorithm, forwarding: $0.isForwarding)
        }
    }
}

/// The facts of a signature request presented for confirmation.
public struct ApprovalRequest: Sendable {
    public let keyName: String
    public let provenance: Provenance
    public let bindingChain: [BindingHop]
    /// Whether "don't ask again" is offered; false for unbound requests,
    /// which have no destination to remember.
    public let canRemember: Bool
    /// The requesting app's current standing, so the dialog can show whether
    /// an authorization decision is being asked for.
    public let appStanding: AppStanding

    public init(keyName: String, provenance: Provenance, bindingChain: [BindingHop],
                canRemember: Bool, appStanding: AppStanding) {
        self.keyName = keyName
        self.provenance = provenance
        self.bindingChain = bindingChain
        self.canRemember = canRemember
        self.appStanding = appStanding
    }
}

public struct ApprovalDecision: Sendable {
    public var allowed: Bool
    /// Approve the destination so future requests on this exact path sign
    /// without asking.
    public var remember: Bool
    /// A name the user gave the destination host while answering.
    public var destinationName: String?
    /// What to remember about the requesting app beyond this signature.
    public var appScope: AppScope

    public init(allowed: Bool, remember: Bool = false, destinationName: String? = nil,
                appScope: AppScope = .once) {
        self.allowed = allowed
        self.remember = remember
        self.destinationName = destinationName
        self.appScope = appScope
    }

    public static let deny = ApprovalDecision(allowed: false)
}

/// Presented with the facts of a signature request, returns the user's
/// decision. The app implements this with a dialog.
public protocol SigningApprover: Sendable {
    func approve(_ request: ApprovalRequest) async -> ApprovalDecision
}

/// Notified after every successful signature so unexpected use surfaces.
/// `silent` is true when the signature happened with no user interaction
/// at all (no dialog and no Touch ID prompt), which is the case worth
/// noticing.
public protocol SigningNotifier: Sendable {
    func signed(keyName: String, authRequired: Bool, bindingChain: [BindingHop], silent: Bool)
    /// A request refused by policy before any prompt, so the user learns why
    /// a signature the terminal only reports as "agent refused operation" was
    /// turned down.
    func denied(keyName: String, authRequired: Bool, requester: String,
                bindingChain: [BindingHop], reason: PolicyEngine.DenialReason)
}

/// The SSH agent protocol handler: parses one client message, produces one
/// response. Only the read-side of the protocol is implemented; add/remove
/// operations are the app's job, so ssh-add mutations report failure.
public struct Agent: Sendable {

    private enum MessageType: UInt8 {
        case requestIdentities = 11
        case signRequest = 13
        case protocolExtension = 27
    }

    private enum Response {
        static let failure = Data([5])
        static let success = Data([6])
        static let identitiesAnswer: UInt8 = 12
        static let signResponse: UInt8 = 14
    }

    private let approver: any SigningApprover
    private let notifier: (any SigningNotifier)?

    public init(approver: any SigningApprover, notifier: (any SigningNotifier)? = nil) {
        self.approver = approver
        self.notifier = notifier
    }

    public func handle(message: Data, session: AgentSession) async -> Data {
        var reader = SSHWireReader(message)
        guard let rawType = try? reader.readByte() else { return Response.failure }
        switch MessageType(rawValue: rawType) {
        case .requestIdentities:
            return identitiesAnswer()
        case .signRequest:
            return await signResponse(reader: &reader, session: session)
        case .protocolExtension:
            return handleExtension(reader: &reader, session: session)
        case nil:
            Log.agent.log("Unhandled agent message type \(rawType, privacy: .public)")
            return Response.failure
        }
    }

    private func identitiesAnswer() -> Data {
        let keys = EnclaveKeyStore.list()
        Log.agent.debug("Listing \(keys.count, privacy: .public) identities")
        var payload = Data([Response.identitiesAnswer])
        payload.append(SSHWire.uint32(UInt32(keys.count)))
        for key in keys {
            payload.append(SSHWire.lengthPrefixed(key.publicKeyBlob))
            payload.append(SSHWire.lengthPrefixed(key.effectiveComment))
        }
        return payload
    }

    private func signResponse(reader: inout SSHWireReader, session: AgentSession) async -> Data {
        guard let keyBlob = try? reader.readString(),
              let dataToSign = try? reader.readString() else {
            return Response.failure
        }
        guard let key = EnclaveKeyStore.find(publicKeyBlob: keyBlob) else {
            Log.agent.log("Sign request for unknown key from \(session.provenance.displayName, privacy: .public)")
            return Response.failure
        }

        let bindingChain = session.bindingChain
        let appStanding = resolveAppStanding(key: key, session: session)
        let outcome = PolicyEngine.outcome(key: key, bindingChain: bindingChain,
                                           appStanding: appStanding, trust: session.provenance.trust)
        var decision = outcome.decision
        // A silent allow is only trustworthy when the signature is tied to
        // the destination that was actually bound. Without that tie a
        // verified binding for one session could be reused to authorize a
        // signature for another, so downgrade to asking.
        if decision == .allow && !destinationBound(session: session, dataToSign: dataToSign) {
            Log.agent.log("Downgrading allow to ask for \(key.name, privacy: .public): request not bound to the destination session")
            decision = .ask
        }

        // Bump an already-listed destination, but only add a new one when
        // the request was not denied, so a denied probe (a locked key, a
        // blocked forwarded path) cannot grow the destinations list; the
        // refusal lives in the log instead.
        if !bindingChain.isEmpty {
            let recorded = EnclaveKeyStore.recordObservation(name: key.name, hops: bindingChain, createIfNew: decision != .deny)
            if !recorded, let destination = bindingChain.last {
                Log.agent.log("Refused signature for \(destination.fingerprint, privacy: .public) with \(key.name, privacy: .public); denied by policy, not added to destinations")
            }
        }
        Log.agent.log("Sign request: key \(key.name, privacy: .public), requester \(session.provenance.displayName, privacy: .public) (pid \(session.provenance.pid, privacy: .public)), trust \(String(describing: session.provenance.trust), privacy: .public), app \(String(describing: appStanding), privacy: .public), chain \(DestinationRecord.bindingChainID(bindingChain), privacy: .public), decision \(String(describing: decision), privacy: .public)")

        switch decision {
        case .deny:
            if let reason = outcome.denialReason {
                notifier?.denied(keyName: key.name, authRequired: key.authRequired,
                                 requester: session.provenance.displayName,
                                 bindingChain: bindingChain, reason: reason)
            }
            return Response.failure
        case .allow:
            break
        case .ask:
            // Non-Touch-ID keys always show the app dialog. Touch ID keys show
            // it only when an app-authorization decision is needed (an unknown
            // app), since the Enclave prompt cannot capture allow/block; once
            // the app is authorized they go straight to the Enclave prompt,
            // which carries the request context in its reason string.
            if !key.authRequired || appStanding == .unknown {
                let approval = await approver.approve(ApprovalRequest(
                    keyName: key.name,
                    provenance: session.provenance,
                    bindingChain: bindingChain,
                    canRemember: !bindingChain.isEmpty && !key.authRequired,
                    appStanding: appStanding
                ))
                applyAppDecision(approval.appScope, session: session)
                if let destination = bindingChain.last, let name = approval.destinationName {
                    HostNames.shared.setName(name, for: destination.fingerprint)
                }
                // "Don't ask again" applies to either choice: allow remembers
                // as approved, deny remembers as blocked, which lets one
                // dialog end a stream of requests.
                if approval.remember, !bindingChain.isEmpty {
                    EnclaveKeyStore.setDestinationState(
                        name: key.name,
                        id: DestinationRecord.bindingChainID(bindingChain),
                        state: approval.allowed ? .approved : .blocked
                    )
                }
                guard approval.allowed else {
                    Log.agent.log("Denied signature with \(key.name, privacy: .public) for \(session.provenance.displayName, privacy: .public)")
                    return Response.failure
                }
            }
        }

        do {
            let raw = try EnclaveKeyStore.sign(
                name: key.name,
                data: dataToSign,
                reason: signReason(key: key, session: session, bindingChain: bindingChain)
            )
            Log.agent.log("Signed with \(key.name, privacy: .public) for \(session.provenance.displayName, privacy: .public)")
            let silent = decision == .allow && !key.authRequired
            notifier?.signed(keyName: key.name, authRequired: key.authRequired,
                             bindingChain: bindingChain, silent: silent)
            var payload = Data([Response.signResponse])
            payload.append(SSHWire.lengthPrefixed(OpenSSH.p256SignatureBlob(rawSignature: raw)))
            return payload
        } catch {
            // Touch ID cancellation lands here too; a failure response makes
            // the client report a clean "agent refused operation".
            Log.agent.error("Signing with \(key.name, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            return Response.failure
        }
    }

    /// The signed userauth blob begins with the session identifier. A
    /// silent signature requires it to match the destination binding, so a
    /// binding captured for one session cannot authorize another.
    private func destinationBound(session: AgentSession, dataToSign: Data) -> Bool {
        guard let destination = session.bindings.last else { return false }
        var reader = SSHWireReader(dataToSign)
        guard let signedSessionID = try? reader.readString() else { return false }
        return signedSessionID == destination.sessionID
    }

    /// Resolves the requesting app's effective standing from the per-key
    /// override, the global authorization store, and the in-memory session
    /// grants.
    private func resolveAppStanding(key: KeyMetadata, session: AgentSession) -> AppStanding {
        AppPolicy.standing(
            identityKey: session.provenance.identityKey,
            instance: session.responsibleInstanceID,
            perKeyRules: key.appRules,
            globalLookup: { AppAuthorizationStore.state(for: $0, domain: .ssh) },
            sessionAllowed: { AppSessionGrants.shared.isAllowed(identity: $0, instance: $1, domain: .ssh) },
            sessionBlocked: { AppSessionGrants.shared.isBlocked(instance: $0) }
        )
    }

    private func applyAppDecision(_ scope: AppScope, session: AgentSession) {
        AppDecisionRecorder.apply(scope, provenance: session.provenance,
                                  instanceID: session.responsibleInstanceID, domain: .ssh)
    }

    private func signReason(key: KeyMetadata, session: AgentSession, bindingChain: [BindingHop]) -> String {
        var reason = "sign an SSH request with key \"\(key.name)\""
        if let destination = bindingChain.last {
            reason += " for \(HostNames.shared.label(for: destination.fingerprint))"
        }
        if bindingChain.contains(where: { $0.forwarding }) {
            reason += " (FORWARDED)"
        }
        // The requester name is attacker-controlled, so it comes last, after
        // the authoritative key and destination that it must not be able to
        // forge, and it is sanitized in Provenance.displayName.
        reason += ", requested by \(session.provenance.displayName)"
        return reason
    }

    /// Records the binding only if its signature verifies against the host
    /// key. A forged binding (a host key the sender does not control)
    /// fails verification and is rejected, so it never enters the binding chain the
    /// policy sees.
    private func handleExtension(reader: inout SSHWireReader, session: AgentSession) -> Data {
        guard let name = try? reader.readUTF8String() else { return Response.failure }
        guard name == "session-bind@openssh.com" else {
            Log.agent.log("Unsupported agent extension \(name, privacy: .public)")
            return Response.failure
        }
        guard let hostKeyBlob = try? reader.readString(),
              let sessionID = try? reader.readString(),
              let signature = try? reader.readString(),
              let forwardingByte = try? reader.readByte() else {
            return Response.failure
        }
        // Bound the chain: a client could otherwise append host keys it
        // controls without limit, and the policy re-scans the chain on every
        // sign. Real forwarding chains are short.
        guard session.bindings.count < 32 else {
            Log.agent.log("Rejected session-bind: chain length limit reached, requester \(session.provenance.displayName, privacy: .public)")
            return Response.failure
        }
        let fingerprint = OpenSSH.fingerprintSHA256(blob: hostKeyBlob)
        guard HostKeyVerifier.verify(hostKey: hostKeyBlob, signature: signature, over: sessionID) else {
            Log.agent.log("Rejected session-bind with an invalid signature for \(fingerprint, privacy: .public), requester \(session.provenance.displayName, privacy: .public)")
            return Response.failure
        }
        let binding = SessionBinding(
            hostKeyAlgorithm: OpenSSH.blobAlgorithm(hostKeyBlob) ?? "unknown",
            hostKeyFingerprint: fingerprint,
            isForwarding: forwardingByte != 0,
            sessionID: sessionID
        )
        session.bindings.append(binding)
        Log.agent.log("Session bound to \(binding.hostKeyFingerprint, privacy: .public) (\(binding.hostKeyAlgorithm, privacy: .public)), forwarding \(binding.isForwarding, privacy: .public), requester \(session.provenance.displayName, privacy: .public)")
        return Response.success
    }
}
