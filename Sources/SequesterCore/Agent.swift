import Foundation
import OSLog

/// One session-bind@openssh.com record received on a connection. OpenSSH
/// 8.9+ clients bind every agent connection to the SSH session it serves,
/// flagging connections opened on behalf of a forwarded agent. A forwarded
/// connection accumulates one binding per hop.
public struct SessionBinding: Sendable, Hashable {
    public let hostKeyAlgorithm: String
    public let hostKeyFingerprint: String
    public let isForwarding: Bool
}

/// Per-connection state. A connection's messages are handled strictly
/// serially by one loop, so mutation is single-threaded despite the
/// unchecked conformance.
public final class AgentSession: @unchecked Sendable {
    public let provenance: Provenance
    public var bindings: [SessionBinding] = []

    public init(provenance: Provenance) {
        self.provenance = provenance
    }

    public var chain: [ChainHop] {
        bindings.map {
            ChainHop(fingerprint: $0.hostKeyFingerprint, algorithm: $0.hostKeyAlgorithm, forwarding: $0.isForwarding)
        }
    }
}

/// The facts of a signature request presented for confirmation.
public struct ApprovalRequest: Sendable {
    public let keyName: String
    public let provenance: Provenance
    public let chain: [ChainHop]
    /// Whether "don't ask again" is offered; false for unbound requests,
    /// which have no destination to remember.
    public let canRemember: Bool
}

public struct ApprovalDecision: Sendable {
    public var allowed: Bool
    /// Approve the destination so future requests on this exact path sign
    /// without asking.
    public var remember: Bool
    /// A name the user gave the destination host while answering.
    public var destinationName: String?

    public init(allowed: Bool, remember: Bool = false, destinationName: String? = nil) {
        self.allowed = allowed
        self.remember = remember
        self.destinationName = destinationName
    }

    public static let deny = ApprovalDecision(allowed: false)
}

/// Presented with the facts of a signature request, returns the user's
/// decision. The app implements this with a dialog.
public protocol SigningApprover: Sendable {
    func approve(_ request: ApprovalRequest) async -> ApprovalDecision
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

    public init(approver: any SigningApprover) {
        self.approver = approver
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
            payload.append(SSHWire.lengthPrefixed(key.name))
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

        let chain = session.chain
        if !chain.isEmpty {
            EnclaveKeyStore.recordObservation(name: key.name, hops: chain)
        }

        let decision = PolicyEngine.evaluate(key: key, chain: chain)
        Log.agent.log("Sign request: key \(key.name, privacy: .public), requester \(session.provenance.displayName, privacy: .public) (pid \(session.provenance.pid, privacy: .public)), chain \(DestinationRecord.chainID(chain), privacy: .public), decision \(String(describing: decision), privacy: .public)")

        switch decision {
        case .deny:
            return Response.failure
        case .allow:
            break
        case .ask:
            // For Touch ID keys the Enclave prompt is the ask; the reason
            // string carries the request context. Other keys get the app
            // dialog.
            if !key.authRequired {
                let approval = await approver.approve(ApprovalRequest(
                    keyName: key.name,
                    provenance: session.provenance,
                    chain: chain,
                    canRemember: !chain.isEmpty
                ))
                guard approval.allowed else {
                    Log.agent.log("Denied signature with \(key.name, privacy: .public) for \(session.provenance.displayName, privacy: .public)")
                    return Response.failure
                }
                if let destination = chain.last, let name = approval.destinationName {
                    HostNames.shared.setName(name, for: destination.fingerprint)
                }
                if approval.remember {
                    EnclaveKeyStore.setDestinationState(name: key.name, id: DestinationRecord.chainID(chain), state: .approved)
                }
            }
        }

        do {
            let raw = try EnclaveKeyStore.sign(
                name: key.name,
                data: dataToSign,
                reason: signReason(key: key, session: session, chain: chain)
            )
            Log.agent.log("Signed with \(key.name, privacy: .public) for \(session.provenance.displayName, privacy: .public)")
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

    private func signReason(key: KeyMetadata, session: AgentSession, chain: [ChainHop]) -> String {
        var reason = "sign an SSH request from \(session.provenance.displayName) with key \"\(key.name)\""
        if let destination = chain.last {
            reason += " for \(HostNames.shared.label(for: destination.fingerprint))"
        }
        if chain.contains(where: { $0.forwarding }) {
            reason += " (FORWARDED)"
        }
        return reason
    }

    /// Records the binding the client reports; the policy layer fails safe,
    /// so any forwarded or unknown path asks before signing.
    private func handleExtension(reader: inout SSHWireReader, session: AgentSession) -> Data {
        guard let name = try? reader.readUTF8String() else { return Response.failure }
        guard name == "session-bind@openssh.com" else {
            Log.agent.log("Unsupported agent extension \(name, privacy: .public)")
            return Response.failure
        }
        guard let hostKeyBlob = try? reader.readString(),
              let _ = try? reader.readString(),  // session identifier
              let _ = try? reader.readString(),  // signature over the session identifier
              let forwardingByte = try? reader.readByte() else {
            return Response.failure
        }
        let binding = SessionBinding(
            hostKeyAlgorithm: OpenSSH.blobAlgorithm(hostKeyBlob) ?? "unknown",
            hostKeyFingerprint: OpenSSH.fingerprintSHA256(blob: hostKeyBlob),
            isForwarding: forwardingByte != 0
        )
        session.bindings.append(binding)
        Log.agent.log("Session bound to \(binding.hostKeyFingerprint, privacy: .public) (\(binding.hostKeyAlgorithm, privacy: .public)), forwarding \(binding.isForwarding, privacy: .public), requester \(session.provenance.displayName, privacy: .public)")
        return Response.success
    }
}
