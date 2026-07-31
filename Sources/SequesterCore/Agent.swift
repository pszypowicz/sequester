import Foundation
import OSLog

/// One session-bind@openssh.com record received on a connection. OpenSSH
/// 8.9+ clients bind every agent connection to the SSH session it serves,
/// flagging connections opened on behalf of a forwarded agent.
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

    public var isForwarded: Bool {
        bindings.contains { $0.isForwarding }
    }
}

/// Presented with the facts of a signature request, returns whether the
/// user allows it. The app implements this with a dialog.
public protocol SigningApprover: Sendable {
    func approve(keyName: String, provenance: Provenance, bindings: [SessionBinding]) async -> Bool
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

        let needsApproval = requiresApproval(policy: key.policy, session: session)
        Log.agent.log("Sign request: key \(key.name, privacy: .public), requester \(session.provenance.displayName, privacy: .public) (pid \(session.provenance.pid, privacy: .public)), policy \(key.policy.rawValue, privacy: .public), forwarded \(session.isForwarded, privacy: .public), bindings \(session.bindings.count, privacy: .public), approval needed \(needsApproval, privacy: .public)")
        if needsApproval {
            let allowed = await approver.approve(
                keyName: key.name,
                provenance: session.provenance,
                bindings: session.bindings
            )
            guard allowed else {
                Log.agent.log("Denied signature with \(key.name, privacy: .public) for \(session.provenance.displayName, privacy: .public)")
                return Response.failure
            }
            Log.agent.log("User approved signature with \(key.name, privacy: .public)")
        }

        do {
            let raw = try EnclaveKeyStore.sign(
                name: key.name,
                data: dataToSign,
                reason: "sign an SSH request from \(session.provenance.displayName) with key \"\(key.name)\""
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

    /// v1 records what the client claims and fails safe: any forwarded or
    /// unbound session asks. Verifying the binding signature against the
    /// host key is a planned hardening step.
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

    private func requiresApproval(policy: SigningPolicy, session: AgentSession) -> Bool {
        switch policy {
        case .askEveryTime:
            true
        case .allowLocalAskForwarded:
            session.bindings.isEmpty || session.isForwarded
        }
    }
}
