import Foundation

/// Adapts the SSH agent to the socket transport: one AgentSession per
/// connection, identified from the peer's socket credentials.
public struct AgentService: MessageService {

    private let agent: Agent

    public var logLabel: String { "agent" }

    public init(agent: Agent) {
        self.agent = agent
    }

    public func makeSession(socket fd: Int32) -> AgentSession {
        let session = AgentSession(provenance: ProvenanceTracer.provenance(socket: fd))
        Log.server.debug("Agent connection opened by \(session.provenance.displayName, privacy: .public) (pid \(session.provenance.pid, privacy: .public), \(session.provenance.path ?? "unknown path", privacy: .public))")
        return session
    }

    public func handle(message: Data, session: AgentSession) async -> Data {
        await agent.handle(message: message, session: session)
    }
}
