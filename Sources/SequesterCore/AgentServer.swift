import Foundation
import Darwin
import OSLog

public enum AgentServerError: LocalizedError {
    case socketFailed(String)

    public var errorDescription: String? {
        switch self {
        case .socketFailed(let detail):
            "Could not open the agent socket: \(detail)"
        }
    }
}

/// Serves the SSH agent protocol on a Unix domain socket using plain
/// blocking I/O on GCD queues: an accept loop, then one handling loop per
/// connection. Message framing is a big-endian uint32 length followed by
/// the payload.
public final class AgentServer: @unchecked Sendable {

    private static let logger = Logger(subsystem: "cz.szypowi.sequester", category: "AgentServer")
    private static let maxMessageSize: UInt32 = 1 << 20

    private let socketPath: String
    private let agent: Agent
    private let acceptQueue = DispatchQueue(label: "cz.szypowi.sequester.agent.accept")
    private var listenFD: Int32 = -1

    public init(socketPath: String, agent: Agent) {
        self.socketPath = socketPath
        self.agent = agent
    }

    public func start() throws {
        // A write to a peer that hung up must surface as an error, not
        // kill the process.
        signal(SIGPIPE, SIG_IGN)

        try SequesterPaths.ensureDirectory()
        unlink(socketPath)

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw AgentServerError.socketFailed(Self.errnoString()) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            close(fd)
            throw AgentServerError.socketFailed("socket path too long")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: pathBytes)
        }

        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bindResult = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bind(fd, sa, size)
            }
        }
        guard bindResult == 0 else {
            close(fd)
            throw AgentServerError.socketFailed("bind: \(Self.errnoString())")
        }
        chmod(socketPath, 0o600)
        guard listen(fd, 16) == 0 else {
            close(fd)
            throw AgentServerError.socketFailed("listen: \(Self.errnoString())")
        }

        listenFD = fd
        acceptQueue.async { [weak self] in self?.acceptLoop(listenFD: fd) }
        Self.logger.log("Agent listening at \(self.socketPath)")
    }

    public func stop() {
        if listenFD >= 0 {
            close(listenFD)
            listenFD = -1
        }
        unlink(socketPath)
    }

    private func acceptLoop(listenFD: Int32) {
        while true {
            let fd = accept(listenFD, nil, nil)
            guard fd >= 0 else {
                if errno == EINTR { continue }
                Self.logger.log("Accept loop ending: \(Self.errnoString())")
                return
            }
            var noSigpipe: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigpipe, socklen_t(MemoryLayout<Int32>.size))
            let agent = agent
            DispatchQueue.global(qos: .userInitiated).async {
                Self.handleConnection(fd: fd, agent: agent)
            }
        }
    }

    private static func handleConnection(fd: Int32, agent: Agent) {
        defer { close(fd) }
        let session = AgentSession(provenance: ProvenanceTracer.provenance(socket: fd))
        while true {
            guard let header = readExactly(fd: fd, count: 4) else { return }
            let length = header.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            guard length > 0, length <= maxMessageSize else { return }
            guard let message = readExactly(fd: fd, count: Int(length)) else { return }

            let response = awaitBlocking { await agent.handle(message: message, session: session) }
            guard writeFully(fd: fd, data: SSHWire.lengthPrefixed(response)) else { return }
        }
    }

    private static func readExactly(fd: Int32, count: Int) -> Data? {
        var buffer = [UInt8](repeating: 0, count: count)
        var total = 0
        while total < count {
            let n = buffer.withUnsafeMutableBytes { raw in
                read(fd, raw.baseAddress!.advanced(by: total), count - total)
            }
            if n == 0 { return nil }
            if n < 0 {
                if errno == EINTR { continue }
                return nil
            }
            total += n
        }
        return Data(buffer)
    }

    private static func writeFully(fd: Int32, data: Data) -> Bool {
        let remaining = [UInt8](data)
        var offset = 0
        while offset < remaining.count {
            let n = remaining.withUnsafeBytes { raw in
                write(fd, raw.baseAddress!.advanced(by: offset), remaining.count - offset)
            }
            if n < 0 {
                if errno == EINTR { continue }
                return false
            }
            offset += n
        }
        return true
    }

    /// Bridges the async handler into the blocking per-connection loop. The
    /// GCD thread parks on a semaphore while the handler (and any approval
    /// dialog on the main actor) runs on the concurrency pool.
    private static func awaitBlocking(_ operation: @escaping @Sendable () async -> Data) -> Data {
        let semaphore = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var result = Data()
        Task.detached {
            result = await operation()
            semaphore.signal()
        }
        semaphore.wait()
        return result
    }

    private static func errnoString() -> String {
        String(cString: strerror(errno))
    }
}
