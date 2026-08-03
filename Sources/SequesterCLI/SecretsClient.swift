import Foundation
import Darwin
import SecretsWire

/// A CLI failure with the exit code it maps to: 1 for local problems, 2 for
/// requests the app refused, 3 when the app is not reachable.
struct CLIError: Error {
    let message: String
    let code: Int32

    static func local(_ message: String) -> CLIError { CLIError(message: message, code: 1) }
    static func refused(_ message: String) -> CLIError { CLIError(message: message, code: 2) }
    static func unreachable(_ message: String) -> CLIError { CLIError(message: message, code: 3) }
}

func printError(_ message: String) {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}

/// Blocking client for the app's secrets socket. One request, one framed
/// JSON response; the read has no timeout because a pending approval dialog
/// or Touch ID prompt legitimately blocks it.
struct SecretsClient {

    private let socketPath: String

    init() {
        socketPath = SecretsSocket.resolvedPath(home: NSHomeDirectory())
    }

    func send(_ request: SecretsRequest) throws -> SecretsResponse {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw CLIError.local("socket: \(errnoString())") }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            throw CLIError.local("socket path too long: \(socketPath)")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: pathBytes)
        }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let connected = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                connect(fd, sa, size)
            }
        }
        guard connected == 0 else {
            if errno == ENOENT || errno == ECONNREFUSED {
                throw CLIError.unreachable("Sequester is not running. Open Sequester.app and try again.")
            }
            throw CLIError.local("connect: \(errnoString())")
        }

        let payload = try SecretsCodec.encode(request)
        var frame = withUnsafeBytes(of: UInt32(payload.count).bigEndian) { Data($0) }
        frame.append(payload)
        guard writeFully(fd: fd, data: frame) else {
            throw CLIError.local("write: \(errnoString())")
        }

        // Approval dialogs and Touch ID prompts appear in the app, which is
        // easy to miss from a terminal; say so once the wait gets long.
        let notice = DispatchWorkItem {
            printError("Waiting for approval in Sequester...")
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.3, execute: notice)
        defer { notice.cancel() }

        guard let header = readExactly(fd: fd, count: 4) else {
            throw CLIError.local("Sequester closed the connection.")
        }
        let length = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
        guard length > 0, length <= UInt32(SecretsWireLimits.maxMessageSize) else {
            throw CLIError.local("Malformed response from Sequester.")
        }
        guard let body = readExactly(fd: fd, count: Int(length)),
              let response = try? SecretsCodec.decode(SecretsResponse.self, from: body) else {
            throw CLIError.local("Malformed response from Sequester.")
        }
        return response
    }

    private func readExactly(fd: Int32, count: Int) -> Data? {
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

    private func writeFully(fd: Int32, data: Data) -> Bool {
        let bytes = [UInt8](data)
        var offset = 0
        while offset < bytes.count {
            let n = bytes.withUnsafeBytes { raw in
                write(fd, raw.baseAddress!.advanced(by: offset), bytes.count - offset)
            }
            if n < 0 {
                if errno == EINTR { continue }
                return false
            }
            offset += n
        }
        return true
    }

    private func errnoString() -> String {
        String(cString: strerror(errno))
    }
}

extension SecretsResponse {
    /// Turns a refused response into the CLIError carrying its exit code.
    @discardableResult
    func unwrap() throws -> SecretsResponse {
        guard ok else {
            let text = message ?? "Request failed."
            switch error {
            case .denied, .authFailed, .exportDisabled:
                throw CLIError.refused(text)
            default:
                throw CLIError.local(text)
            }
        }
        return self
    }
}
