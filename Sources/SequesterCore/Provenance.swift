import Foundation
import Darwin

/// Identity of the local process on the other end of an agent connection.
public struct Provenance: Sendable, Hashable {
    public let pid: pid_t
    public let path: String?

    public var displayName: String {
        guard let path else { return "pid \(pid)" }
        return URL(filePath: path).lastPathComponent
    }
}

public enum ProvenanceTracer {

    /// Resolves the peer of a connected Unix socket via LOCAL_PEERPID and
    /// libproc. Best effort: a failure yields pid -1 and no path.
    public static func provenance(socket fd: Int32) -> Provenance {
        var pid: pid_t = -1
        var size = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0 else {
            return Provenance(pid: -1, path: nil)
        }
        var buffer = [CChar](repeating: 0, count: 4096)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        let path = length > 0 ? String(cString: buffer) : nil
        return Provenance(pid: pid, path: path)
    }
}
