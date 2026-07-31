import Foundation

/// Helpers for the SSH wire format used by the agent protocol
/// (draft-miller-ssh-agent): big-endian uint32 length prefixes, strings,
/// and mpints.
public enum SSHWire {

    public static func uint32(_ value: UInt32) -> Data {
        var big = value.bigEndian
        return withUnsafeBytes(of: &big) { Data($0) }
    }

    /// A string in SSH framing: uint32 length followed by the raw bytes.
    public static func lengthPrefixed(_ data: Data) -> Data {
        var out = uint32(UInt32(data.count))
        out.append(data)
        return out
    }

    public static func lengthPrefixed(_ string: String) -> Data {
        lengthPrefixed(Data(string.utf8))
    }

    /// Converts a fixed-width big-endian positive integer (e.g. r or s from a
    /// raw ECDSA signature) into an SSH mpint: leading zeros stripped, a 0x00
    /// prefix added when the high bit is set so the value stays positive.
    public static func mpint(fixedWidthPositive bytes: Data) -> Data {
        guard let firstNonZero = bytes.firstIndex(where: { $0 != 0 }) else {
            return Data()
        }
        var trimmed = Data(bytes[firstNonZero...])
        if let first = trimmed.first, first >= 0x80 {
            trimmed.insert(0x00, at: 0)
        }
        return trimmed
    }
}

/// Sequential reader over an SSH wire-format payload. Offsets are explicit so
/// Data slice index quirks cannot bite.
public struct SSHWireReader {

    public enum ReaderError: Error {
        case truncated
    }

    private let bytes: [UInt8]
    private var offset = 0

    public init(_ data: Data) {
        bytes = [UInt8](data)
    }

    public var isAtEnd: Bool { offset >= bytes.count }

    public mutating func readByte() throws -> UInt8 {
        guard offset < bytes.count else { throw ReaderError.truncated }
        defer { offset += 1 }
        return bytes[offset]
    }

    public mutating func readUInt32() throws -> UInt32 {
        guard offset + 4 <= bytes.count else { throw ReaderError.truncated }
        defer { offset += 4 }
        return (UInt32(bytes[offset]) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
    }

    public mutating func readString() throws -> Data {
        let length = Int(try readUInt32())
        guard length >= 0, offset + length <= bytes.count else {
            throw ReaderError.truncated
        }
        defer { offset += length }
        return Data(bytes[offset..<(offset + length)])
    }

    public mutating func readUTF8String() throws -> String {
        guard let string = String(data: try readString(), encoding: .utf8) else {
            throw ReaderError.truncated
        }
        return string
    }
}
