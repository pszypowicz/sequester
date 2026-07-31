import Foundation
import CryptoKit

/// OpenSSH representations for ECDSA P-256 keys (RFC 5656).
public enum OpenSSH {

    public static let p256Identifier = "ecdsa-sha2-nistp256"

    /// The public key blob: string identifier, string curve name, string Q
    /// (the uncompressed point, which is exactly CryptoKit's
    /// x963Representation).
    public static func p256PublicKeyBlob(x963: Data) -> Data {
        var blob = SSHWire.lengthPrefixed(p256Identifier)
        blob.append(SSHWire.lengthPrefixed("nistp256"))
        blob.append(SSHWire.lengthPrefixed(x963))
        return blob
    }

    /// The signature blob carried inside SSH_AGENT_SIGN_RESPONSE:
    /// string identifier, string (mpint r, mpint s). The caller adds the
    /// outer length prefix.
    public static func p256SignatureBlob(rawSignature: Data) -> Data {
        let half = rawSignature.count / 2
        let r = SSHWire.mpint(fixedWidthPositive: Data(rawSignature.prefix(half)))
        let s = SSHWire.mpint(fixedWidthPositive: Data(rawSignature.suffix(from: half)))
        var inner = SSHWire.lengthPrefixed(r)
        inner.append(SSHWire.lengthPrefixed(s))
        var blob = SSHWire.lengthPrefixed(p256Identifier)
        blob.append(SSHWire.lengthPrefixed(inner))
        return blob
    }

    /// A single authorized_keys / .pub line.
    public static func publicKeyLine(x963: Data, comment: String) -> String {
        let blob = p256PublicKeyBlob(x963: x963)
        return "\(p256Identifier) \(blob.base64EncodedString()) \(comment)"
    }

    /// OpenSSH-style fingerprint of a key blob: SHA256, base64 without
    /// padding.
    public static func fingerprintSHA256(blob: Data) -> String {
        let digest = SHA256.hash(data: blob)
        let b64 = Data(digest).base64EncodedString()
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
        return "SHA256:\(b64)"
    }

    /// The algorithm identifier at the head of a key blob, e.g.
    /// "ssh-ed25519" from a session-bind host key.
    public static func blobAlgorithm(_ blob: Data) -> String? {
        var reader = SSHWireReader(blob)
        return try? reader.readUTF8String()
    }
}
