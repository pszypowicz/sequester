import Foundation
import CryptoKit
import Security

/// Verifies the signature inside a session-bind@openssh.com record: proof
/// that whoever produced the binding holds the destination host's private
/// key, signing over that connection's session identifier. A binding for a
/// host key the sender does not control fails here, which is what
/// distinguishes a genuine hop from one an intermediate host fabricated.
///
/// Supports the host key types that appear in practice: Ed25519, ECDSA
/// (nistp256/384/521), and RSA. An unrecognized type fails closed.
public enum HostKeyVerifier {

    public static func verify(hostKey: Data, signature: Data, over message: Data) -> Bool {
        var keyReader = SSHWireReader(hostKey)
        guard let keyType = try? keyReader.readUTF8String() else { return false }
        var sigReader = SSHWireReader(signature)
        guard let sigType = try? sigReader.readUTF8String(),
              let sigData = try? sigReader.readString() else { return false }

        switch keyType {
        case "ssh-ed25519":
            guard sigType == "ssh-ed25519",
                  let pub = try? keyReader.readString(),
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: pub) else {
                return false
            }
            return key.isValidSignature(sigData, for: message)

        case "ecdsa-sha2-nistp256":
            return verifyECDSA(.p256, keyReader: &keyReader, sigData: sigData, message: message)
        case "ecdsa-sha2-nistp384":
            return verifyECDSA(.p384, keyReader: &keyReader, sigData: sigData, message: message)
        case "ecdsa-sha2-nistp521":
            return verifyECDSA(.p521, keyReader: &keyReader, sigData: sigData, message: message)

        case "ssh-rsa":
            // An RSA host key's blob type is always "ssh-rsa"; the hash
            // (SHA-1/256/512) is chosen from the signature type below.
            return verifyRSA(sigType: sigType, keyReader: &keyReader, sigData: sigData, message: message)

        default:
            return false
        }
    }

    private enum Curve { case p256, p384, p521 }

    private static func verifyECDSA(_ curve: Curve, keyReader: inout SSHWireReader,
                                    sigData: Data, message: Data) -> Bool {
        guard let _ = try? keyReader.readString(),   // curve identifier
              let q = try? keyReader.readString() else { return false }
        var sr = SSHWireReader(sigData)
        guard let rRaw = try? sr.readString(), let sRaw = try? sr.readString() else { return false }

        switch curve {
        case .p256:
            guard let r = fixedWidth(rRaw, 32), let s = fixedWidth(sRaw, 32),
                  let key = try? P256.Signing.PublicKey(x963Representation: q),
                  let sig = try? P256.Signing.ECDSASignature(rawRepresentation: r + s) else { return false }
            return key.isValidSignature(sig, for: message)
        case .p384:
            guard let r = fixedWidth(rRaw, 48), let s = fixedWidth(sRaw, 48),
                  let key = try? P384.Signing.PublicKey(x963Representation: q),
                  let sig = try? P384.Signing.ECDSASignature(rawRepresentation: r + s) else { return false }
            return key.isValidSignature(sig, for: message)
        case .p521:
            guard let r = fixedWidth(rRaw, 66), let s = fixedWidth(sRaw, 66),
                  let key = try? P521.Signing.PublicKey(x963Representation: q),
                  let sig = try? P521.Signing.ECDSASignature(rawRepresentation: r + s) else { return false }
            return key.isValidSignature(sig, for: message)
        }
    }

    private static func verifyRSA(sigType: String, keyReader: inout SSHWireReader,
                                  sigData: Data, message: Data) -> Bool {
        guard let e = try? keyReader.readString(), let n = try? keyReader.readString() else { return false }
        var der = Data([0x30])
        let body = derInteger(n) + derInteger(e)
        der.append(derLength(body.count))
        der.append(body)

        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, &error) else {
            return false
        }
        let algorithm: SecKeyAlgorithm = switch sigType {
        case "rsa-sha2-256": .rsaSignatureMessagePKCS1v15SHA256
        case "rsa-sha2-512": .rsaSignatureMessagePKCS1v15SHA512
        default: .rsaSignatureMessagePKCS1v15SHA1
        }
        return SecKeyVerifySignature(key, algorithm, message as CFData, sigData as CFData, &error)
    }

    /// Turns an SSH mpint into a fixed-width big-endian integer: strips the
    /// sign-byte padding, then left-pads to the curve's coordinate size.
    private static func fixedWidth(_ mpint: Data, _ size: Int) -> Data? {
        var bytes = mpint
        while bytes.first == 0x00 && bytes.count > size {
            bytes.removeFirst()
        }
        guard bytes.count <= size else { return nil }
        return Data(repeating: 0, count: size - bytes.count) + bytes
    }

    private static func derInteger(_ value: Data) -> Data {
        var out = Data([0x02])
        out.append(derLength(value.count))
        out.append(value)
        return out
    }

    private static func derLength(_ length: Int) -> Data {
        if length < 0x80 {
            return Data([UInt8(length)])
        }
        var bytes: [UInt8] = []
        var remaining = length
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xff), at: 0)
            remaining >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
}
