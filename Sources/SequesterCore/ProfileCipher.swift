import Foundation
import CryptoKit
import SecretsWire

public enum ProfileCipherError: LocalizedError {
    case malformedBlob

    public var errorDescription: String? {
        "The profile's encrypted data could not be parsed."
    }
}

/// A key that can stand as the recipient of a sealed profile blob: the
/// Enclave key in the app, a software P-256 key in tests.
public protocol ECIESRecipientKey {
    var publicKey: P256.KeyAgreement.PublicKey { get }
    func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws -> SharedSecret
}

extension P256.KeyAgreement.PrivateKey: ECIESRecipientKey {}
extension SecureEnclave.P256.KeyAgreement.PrivateKey: ECIESRecipientKey {}

/// Encrypts a profile's values as one blob: ephemeral ECDH against the
/// recipient public key, HKDF-SHA256, ChaChaPoly. Sealing needs only the
/// public key, so creating or replacing values never touches the Enclave;
/// opening runs the ECDH inside it, which is where a userPresence key
/// demands Touch ID.
public enum ProfileCipher {

    /// Uncompressed x9.63 P-256 point length; the blob's fixed prefix.
    static let ephemeralKeyLength = 65

    private static let salt = Data("cz.szypowi.sequester.profile.v1".utf8)

    private static func symmetricKey(secret: SharedSecret,
                                     recipient: P256.KeyAgreement.PublicKey,
                                     ephemeral: P256.KeyAgreement.PublicKey) -> SymmetricKey {
        secret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: recipient.x963Representation + ephemeral.x963Representation,
            outputByteCount: 32
        )
    }

    /// Blob layout: ephemeral public key (x9.63, 65 bytes) followed by the
    /// ChaChaPoly combined box (nonce, ciphertext, tag).
    public static func seal(_ plaintext: Data, to recipient: P256.KeyAgreement.PublicKey) throws -> Data {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let secret = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let key = symmetricKey(secret: secret, recipient: recipient, ephemeral: ephemeral.publicKey)
        let sealed = try ChaChaPoly.seal(plaintext, using: key)
        return ephemeral.publicKey.x963Representation + sealed.combined
    }

    public static func open(_ blob: Data, with recipientKey: some ECIESRecipientKey) throws -> Data {
        guard blob.count > ephemeralKeyLength else { throw ProfileCipherError.malformedBlob }
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: blob.prefix(ephemeralKeyLength))
        let secret = try recipientKey.sharedSecretFromKeyAgreement(with: ephemeral)
        let key = symmetricKey(secret: secret, recipient: recipientKey.publicKey, ephemeral: ephemeral)
        return try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: blob.dropFirst(ephemeralKeyLength)), using: key)
    }

    public static func encodeValues(_ values: [String: String]) throws -> Data {
        try SecretsCodec.encode(values)
    }

    public static func decodeValues(_ data: Data) throws -> [String: String] {
        try SecretsCodec.decode([String: String].self, from: data)
    }
}
