import Testing
import Foundation
import CryptoKit
@testable import SequesterCore

@Suite struct ProfileCipherTests {

    private let key = P256.KeyAgreement.PrivateKey()

    @Test func roundTrip() throws {
        let values = ["GITHUB_TOKEN": "ghp_example", "NPM_TOKEN": "npm_example"]
        let sealed = try ProfileCipher.seal(ProfileCipher.encodeValues(values), to: key.publicKey)
        let opened = try ProfileCipher.decodeValues(try ProfileCipher.open(sealed, with: key))
        #expect(opened == values)
    }

    @Test func blobStartsWithUncompressedEphemeralPoint() throws {
        let sealed = try ProfileCipher.seal(Data("x".utf8), to: key.publicKey)
        // 65-byte x9.63 point (0x04 prefix), then nonce+ciphertext+tag.
        #expect(sealed.first == 0x04)
        #expect(sealed.count == 65 + 12 + 1 + 16)
        _ = try P256.KeyAgreement.PublicKey(x963Representation: sealed.prefix(65))
    }

    @Test func emptyPlaintextRoundTrips() throws {
        let sealed = try ProfileCipher.seal(Data(), to: key.publicKey)
        #expect(try ProfileCipher.open(sealed, with: key).isEmpty)
    }

    @Test func largePlaintextRoundTrips() throws {
        let plaintext = Data(repeating: 0x41, count: 128 * 1024)
        let sealed = try ProfileCipher.seal(plaintext, to: key.publicKey)
        #expect(try ProfileCipher.open(sealed, with: key) == plaintext)
    }

    @Test func tamperedCiphertextIsRejected() throws {
        var sealed = try ProfileCipher.seal(Data("secret".utf8), to: key.publicKey)
        sealed[70] ^= 0x01
        #expect(throws: (any Error).self) {
            try ProfileCipher.open(sealed, with: key)
        }
    }

    @Test func tamperedEphemeralPointIsRejected() throws {
        var sealed = try ProfileCipher.seal(Data("secret".utf8), to: key.publicKey)
        sealed[10] ^= 0x01
        #expect(throws: (any Error).self) {
            try ProfileCipher.open(sealed, with: key)
        }
    }

    @Test func truncatedBlobIsRejected() throws {
        let sealed = try ProfileCipher.seal(Data("secret".utf8), to: key.publicKey)
        #expect(throws: ProfileCipherError.self) {
            try ProfileCipher.open(sealed.prefix(40), with: key)
        }
    }

    @Test func wrongKeyIsRejected() throws {
        let sealed = try ProfileCipher.seal(Data("secret".utf8), to: key.publicKey)
        #expect(throws: (any Error).self) {
            try ProfileCipher.open(sealed, with: P256.KeyAgreement.PrivateKey())
        }
    }
}
