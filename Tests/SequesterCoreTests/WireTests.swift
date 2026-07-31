import Testing
import Foundation
import CryptoKit
@testable import SequesterCore

@Suite struct SSHWireTests {

    @Test func uint32BigEndian() {
        #expect(SSHWire.uint32(1) == Data([0, 0, 0, 1]))
        #expect(SSHWire.uint32(0x01020304) == Data([1, 2, 3, 4]))
    }

    @Test func lengthPrefixedString() {
        #expect(SSHWire.lengthPrefixed("abc") == Data([0, 0, 0, 3, 0x61, 0x62, 0x63]))
        #expect(SSHWire.lengthPrefixed(Data()) == Data([0, 0, 0, 0]))
    }

    @Test func mpintStripsLeadingZeros() {
        #expect(SSHWire.mpint(fixedWidthPositive: Data([0, 0, 0x01, 0x02])) == Data([0x01, 0x02]))
    }

    @Test func mpintPrefixesHighBit() {
        #expect(SSHWire.mpint(fixedWidthPositive: Data([0x80, 0x01])) == Data([0x00, 0x80, 0x01]))
    }

    @Test func mpintZero() {
        #expect(SSHWire.mpint(fixedWidthPositive: Data([0, 0, 0])) == Data())
    }

    @Test func readerRoundTrip() throws {
        var payload = Data([13])
        payload.append(SSHWire.lengthPrefixed("hello"))
        payload.append(SSHWire.uint32(42))
        var reader = SSHWireReader(payload)
        #expect(try reader.readByte() == 13)
        #expect(try reader.readUTF8String() == "hello")
        #expect(try reader.readUInt32() == 42)
        #expect(reader.isAtEnd)
    }

    @Test func readerRejectsTruncation() {
        var reader = SSHWireReader(Data([0, 0, 0, 9, 1]))
        #expect(throws: SSHWireReader.ReaderError.self) {
            try reader.readString()
        }
    }
}

@Suite struct OpenSSHTests {

    @Test func publicKeyBlobStructure() throws {
        let key = P256.Signing.PrivateKey()
        let blob = OpenSSH.p256PublicKeyBlob(x963: key.publicKey.x963Representation)
        var reader = SSHWireReader(blob)
        #expect(try reader.readUTF8String() == "ecdsa-sha2-nistp256")
        #expect(try reader.readUTF8String() == "nistp256")
        let point = try reader.readString()
        #expect(point.count == 65)
        #expect(point.first == 0x04)
        #expect(reader.isAtEnd)
    }

    /// The blob our writer produces must be exactly what ssh-keygen would
    /// emit for the same point, so fingerprints match everywhere.
    @Test func publicKeyLineRoundTrip() throws {
        let key = P256.Signing.PrivateKey()
        let line = OpenSSH.publicKeyLine(x963: key.publicKey.x963Representation, comment: "test")
        let parts = line.split(separator: " ")
        #expect(parts.count == 3)
        let blob = try #require(Data(base64Encoded: String(parts[1])))
        #expect(blob == OpenSSH.p256PublicKeyBlob(x963: key.publicKey.x963Representation))
        #expect(parts[2] == "test")
    }

    @Test func signatureBlobParsesAsMpints() throws {
        let key = P256.Signing.PrivateKey()
        let signature = try key.signature(for: Data("payload".utf8))
        let blob = OpenSSH.p256SignatureBlob(rawSignature: signature.rawRepresentation)
        var reader = SSHWireReader(blob)
        #expect(try reader.readUTF8String() == "ecdsa-sha2-nistp256")
        var inner = SSHWireReader(try reader.readString())
        let r = try inner.readString()
        let s = try inner.readString()
        #expect(reader.isAtEnd)
        #expect(inner.isAtEnd)
        // mpints are positive: high bit clear, no redundant leading zero.
        for half in [r, s] {
            #expect(!half.isEmpty)
            #expect(half.first! < 0x80 || half.count > 1)
            if half.first == 0x00 {
                #expect(half[half.index(after: half.startIndex)] >= 0x80)
            }
        }
    }

    @Test func fingerprintFormat() {
        let fingerprint = OpenSSH.fingerprintSHA256(blob: Data("blob".utf8))
        #expect(fingerprint.hasPrefix("SHA256:"))
        #expect(!fingerprint.hasSuffix("="))
    }

    @Test func fingerprintMD5Format() {
        let fingerprint = OpenSSH.fingerprintMD5(blob: Data("blob".utf8))
        #expect(fingerprint.hasPrefix("MD5:"))
        let hex = fingerprint.dropFirst(4).split(separator: ":")
        #expect(hex.count == 16)
        #expect(hex.allSatisfy { $0.count == 2 })
    }
}

@Suite struct AgentProtocolTests {

    private struct DenyAll: SigningApprover {
        func approve(keyName: String, provenance: Provenance, bindings: [SessionBinding]) async -> Bool {
            false
        }
    }

    private func makeSession() -> AgentSession {
        AgentSession(provenance: Provenance(pid: 1, path: "/usr/bin/ssh"))
    }

    @Test func unknownMessageFails() async {
        let agent = Agent(approver: DenyAll())
        let response = await agent.handle(message: Data([99]), session: makeSession())
        #expect(response == Data([5]))
    }

    @Test func sessionBindRecordsAndSucceeds() async throws {
        let agent = Agent(approver: DenyAll())
        let session = makeSession()

        var payload = Data([27])
        payload.append(SSHWire.lengthPrefixed("session-bind@openssh.com"))
        payload.append(SSHWire.lengthPrefixed(SSHWire.lengthPrefixed("ssh-ed25519")))
        payload.append(SSHWire.lengthPrefixed(Data("sessionid".utf8)))
        payload.append(SSHWire.lengthPrefixed(Data("signature".utf8)))
        payload.append(Data([1]))

        let response = await agent.handle(message: payload, session: session)
        #expect(response == Data([6]))
        #expect(session.bindings.count == 1)
        #expect(session.bindings[0].isForwarding)
        #expect(session.bindings[0].hostKeyAlgorithm == "ssh-ed25519")
        #expect(session.isForwarded)
    }

    @Test func unsupportedExtensionFails() async {
        let agent = Agent(approver: DenyAll())
        var payload = Data([27])
        payload.append(SSHWire.lengthPrefixed("some-other@example.com"))
        let response = await agent.handle(message: payload, session: makeSession())
        #expect(response == Data([5]))
    }
}
