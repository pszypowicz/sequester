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

    @Test func keyPublicKeyLineCommentIsScopedToSequester() {
        let key = P256.Signing.PrivateKey()
        let metadata = KeyMetadata(name: "work", keyDescription: "", authRequired: false,
                                   publicKey: key.publicKey.x963Representation,
                                   createdAt: Date(timeIntervalSince1970: 0))
        let parts = metadata.publicKeyLine.split(separator: " ")
        #expect(parts.count == 3)
        #expect(parts[2] == "work@sequester")
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
        func approve(_ request: ApprovalRequest) async -> ApprovalDecision {
            .deny
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

    private func sessionBindMessage(hostKey: Curve25519.Signing.PrivateKey, sessionID: Data,
                                    signature: Data, forwarding: Bool) -> Data {
        var hostKeyBlob = SSHWire.lengthPrefixed("ssh-ed25519")
        hostKeyBlob.append(SSHWire.lengthPrefixed(hostKey.publicKey.rawRepresentation))
        var sigBlob = SSHWire.lengthPrefixed("ssh-ed25519")
        sigBlob.append(SSHWire.lengthPrefixed(signature))
        var payload = Data([27])
        payload.append(SSHWire.lengthPrefixed("session-bind@openssh.com"))
        payload.append(SSHWire.lengthPrefixed(hostKeyBlob))
        payload.append(SSHWire.lengthPrefixed(sessionID))
        payload.append(SSHWire.lengthPrefixed(sigBlob))
        payload.append(Data([forwarding ? 1 : 0]))
        return payload
    }

    @Test func validSessionBindRecordsAndSucceeds() async throws {
        let agent = Agent(approver: DenyAll())
        let session = makeSession()
        let hostKey = Curve25519.Signing.PrivateKey()
        let sessionID = Data((0..<32).map { UInt8($0) })
        let signature = try hostKey.signature(for: sessionID)

        let response = await agent.handle(
            message: sessionBindMessage(hostKey: hostKey, sessionID: sessionID, signature: signature, forwarding: true),
            session: session
        )
        #expect(response == Data([6]))
        #expect(session.bindings.count == 1)
        #expect(session.bindings[0].isForwarding)
        #expect(session.bindings[0].hostKeyAlgorithm == "ssh-ed25519")
        #expect(session.bindings[0].sessionID == sessionID)
    }

    @Test func forgedSessionBindRejected() async throws {
        let agent = Agent(approver: DenyAll())
        let session = makeSession()
        let hostKey = Curve25519.Signing.PrivateKey()
        let sessionID = Data((0..<32).map { _ in UInt8(7) })
        // A signature over different data (or here, junk) must not verify.
        let response = await agent.handle(
            message: sessionBindMessage(hostKey: hostKey, sessionID: sessionID, signature: Data(count: 64), forwarding: false),
            session: session
        )
        #expect(response == Data([5]))
        #expect(session.bindings.isEmpty)
    }

    @Test func unsupportedExtensionFails() async {
        let agent = Agent(approver: DenyAll())
        var payload = Data([27])
        payload.append(SSHWire.lengthPrefixed("some-other@example.com"))
        let response = await agent.handle(message: payload, session: makeSession())
        #expect(response == Data([5]))
    }
}

@Suite struct PolicyEngineTests {

    private func makeKey(authRequired: Bool = false, blockForwarded: Bool = false,
                         destinations: [DestinationRecord] = []) -> KeyMetadata {
        KeyMetadata(
            name: "test", keyDescription: "", authRequired: authRequired,
            blockForwarded: blockForwarded, destinations: destinations,
            publicKey: Data(count: 65), createdAt: Date(timeIntervalSince1970: 0)
        )
    }

    private let local = BindingHop(fingerprint: "SHA256:aaa", algorithm: "ssh-ed25519", forwarding: false)
    private let hop = BindingHop(fingerprint: "SHA256:vm1", algorithm: "ssh-ed25519", forwarding: true)

    private func record(_ hops: [BindingHop], _ state: DestinationState) -> DestinationRecord {
        DestinationRecord(
            hops: hops, state: state,
            firstSeen: Date(timeIntervalSince1970: 0), lastUsed: Date(timeIntervalSince1970: 0), count: 1
        )
    }

    @Test func unknownChainAsks() {
        #expect(PolicyEngine.evaluate(key: makeKey(), bindingChain: [local], appStanding: .allowed, trust: .applePlatform) == .ask)
    }

    @Test func emptyChainAsks() {
        #expect(PolicyEngine.evaluate(key: makeKey(), bindingChain: [], appStanding: .allowed, trust: .applePlatform) == .ask)
    }

    @Test func blockForwardedDeniesForwardedOnly() {
        let key = makeKey(blockForwarded: true)
        #expect(PolicyEngine.evaluate(key: key, bindingChain: [hop, local], appStanding: .allowed, trust: .applePlatform) == .deny)
        #expect(PolicyEngine.evaluate(key: key, bindingChain: [local], appStanding: .allowed, trust: .applePlatform) == .ask)
    }

    @Test func blockForwardedBeatsApprovedRecord() {
        let bindingChain = [hop, local]
        let key = makeKey(blockForwarded: true, destinations: [record(bindingChain, .approved)])
        #expect(PolicyEngine.evaluate(key: key, bindingChain: bindingChain, appStanding: .allowed, trust: .applePlatform) == .deny)
    }

    @Test func recordStatesApply() {
        #expect(PolicyEngine.evaluate(key: makeKey(destinations: [record([local], .approved)]), bindingChain: [local], appStanding: .allowed, trust: .applePlatform) == .allow)
        #expect(PolicyEngine.evaluate(key: makeKey(destinations: [record([local], .blocked)]), bindingChain: [local], appStanding: .allowed, trust: .applePlatform) == .deny)
        #expect(PolicyEngine.evaluate(key: makeKey(destinations: [record([local], .neutral)]), bindingChain: [local], appStanding: .allowed, trust: .applePlatform) == .ask)
    }

    @Test func chainIdentityIncludesRoute() {
        let viaVM1 = [hop, local]
        let key = makeKey(destinations: [record(viaVM1, .approved)])
        let viaVM2 = [BindingHop(fingerprint: "SHA256:vm2", algorithm: "ssh-ed25519", forwarding: true), local]
        #expect(PolicyEngine.evaluate(key: key, bindingChain: viaVM1, appStanding: .allowed, trust: .applePlatform) == .allow)
        #expect(PolicyEngine.evaluate(key: key, bindingChain: viaVM2, appStanding: .allowed, trust: .applePlatform) == .ask)
        #expect(PolicyEngine.evaluate(key: key, bindingChain: [local], appStanding: .allowed, trust: .applePlatform) == .ask)
    }
}

@Suite struct BranchRuleTests {

    private let vm1 = BindingHop(fingerprint: "SHA256:vm1", algorithm: "ssh-ed25519", forwarding: true)
    private let vm2 = BindingHop(fingerprint: "SHA256:vm2", algorithm: "ssh-ed25519", forwarding: true)
    private let github = BindingHop(fingerprint: "SHA256:gh", algorithm: "ssh-ed25519", forwarding: false)

    private func makeKey(destinations: [DestinationRecord] = [], rules: [BranchRule] = [],
                         autoApprove: Bool = false, blockForwarded: Bool = false) -> KeyMetadata {
        KeyMetadata(
            name: "test", keyDescription: "", authRequired: false,
            blockForwarded: blockForwarded, autoApprove: autoApprove,
            destinations: destinations, branchRules: rules,
            publicKey: Data(count: 65), createdAt: Date(timeIntervalSince1970: 0)
        )
    }

    private func record(_ hops: [BindingHop], _ state: DestinationState) -> DestinationRecord {
        DestinationRecord(
            hops: hops, state: state,
            firstSeen: Date(timeIntervalSince1970: 0), lastUsed: Date(timeIntervalSince1970: 0), count: 1
        )
    }

    @Test func branchRuleCoversEveryPathThroughIt() {
        let key = makeKey(rules: [BranchRule(hops: [vm1], state: .blocked)])
        #expect(PolicyEngine.evaluate(key: key, bindingChain: [vm1, github], appStanding: .allowed, trust: .applePlatform) == .deny)
        #expect(PolicyEngine.evaluate(key: key, bindingChain: [vm1], appStanding: .allowed, trust: .applePlatform) == .deny)
        #expect(PolicyEngine.evaluate(key: key, bindingChain: [vm2, github], appStanding: .allowed, trust: .applePlatform) == .ask)
    }

    /// The user's case: block github through vm1, approve it through vm2.
    @Test func perHopGranularity() {
        let key = makeKey(rules: [
            BranchRule(hops: [vm1], state: .blocked),
            BranchRule(hops: [vm2], state: .approved),
        ])
        #expect(PolicyEngine.evaluate(key: key, bindingChain: [vm1, github], appStanding: .allowed, trust: .applePlatform) == .deny)
        #expect(PolicyEngine.evaluate(key: key, bindingChain: [vm2, github], appStanding: .allowed, trust: .applePlatform) == .allow)
    }

    @Test func blockAnywhereOnPathWins() {
        let blockedBranch = makeKey(
            destinations: [record([vm1, github], .approved)],
            rules: [BranchRule(hops: [vm1], state: .blocked)]
        )
        #expect(PolicyEngine.evaluate(key: blockedBranch, bindingChain: [vm1, github], appStanding: .allowed, trust: .applePlatform) == .deny)

        let blockedLeaf = makeKey(
            destinations: [record([vm1, github], .blocked)],
            rules: [BranchRule(hops: [vm1], state: .approved)]
        )
        #expect(PolicyEngine.evaluate(key: blockedLeaf, bindingChain: [vm1, github], appStanding: .allowed, trust: .applePlatform) == .deny)
    }

    @Test func exactRecordBeatsApprovedBranchOnlyWhenBlocking() {
        let key = makeKey(
            destinations: [record([vm2, github], .neutral)],
            rules: [BranchRule(hops: [vm2], state: .approved)]
        )
        #expect(PolicyEngine.evaluate(key: key, bindingChain: [vm2, github], appStanding: .allowed, trust: .applePlatform) == .allow)
    }

    @Test func approveAllSignsUnblockedIncludingForwarded() {
        var key = makeKey()
        key.approveAll = true
        #expect(PolicyEngine.evaluate(key: key, bindingChain: [github], appStanding: .allowed, trust: .applePlatform) == .allow)
        #expect(PolicyEngine.evaluate(key: key, bindingChain: [vm1, github], appStanding: .allowed, trust: .applePlatform) == .allow)
        // Blocks still win over approve-all.
        var blockedFwd = key
        blockedFwd.blockForwarded = true
        #expect(PolicyEngine.evaluate(key: blockedFwd, bindingChain: [vm1, github], appStanding: .allowed, trust: .applePlatform) == .deny)
        var blockedDest = makeKey(destinations: [record([github], .blocked)])
        blockedDest.approveAll = true
        #expect(PolicyEngine.evaluate(key: blockedDest, bindingChain: [github], appStanding: .allowed, trust: .applePlatform) == .deny)
        // Approve-all overrides lock.
        var lockedToo = key
        lockedToo.locked = true
        #expect(PolicyEngine.evaluate(key: lockedToo, bindingChain: [github], appStanding: .allowed, trust: .applePlatform) == .allow)
    }

    @Test func lockedDeniesUnapprovedButKeepsStandings() {
        let approved = makeKey(destinations: [record([github], .approved)])
        var lockedApproved = approved
        lockedApproved.locked = true
        // Approved paths still sign, unknown paths deny instead of ask.
        #expect(PolicyEngine.evaluate(key: lockedApproved, bindingChain: [github], appStanding: .allowed, trust: .applePlatform) == .allow)
        #expect(PolicyEngine.evaluate(key: lockedApproved, bindingChain: [vm1, github], appStanding: .allowed, trust: .applePlatform) == .deny)

        // Locking overrides auto-approve too: nothing new, even local.
        var lockedAuto = makeKey(autoApprove: true)
        lockedAuto.locked = true
        #expect(PolicyEngine.evaluate(key: lockedAuto, bindingChain: [github], appStanding: .allowed, trust: .applePlatform) == .deny)

        // A blocked path stays blocked (deny), unaffected by lock.
        var lockedBlocked = makeKey(destinations: [record([github], .blocked)])
        lockedBlocked.locked = true
        #expect(PolicyEngine.evaluate(key: lockedBlocked, bindingChain: [github], appStanding: .allowed, trust: .applePlatform) == .deny)
    }

    @Test func autoApproveIsLocalOnly() {
        let key = makeKey(autoApprove: true)
        // Local (no forwarding) signs silently.
        #expect(PolicyEngine.evaluate(key: key, bindingChain: [github], appStanding: .allowed, trust: .applePlatform) == .allow)
        // Forwarded still asks, and an unbound request still asks.
        #expect(PolicyEngine.evaluate(key: key, bindingChain: [vm1, github], appStanding: .allowed, trust: .applePlatform) == .ask)
        #expect(PolicyEngine.evaluate(key: key, bindingChain: [], appStanding: .allowed, trust: .applePlatform) == .ask)
    }

    @Test func autoApproveYieldsToBlocks() {
        let blockedLeaf = makeKey(destinations: [record([github], .blocked)], autoApprove: true)
        #expect(PolicyEngine.evaluate(key: blockedLeaf, bindingChain: [github], appStanding: .allowed, trust: .applePlatform) == .deny)

        let blockedBranch = makeKey(rules: [BranchRule(hops: [github], state: .blocked)], autoApprove: true)
        #expect(PolicyEngine.evaluate(key: blockedBranch, bindingChain: [github], appStanding: .allowed, trust: .applePlatform) == .deny)

        let noForwarding = makeKey(autoApprove: true, blockForwarded: true)
        #expect(PolicyEngine.evaluate(key: noForwarding, bindingChain: [vm1, github], appStanding: .allowed, trust: .applePlatform) == .deny)
        #expect(PolicyEngine.evaluate(key: noForwarding, bindingChain: [github], appStanding: .allowed, trust: .applePlatform) == .allow)
    }

    @Test func deepChainsAreDistinctPaths() {
        let hopA = BindingHop(fingerprint: "SHA256:a", algorithm: "ssh-ed25519", forwarding: true)
        let hopB = BindingHop(fingerprint: "SHA256:b", algorithm: "ssh-ed25519", forwarding: true)
        let hopC = BindingHop(fingerprint: "SHA256:c", algorithm: "ssh-ed25519", forwarding: true)
        let deep = [hopA, hopB, hopC, github]
        let key = makeKey(destinations: [record(deep, .approved)])
        #expect(PolicyEngine.evaluate(key: key, bindingChain: deep, appStanding: .allowed, trust: .applePlatform) == .allow)
        // Same destination, one hop shorter, is a different path.
        #expect(PolicyEngine.evaluate(key: key, bindingChain: [hopA, hopB, github], appStanding: .allowed, trust: .applePlatform) == .ask)
        // A block on the first hop covers the whole depth below it.
        let blocked = makeKey(destinations: [record(deep, .approved)], rules: [BranchRule(hops: [hopA], state: .blocked)])
        #expect(PolicyEngine.evaluate(key: blocked, bindingChain: deep, appStanding: .allowed, trust: .applePlatform) == .deny)
    }
}

@Suite struct HostKeyVerifierTests {

    @Test func ed25519RoundTrip() throws {
        let key = Curve25519.Signing.PrivateKey()
        let message = Data("session-identifier".utf8)
        let signature = try key.signature(for: message)
        var hostKey = SSHWire.lengthPrefixed("ssh-ed25519")
        hostKey.append(SSHWire.lengthPrefixed(key.publicKey.rawRepresentation))
        var sigBlob = SSHWire.lengthPrefixed("ssh-ed25519")
        sigBlob.append(SSHWire.lengthPrefixed(signature))

        #expect(HostKeyVerifier.verify(hostKey: hostKey, signature: sigBlob, over: message))
        #expect(!HostKeyVerifier.verify(hostKey: hostKey, signature: sigBlob, over: Data("other".utf8)))
    }

    @Test func ecdsaP256RoundTrip() throws {
        let key = P256.Signing.PrivateKey()
        let message = Data("session-identifier".utf8)
        let signature = try key.signature(for: message)
        var hostKey = SSHWire.lengthPrefixed("ecdsa-sha2-nistp256")
        hostKey.append(SSHWire.lengthPrefixed("nistp256"))
        hostKey.append(SSHWire.lengthPrefixed(key.publicKey.x963Representation))

        let raw = signature.rawRepresentation
        let r = SSHWire.mpint(fixedWidthPositive: Data(raw.prefix(32)))
        let s = SSHWire.mpint(fixedWidthPositive: Data(raw.suffix(32)))
        var inner = SSHWire.lengthPrefixed(r)
        inner.append(SSHWire.lengthPrefixed(s))
        var sigBlob = SSHWire.lengthPrefixed("ecdsa-sha2-nistp256")
        sigBlob.append(SSHWire.lengthPrefixed(inner))

        #expect(HostKeyVerifier.verify(hostKey: hostKey, signature: sigBlob, over: message))
        #expect(!HostKeyVerifier.verify(hostKey: hostKey, signature: sigBlob, over: Data("tampered".utf8)))
    }

    @Test func wrongKeyFails() throws {
        let signer = Curve25519.Signing.PrivateKey()
        let impostor = Curve25519.Signing.PrivateKey()
        let message = Data("session".utf8)
        let signature = try signer.signature(for: message)
        var hostKey = SSHWire.lengthPrefixed("ssh-ed25519")
        hostKey.append(SSHWire.lengthPrefixed(impostor.publicKey.rawRepresentation))
        var sigBlob = SSHWire.lengthPrefixed("ssh-ed25519")
        sigBlob.append(SSHWire.lengthPrefixed(signature))

        #expect(!HostKeyVerifier.verify(hostKey: hostKey, signature: sigBlob, over: message))
    }
}
