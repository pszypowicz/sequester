import Testing
import Foundation
@testable import SequesterCore

@Suite struct AppPolicyTests {

    private let id = "apple:com.apple.ssh"
    private let instance = "100.5"

    private func standing(
        identityKey: String?,
        perKeyRules: [AppRule] = [],
        global: AppState? = nil,
        sessionAllowed: Bool = false,
        sessionBlocked: Bool = false
    ) -> AppStanding {
        AppPolicy.standing(
            identityKey: identityKey,
            instance: instance,
            perKeyRules: perKeyRules,
            globalLookup: { _ in global },
            sessionAllowed: { _, _ in sessionAllowed },
            sessionBlocked: { _ in sessionBlocked }
        )
    }

    @Test func unknownWhenNothingKnown() {
        #expect(standing(identityKey: id) == .unknown)
    }

    @Test func globalAllowAndBlock() {
        #expect(standing(identityKey: id, global: .allowed) == .allowed)
        #expect(standing(identityKey: id, global: .blocked) == .blocked)
    }

    @Test func perKeyOverridesGlobal() {
        let block = [AppRule(identity: id, displayName: "ssh", state: .blocked)]
        #expect(standing(identityKey: id, perKeyRules: block, global: .allowed) == .blocked)
        let allow = [AppRule(identity: id, displayName: "ssh", state: .allowed)]
        #expect(standing(identityKey: id, perKeyRules: allow, global: .blocked) == .allowed)
    }

    @Test func sessionAllowGrantsWhenNoPersisted() {
        #expect(standing(identityKey: id, sessionAllowed: true) == .allowed)
    }

    @Test func unverifiedIsUnknownUnlessSessionBlocked() {
        #expect(standing(identityKey: nil) == .unknown)
        #expect(standing(identityKey: nil, sessionBlocked: true) == .blocked)
    }

    @Test func unverifiedIgnoresGlobalAndSessionAllow() {
        // No identity means no stable key, so a global entry or a session
        // allow can never apply - only a session block can.
        #expect(standing(identityKey: nil, global: .allowed, sessionAllowed: true) == .unknown)
    }
}

@Suite struct PolicyEngineAppTests {

    private let local = BindingHop(fingerprint: "SHA256:gh", algorithm: "ssh-ed25519", forwarding: false)

    private func key(approved: Bool = false, autoApprove: Bool = false, blocked: Bool = false) -> KeyMetadata {
        var destinations: [DestinationRecord] = []
        if approved || blocked {
            destinations = [DestinationRecord(hops: [local], state: blocked ? .blocked : .approved,
                                              firstSeen: Date(timeIntervalSince1970: 0),
                                              lastUsed: Date(timeIntervalSince1970: 0), count: 1)]
        }
        return KeyMetadata(name: "k", keyDescription: "", authRequired: false,
                           autoApprove: autoApprove, destinations: destinations,
                           publicKey: Data(count: 65), createdAt: Date(timeIntervalSince1970: 0))
    }

    @Test func blockedAppDeniesEvenApprovedDestination() {
        #expect(PolicyEngine.evaluate(key: key(approved: true), bindingChain: [local],
                                      appStanding: .blocked, trust: .applePlatform) == .deny)
    }

    @Test func unknownAppAsksEvenApprovedDestination() {
        #expect(PolicyEngine.evaluate(key: key(approved: true), bindingChain: [local],
                                      appStanding: .unknown, trust: .applePlatform) == .ask)
    }

    @Test func allowedAppWithApprovedDestinationSigns() {
        #expect(PolicyEngine.evaluate(key: key(approved: true), bindingChain: [local],
                                      appStanding: .allowed, trust: .applePlatform) == .allow)
    }

    @Test func destinationBlockBeatsAllowedApp() {
        #expect(PolicyEngine.evaluate(key: key(blocked: true), bindingChain: [local],
                                      appStanding: .allowed, trust: .applePlatform) == .deny)
    }

    @Test func unverifiedNeverSignsSilently() {
        // An allowed app on an auto-approved local destination would sign
        // silently, but an unverified requester is downgraded to asking.
        #expect(PolicyEngine.evaluate(key: key(autoApprove: true), bindingChain: [local],
                                      appStanding: .allowed, trust: .unverified) == .ask)
        #expect(PolicyEngine.evaluate(key: key(autoApprove: true), bindingChain: [local],
                                      appStanding: .allowed, trust: .applePlatform) == .allow)
    }

    @Test func lockedKeyDeniesNewDestinationRegardlessOfApp() {
        var locked = key()
        locked.locked = true
        // A locked key facing a chain it has no record of denies; authorizing
        // the app must not reopen it, so an unknown app is denied, not asked.
        #expect(PolicyEngine.evaluate(key: locked, bindingChain: [local],
                                      appStanding: .unknown, trust: .applePlatform) == .deny)
        #expect(PolicyEngine.evaluate(key: locked, bindingChain: [local],
                                      appStanding: .allowed, trust: .applePlatform) == .deny)
        // An already-approved destination on a locked key still verifies the app.
        var lockedApproved = key(approved: true)
        lockedApproved.locked = true
        #expect(PolicyEngine.evaluate(key: lockedApproved, bindingChain: [local],
                                      appStanding: .unknown, trust: .applePlatform) == .ask)
        #expect(PolicyEngine.evaluate(key: lockedApproved, bindingChain: [local],
                                      appStanding: .allowed, trust: .applePlatform) == .allow)
    }
}
