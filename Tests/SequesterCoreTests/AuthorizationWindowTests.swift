import Testing
import Foundation
import LocalAuthentication
@testable import SequesterCore

/// The scope decides where a remembered tap may apply at all, so these pin
/// the two refusals that keep a window from covering a request the user
/// never authorized.
@Suite struct AuthorizationScopeTests {

    private func hop(_ fingerprint: String, forwarding: Bool = false) -> BindingHop {
        BindingHop(fingerprint: fingerprint, algorithm: "ssh-ed25519", forwarding: forwarding)
    }

    @Test func localChainGetsAScope() {
        #expect(AuthorizationScope.key("work", bindingChain: [hop("SHA256:gh")]) != nil)
    }

    @Test func chainsAreScopedSeparately() {
        let direct = AuthorizationScope.key("work", bindingChain: [hop("SHA256:gh")])
        let viaHost = AuthorizationScope.key("work", bindingChain: [hop("SHA256:vm"), hop("SHA256:gh")])
        #expect(direct != viaHost)
    }

    @Test func keysAreScopedSeparately() {
        #expect(AuthorizationScope.key("work", bindingChain: [hop("SHA256:gh")])
                != AuthorizationScope.key("personal", bindingChain: [hop("SHA256:gh")]))
    }

    @Test func forwardedChainsNeverGetAScope() {
        // A request arriving through a forwarding hop comes from a remote
        // host, where the Touch ID prompt is the last human gate.
        #expect(AuthorizationScope.key("work", bindingChain: [hop("SHA256:vm", forwarding: true),
                                                             hop("SHA256:gh")]) == nil)
        #expect(AuthorizationScope.key("work", bindingChain: [hop("SHA256:gh", forwarding: true)]) == nil)
    }

    @Test func unboundRequestsNeverGetAScope() {
        #expect(AuthorizationScope.key("work", bindingChain: []) == nil)
    }

    @Test func prefixesCoverTheirOwnCredential() {
        let scope = AuthorizationScope.key("work", bindingChain: [hop("SHA256:gh")])
        #expect(scope?.hasPrefix(AuthorizationScope.keyPrefix("work")) == true)
        #expect(scope?.hasPrefix(AuthorizationScope.keyPrefix("personal")) == false)
        #expect(AuthorizationScope.profile("deploy").hasPrefix(AuthorizationScope.profilePrefix("deploy")))
    }
}

@Suite struct AuthorizationWindowsTests {

    /// Drives the store from a fake monotonic clock, in nanoseconds.
    private func windows(_ clock: @escaping @Sendable () -> UInt64) -> AuthorizationWindows {
        AuthorizationWindows(now: clock)
    }

    private final class Clock: @unchecked Sendable {
        var nanos: UInt64 = 1_000_000_000
        func advance(seconds: Double) { nanos += UInt64(seconds * 1_000_000_000) }
    }

    @Test func rememberedContextComesBack() {
        let clock = Clock()
        let store = windows { clock.nanos }
        let context = LAContext()
        store.remember(scope: "a", context: context, seconds: 60)
        #expect(store.existing(scope: "a") === context)
    }

    @Test func zeroSecondsRemembersNothing() {
        let clock = Clock()
        let store = windows { clock.nanos }
        store.remember(scope: "a", context: LAContext(), seconds: 0)
        #expect(store.existing(scope: "a") == nil)
    }

    @Test func windowExpires() {
        let clock = Clock()
        let store = windows { clock.nanos }
        store.remember(scope: "a", context: LAContext(), seconds: 60)
        clock.advance(seconds: 59)
        #expect(store.existing(scope: "a") != nil)
        clock.advance(seconds: 2)
        #expect(store.existing(scope: "a") == nil)
    }

    @Test func scopesDoNotBleed() {
        let clock = Clock()
        let store = windows { clock.nanos }
        store.remember(scope: "key:work:gh", context: LAContext(), seconds: 60)
        #expect(store.existing(scope: "key:work:vm|gh") == nil)
        #expect(store.existing(scope: "key:personal:gh") == nil)
    }

    @Test func invalidateByPrefixLeavesOthers() {
        let clock = Clock()
        let store = windows { clock.nanos }
        store.remember(scope: "key:work:gh", context: LAContext(), seconds: 60)
        store.remember(scope: "key:personal:gh", context: LAContext(), seconds: 60)
        store.invalidate(prefix: "key:work:")
        #expect(store.existing(scope: "key:work:gh") == nil)
        #expect(store.existing(scope: "key:personal:gh") != nil)
    }

    @Test func invalidateAllClearsEverything() {
        let clock = Clock()
        let store = windows { clock.nanos }
        store.remember(scope: "a", context: LAContext(), seconds: 60)
        store.remember(scope: "b", context: LAContext(), seconds: 60)
        store.invalidateAll()
        #expect(store.existing(scope: "a") == nil)
        #expect(store.existing(scope: "b") == nil)
    }
}
