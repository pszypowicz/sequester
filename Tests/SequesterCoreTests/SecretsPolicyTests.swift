import Testing
import Foundation
import SecretsWire
@testable import SequesterCore

@Suite struct SecretsPolicyTests {

    @Test func readsFollowTheTier() {
        #expect(SecretsPolicy.outcome(tier: .everyRead, operation: .get, graceActive: false) == .proceed)
        #expect(SecretsPolicy.outcome(tier: .noPrompt, operation: .get, graceActive: false) == .proceed)
        #expect(SecretsPolicy.outcome(tier: .confirmEveryRead, operation: .get, graceActive: false) == .dialogAsk)
    }

    @Test func graceOnlyWaivesTheConfirmTier() {
        #expect(SecretsPolicy.outcome(tier: .confirmEveryRead, operation: .get, graceActive: true) == .proceed)
        // The Enclave prompt is in the key's access control, so a grace
        // window cannot skip it either way.
        #expect(SecretsPolicy.outcome(tier: .everyRead, operation: .get, graceActive: true) == .proceed)
    }

    @Test func managementAlwaysConfirms() {
        for tier in SecretTier.allCases {
            for operation in [SecretsPolicy.Operation.set, .rm] {
                #expect(SecretsPolicy.outcome(tier: tier, operation: operation, graceActive: false) == .dialogAsk)
                #expect(SecretsPolicy.outcome(tier: tier, operation: operation, graceActive: true) == .dialogAsk)
            }
        }
    }
}

@Suite struct SecretsGraceWindowsTests {

    private let epoch = Date(timeIntervalSince1970: 1_000_000)

    @Test func grantIsScopedToOneProfile() {
        let windows = SecretsGraceWindows()
        windows.grant(profile: "a", now: epoch)
        #expect(windows.isActive(profile: "a", now: epoch))
        #expect(!windows.isActive(profile: "b", now: epoch))
    }

    @Test func windowExpires() {
        let windows = SecretsGraceWindows()
        windows.grant(profile: "a", now: epoch)
        #expect(windows.isActive(profile: "a", now: epoch.addingTimeInterval(SecretsGraceWindows.duration - 1)))
        #expect(!windows.isActive(profile: "a", now: epoch.addingTimeInterval(SecretsGraceWindows.duration)))
    }

    @Test func revokeClosesTheWindow() {
        let windows = SecretsGraceWindows()
        windows.grant(profile: "a", now: epoch)
        windows.revoke(profile: "a")
        #expect(!windows.isActive(profile: "a", now: epoch))
    }

    @Test func noWindowWithoutAGrant() {
        #expect(!SecretsGraceWindows().isActive(profile: "a", now: epoch))
    }
}
