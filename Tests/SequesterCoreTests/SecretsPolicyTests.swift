import Testing
import SecretsWire
@testable import SequesterCore

@Suite struct SecretsPolicyTests {

    private func outcome(tier: SecretTier = .everyRead, standing: AppStanding,
                         operation: SecretsPolicy.Operation = .get,
                         approveAll: Bool = false) -> SecretsPolicy.Outcome {
        SecretsPolicy.outcome(tier: tier, standing: standing, operation: operation, approveAll: approveAll)
    }

    @Test func blockedDeniesEveryOperation() {
        for tier in SecretTier.allCases {
            for operation in [SecretsPolicy.Operation.get, .set, .rm] {
                #expect(outcome(tier: tier, standing: .blocked, operation: operation) == .deny(.appBlocked))
            }
        }
    }

    @Test func blockedDeniesDespiteApproveAll() {
        for tier in SecretTier.allCases {
            #expect(outcome(tier: tier, standing: .blocked, approveAll: true) == .deny(.appBlocked))
        }
    }

    @Test func allowedReadsSilently() {
        for tier in SecretTier.allCases {
            #expect(outcome(tier: tier, standing: .allowed) == .silentAllow)
        }
    }

    @Test func approveAllReadsSilentlyForUnknown() {
        for tier in SecretTier.allCases {
            #expect(outcome(tier: tier, standing: .unknown, approveAll: true) == .silentAllow)
        }
    }

    @Test func unknownReaderAsksPerTier() {
        #expect(outcome(tier: .everyRead, standing: .unknown) == .dialogAsk)
        #expect(outcome(tier: .policyOnly, standing: .unknown) == .dialogAsk)
        #expect(outcome(tier: .unapprovedOnly, standing: .unknown) == .biometricGate)
    }

    @Test func managementAlwaysAsks() {
        for tier in SecretTier.allCases {
            for standing in [AppStanding.allowed, .unknown] {
                #expect(outcome(tier: tier, standing: standing, operation: .set, approveAll: true) == .dialogAsk)
                #expect(outcome(tier: tier, standing: standing, operation: .rm, approveAll: true) == .dialogAsk)
            }
        }
    }
}
