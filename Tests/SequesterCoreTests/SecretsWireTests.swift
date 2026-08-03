import Testing
import Foundation
import SecretsWire

@Suite struct SecretsWireTests {

    @Test func requestRoundTrip() throws {
        let request = SecretsRequest(op: .set, profile: "deploy",
                                     values: ["A": "1"],
                                     create: CreateOptions(tier: .confirmEveryRead, exportDisabled: true))
        let decoded = try SecretsCodec.decode(SecretsRequest.self, from: SecretsCodec.encode(request))
        #expect(decoded == request)
        #expect(decoded.v == SecretsWireLimits.version)
    }

    @Test func responseRoundTrip() throws {
        let response = SecretsResponse(ok: true, values: ["A": "1"], exportDisabled: false)
        let decoded = try SecretsCodec.decode(SecretsResponse.self, from: SecretsCodec.encode(response))
        #expect(decoded == response)
    }

    @Test func datesTravelAsEpochSeconds() throws {
        let summary = ProfileSummary(name: "p", tier: .everyRead, variables: ["A"],
                                     exportDisabled: false,
                                     createdAt: Date(timeIntervalSince1970: 1754200000),
                                     updatedAt: Date(timeIntervalSince1970: 1754200000))
        let json = String(decoding: try SecretsCodec.encode(summary), as: UTF8.self)
        #expect(json.contains("\"createdAt\":1754200000"))
    }

    @Test func unknownOpFailsToDecode() {
        let payload = Data(#"{"v":1,"op":"steal"}"#.utf8)
        #expect(throws: (any Error).self) {
            try SecretsCodec.decode(SecretsRequest.self, from: payload)
        }
    }

    @Test func tierRawValuesAreStable() {
        // Wire contract: these strings appear in stored metadata and JSON.
        #expect(SecretTier.everyRead.rawValue == "everyRead")
        #expect(SecretTier.confirmEveryRead.rawValue == "confirmEveryRead")
        #expect(SecretTier.noPrompt.rawValue == "noPrompt")
    }

    @Test func errorCodesAreStable() {
        #expect(SecretsErrorCode.internalError.rawValue == "internal")
        #expect(SecretsErrorCode.exportDisabled.rawValue == "exportDisabled")
        #expect(SecretsErrorCode.unsupportedVersion.rawValue == "unsupportedVersion")
        #expect(SecretsErrorCode.denied.rawValue == "denied")
        #expect(SecretsErrorCode.authFailed.rawValue == "authFailed")
        #expect(SecretsErrorCode.notFound.rawValue == "notFound")
    }

    @Test func enforcementLabelsAreHonest() {
        #expect(SecretTier.everyRead.enforcementLabel == "Enforced by the Secure Enclave")
        #expect(SecretTier.confirmEveryRead.enforcementLabel == "Enforced by Sequester")
        #expect(SecretTier.noPrompt.enforcementLabel == "Notification only")
    }

    @Test func socketPath() {
        #expect(SecretsSocket.path(home: "/Users/u")
                == "/Users/u/Library/Containers/cz.szypowi.sequester/Data/.sequester/secrets.sock")
        #expect(SecretsSocket.resolvedPath(home: "/Users/u", environment: ["SEQUESTER_SECRETS_SOCK": "/tmp/t.sock"])
                == "/tmp/t.sock")
        #expect(SecretsSocket.resolvedPath(home: "/Users/u", environment: [:])
                == SecretsSocket.path(home: "/Users/u"))
    }
}
