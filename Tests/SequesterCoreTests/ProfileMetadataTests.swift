import Testing
import Foundation
import SecretsWire
@testable import SequesterCore

@Suite struct ProfileMetadataTests {

    private let epoch = Date(timeIntervalSince1970: 0)

    private func metadata() -> ProfileMetadata {
        ProfileMetadata(name: "deploy", tier: .unapprovedOnly,
                        variableNames: ["A_TOKEN", "B_TOKEN"],
                        exportDisabled: true, approveAll: false,
                        appRules: [AppRule(identity: "devid:T:app", displayName: "app", state: .blocked)],
                        publicKey: Data(count: 65), createdAt: epoch, updatedAt: epoch)
    }

    @Test func codableRoundTrip() throws {
        let original = metadata()
        let decoded = try JSONDecoder().decode(ProfileMetadata.self, from: JSONEncoder().encode(original))
        #expect(decoded == original)
    }

    @Test func decodingIgnoresUnknownFields() throws {
        // Forward compatibility: metadata written by a newer version with
        // extra fields must still load.
        var object = try JSONSerialization.jsonObject(
            with: JSONEncoder().encode(metadata())) as! [String: Any]
        object["futureField"] = "future"
        let data = try JSONSerialization.data(withJSONObject: object)
        let decoded = try JSONDecoder().decode(ProfileMetadata.self, from: data)
        #expect(decoded.name == "deploy")
        #expect(decoded.tier == .unapprovedOnly)
    }

    @Test func summaryCarriesListFields() {
        let summary = metadata().summary
        #expect(summary.name == "deploy")
        #expect(summary.tier == .unapprovedOnly)
        #expect(summary.variables == ["A_TOKEN", "B_TOKEN"])
        #expect(summary.exportDisabled)
    }

    @Test func nameValidationMatchesKeyRules() throws {
        try ProfileName.validate("deploy")
        try ProfileName.validate("a.b-c_d")
        for invalid in ["", ".hidden", "-dash", "with space", "ż", String(repeating: "a", count: 65)] {
            #expect(throws: ProfileNameError.self) {
                try ProfileName.validate(invalid)
            }
        }
    }
}
