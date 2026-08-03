import Testing
import Foundation
import SecretsWire
@testable import SequesterCore

/// A credential stored by a version that predates a setting has to keep
/// working. Adding a required field would make every existing item fail to
/// decode and vanish from the inventory, so these pin the tolerance.
@Suite struct MetadataCompatibilityTests {

    private let epoch = Date(timeIntervalSince1970: 0)

    private func decodeKey(_ object: [String: Any]) throws -> KeyMetadata {
        let data = try JSONSerialization.data(withJSONObject: object)
        return try JSONDecoder().decode(KeyMetadata.self, from: data)
    }

    @Test func keyWithoutRememberSecondsStillDecodes() throws {
        // Exactly the shape written before the remembered-tap window
        // existed.
        let key = try decodeKey([
            "name": "github",
            "keyDescription": "work",
            "authRequired": true,
            "blockForwarded": false,
            "approveAll": false,
            "autoApprove": false,
            "locked": false,
            "destinations": [],
            "branchRules": [],
            "appRules": [],
            "publicKey": Data(count: 65).base64EncodedString(),
            "createdAt": 0,
        ])
        #expect(key.name == "github")
        #expect(key.authRequired)
        #expect(key.rememberSeconds == 0)
    }

    @Test func keyWithOnlyIdentityFieldsDecodes() throws {
        let key = try decodeKey([
            "name": "minimal",
            "publicKey": Data(count: 65).base64EncodedString(),
            "createdAt": 0,
        ])
        #expect(key.name == "minimal")
        // Absent settings fall back to the safe end, never to signing
        // without asking.
        #expect(key.authRequired)
        #expect(!key.approveAll)
        #expect(!key.autoApprove)
        #expect(key.rememberSeconds == 0)
    }

    @Test func keyMissingItsIdentityIsRejected() {
        #expect(throws: (any Error).self) {
            try decodeKey(["keyDescription": "no name or key material"])
        }
    }

    @Test func profileWithoutRememberSecondsStillDecodes() throws {
        let object: [String: Any] = [
            "name": "deploy",
            "tier": "everyRead",
            "variableNames": ["TOKEN"],
            "exportDisabled": false,
            "publicKey": Data(count: 65).base64EncodedString(),
            "createdAt": 0,
            "updatedAt": 0,
        ]
        let data = try JSONSerialization.data(withJSONObject: object)
        let profile = try JSONDecoder().decode(ProfileMetadata.self, from: data)
        #expect(profile.name == "deploy")
        #expect(profile.tier == .everyRead)
        #expect(profile.rememberSeconds == 0)
    }

    @Test func roundTripsSurviveTheCustomDecoders() throws {
        let key = KeyMetadata(name: "k", keyDescription: "d", authRequired: true,
                              rememberSeconds: 300, comment: "c",
                              publicKey: Data(count: 65), createdAt: epoch)
        let decodedKey = try JSONDecoder().decode(KeyMetadata.self, from: JSONEncoder().encode(key))
        #expect(decodedKey == key)

        let profile = ProfileMetadata(name: "p", tier: .confirmEveryRead, variableNames: ["A"],
                                      rememberSeconds: 60, publicKey: Data(count: 65),
                                      createdAt: epoch, updatedAt: epoch)
        let decodedProfile = try JSONDecoder().decode(ProfileMetadata.self, from: JSONEncoder().encode(profile))
        #expect(decodedProfile == profile)
    }
}
