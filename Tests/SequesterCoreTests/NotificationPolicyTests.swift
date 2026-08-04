import Testing
import Foundation
@testable import SequesterCore

@Suite struct NotificationPreferencesTests {

    @Test func defaultsAnnounceEverythingButPromptedSignatures() {
        let preferences = NotificationPreferences()
        // A prompted signature repeats a prompt just answered, so it is the
        // one class that starts off.
        #expect(preferences.signedKind(silent: false, firstUse: false) == nil)
        #expect(preferences.signedKind(silent: true, firstUse: false) == .silent)
        #expect(preferences.signedKind(silent: false, firstUse: true) == .newDestination)
        for reason in [PolicyEngine.DenialReason.appBlocked, .destinationBlocked, .keyLocked] {
            #expect(preferences.allows(reason))
        }
    }

    @Test func firstUseOutranksSilencedSignatures() {
        // Someone who has silenced routine signatures still hears about a
        // key reaching a destination for the first time.
        let preferences = NotificationPreferences(signedSilently: false, signedAfterPrompt: false,
                                                  signedNewDestination: true)
        #expect(preferences.signedKind(silent: true, firstUse: true) == .newDestination)
        #expect(preferences.signedKind(silent: false, firstUse: true) == .newDestination)
        #expect(preferences.signedKind(silent: true, firstUse: false) == nil)
    }

    @Test func firstUseFallsBackWhenItsOwnClassIsOff() {
        let preferences = NotificationPreferences(signedSilently: true, signedAfterPrompt: true,
                                                  signedNewDestination: false)
        #expect(preferences.signedKind(silent: true, firstUse: true) == .silent)
        #expect(preferences.signedKind(silent: false, firstUse: true) == .afterPrompt)
    }

    @Test func eachSignatureClassSilencesOnlyItself() {
        let quietSilent = NotificationPreferences(signedSilently: false, signedAfterPrompt: true,
                                                  signedNewDestination: false)
        #expect(quietSilent.signedKind(silent: true, firstUse: false) == nil)
        #expect(quietSilent.signedKind(silent: false, firstUse: false) == .afterPrompt)

        let quietPrompted = NotificationPreferences(signedSilently: true, signedAfterPrompt: false,
                                                    signedNewDestination: false)
        #expect(quietPrompted.signedKind(silent: true, firstUse: false) == .silent)
        #expect(quietPrompted.signedKind(silent: false, firstUse: false) == nil)
    }

    @Test func keyOverrideReplacesOnlyTheClassesAKeyProduces() {
        // A key silences its own signatures without touching what the
        // profiles are doing.
        let global = NotificationPreferences(signedSilently: true, secretsReadSilently: true)
        let quietKey = KeyNotificationOverride(signedSilently: false, signedAfterPrompt: false,
                                               signedNewDestination: false, refusedAppBlocked: false,
                                               refusedDestinationBlocked: false, refusedKeyLocked: false)
        let resolved = global.applying(quietKey)
        #expect(resolved.signedKind(silent: true, firstUse: true) == nil)
        #expect(!resolved.allows(.keyLocked))
        #expect(resolved.allowsSecretsRead(silent: true))
        #expect(resolved.secretsChanged)
    }

    @Test func profileOverrideReplacesOnlyItsOwnClasses() {
        let global = NotificationPreferences(signedSilently: true, secretsReadSilently: true, secretsChanged: true)
        let quietProfile = ProfileNotificationOverride(readSilently: false, readAfterPrompt: false, changed: false)
        let resolved = global.applying(quietProfile)
        #expect(!resolved.allowsSecretsRead(silent: true))
        #expect(!resolved.secretsChanged)
        #expect(resolved.signedKind(silent: true, firstUse: false) == .silent)
    }

    @Test func absentOverrideLeavesTheGlobalSettings() {
        let global = NotificationPreferences(signedSilently: false, secretsChanged: false)
        #expect(global.applying(nil as KeyNotificationOverride?) == global)
        #expect(global.applying(nil as ProfileNotificationOverride?) == global)
    }

    @Test func overrideStartsFromTheGlobalSettings() {
        // Moving a credential off the global settings copies them, so it
        // begins by doing exactly what it did before.
        let global = NotificationPreferences(signedSilently: false, signedAfterPrompt: true,
                                             refusedKeyLocked: false, secretsReadSilently: false)
        #expect(global.applying(global.keyOverride) == global)
        #expect(global.applying(global.profileOverride) == global)
    }

    @Test func metadataWrittenBeforeOverridesExistedStillDecodes() throws {
        // The field is optional precisely so a key or profile stored by an
        // earlier version keeps working: absent decodes as "follow global",
        // and no credential has to be recreated.
        let keyJSON = """
        {"name":"k","keyDescription":"","authRequired":true,"blockForwarded":false,
         "approveAll":false,"autoApprove":false,"locked":false,"destinations":[],
         "branchRules":[],"appRules":[],"rememberSeconds":0,
         "publicKey":"\(Data(count: 65).base64EncodedString())","createdAt":0}
        """
        let key = try JSONDecoder().decode(KeyMetadata.self, from: Data(keyJSON.utf8))
        #expect(key.notifications == nil)

        let profileJSON = """
        {"name":"p","tier":"everyRead","variableNames":[],"exportDisabled":false,
         "rememberSeconds":0,"publicKey":"\(Data(count: 65).base64EncodedString())",
         "createdAt":0,"updatedAt":0}
        """
        let profile = try JSONDecoder().decode(ProfileMetadata.self, from: Data(profileJSON.utf8))
        #expect(profile.notifications == nil)
    }

    @Test func overridesSurviveTheStorageRoundTrip() throws {
        var key = KeyMetadata(name: "k", keyDescription: "", authRequired: true,
                              publicKey: Data(count: 65), createdAt: Date(timeIntervalSince1970: 0))
        key.notifications = KeyNotificationOverride(
            signedSilently: false, signedAfterPrompt: true, signedNewDestination: false,
            refusedAppBlocked: true, refusedDestinationBlocked: false, refusedKeyLocked: true
        )
        let decodedKey = try JSONDecoder().decode(KeyMetadata.self, from: JSONEncoder().encode(key))
        #expect(decodedKey.notifications == key.notifications)

        var profile = ProfileMetadata(name: "p", tier: .everyRead, variableNames: [],
                                      publicKey: Data(count: 65),
                                      createdAt: Date(timeIntervalSince1970: 0),
                                      updatedAt: Date(timeIntervalSince1970: 0))
        profile.notifications = ProfileNotificationOverride(readSilently: false, readAfterPrompt: true, changed: false)
        let decodedProfile = try JSONDecoder().decode(ProfileMetadata.self, from: JSONEncoder().encode(profile))
        #expect(decodedProfile.notifications == profile.notifications)
    }

    @Test func eachRefusalClassSilencesOnlyItself() {
        let preferences = NotificationPreferences(refusedAppBlocked: false,
                                                  refusedDestinationBlocked: true,
                                                  refusedKeyLocked: false)
        #expect(!preferences.allows(.appBlocked))
        #expect(preferences.allows(.destinationBlocked))
        #expect(!preferences.allows(.keyLocked))
    }
}
