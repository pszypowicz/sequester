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

    @Test func eachRefusalClassSilencesOnlyItself() {
        let preferences = NotificationPreferences(refusedAppBlocked: false,
                                                  refusedDestinationBlocked: true,
                                                  refusedKeyLocked: false)
        #expect(!preferences.allows(.appBlocked))
        #expect(preferences.allows(.destinationBlocked))
        #expect(!preferences.allows(.keyLocked))
    }
}
