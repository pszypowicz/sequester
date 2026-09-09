import Testing
import Foundation
@testable import SequesterCore

/// The remember-window choices and their labels, shared by the settings
/// pickers and the "don't ask again" checkbox.
@Suite struct RememberWindowTests {

    @Test func zeroIsOff() {
        #expect(RememberWindow.label(seconds: 0) == "Off")
    }

    @Test func singleMinute() {
        #expect(RememberWindow.label(seconds: 60) == "1 minute")
    }

    @Test func minutesBelowAnHour() {
        #expect(RememberWindow.label(seconds: 300) == "5 minutes")
        #expect(RememberWindow.label(seconds: 1800) == "30 minutes")
    }

    @Test func wholeHours() {
        #expect(RememberWindow.label(seconds: 3600) == "1 hour")
        #expect(RememberWindow.label(seconds: 7200) == "2 hours")
    }

    @Test func choicesReachAnHour() {
        #expect(RememberWindow.choices.contains(1800))
        #expect(RememberWindow.choices.contains(3600))
        #expect(RememberWindow.choices == RememberWindow.choices.sorted())
    }
}
