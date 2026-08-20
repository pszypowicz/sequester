import Testing
import SecretsWire
@testable import SequesterCore

@Suite struct CheckedNameTests {

    @Test func acceptsAPlainName() {
        let checked = CheckedName("deploy", rule: ProfileName.validate)
        #expect(checked.value == "deploy")
        #expect(checked.message == nil)
        #expect(checked.isUsable)
    }

    @Test func trimsSurroundingWhitespace() {
        // The case that sent this in: a trailing space does not advance the
        // caret, so the field looks correct and the rule rejects it.
        for raw in ["deploy ", " deploy", "  deploy  ", "deploy\n", "\tdeploy"] {
            let checked = CheckedName(raw, rule: ProfileName.validate)
            #expect(checked.value == "deploy")
            #expect(checked.isUsable)
        }
    }

    @Test func reportsTheRuleForAnInnerSpace() {
        let checked = CheckedName("two words", rule: ProfileName.validate)
        #expect(checked.value == "two words")
        #expect(checked.message == ProfileNameError.invalid.errorDescription)
        #expect(!checked.isUsable)
    }

    @Test func reportsTheRuleForOtherRejectedNames() {
        for raw in [".hidden", "-dash", "ż", String(repeating: "a", count: 65)] {
            #expect(!CheckedName(raw, rule: KeyName.validate).isUsable)
        }
    }

    @Test func staysQuietWhileEmpty() {
        // An untouched field is not a mistake to report, but it is not
        // something to submit either.
        for raw in ["", "   ", "\n"] {
            let checked = CheckedName(raw, rule: ProfileName.validate)
            #expect(checked.value.isEmpty)
            #expect(checked.message == nil)
            #expect(!checked.isUsable)
        }
    }

    @Test func carriesTheRuleOfWhicheverValidatorItIsGiven() {
        // Variable names allow no dots or dashes, unlike profile names.
        #expect(CheckedName("a.b-c", rule: ProfileName.validate).isUsable)
        let variable = CheckedName("a.b-c", rule: EnvName.validate)
        #expect(!variable.isUsable)
        #expect(variable.message == EnvNameError.invalid("a.b-c").errorDescription)
    }
}
