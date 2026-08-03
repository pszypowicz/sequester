import Testing
import SecretsWire

@Suite struct EnvNameTests {

    @Test func acceptsIdentifiers() throws {
        for name in ["A", "_A", "GITHUB_TOKEN", "a1", "_", "X_2_Y"] {
            try EnvName.validate(name)
        }
    }

    @Test func rejectsNonIdentifiers() {
        let tooLong = String(repeating: "A", count: 257)
        for name in ["", "1A", "A-B", "A B", "A=B", "A\nB", "TOKEN!", "ż", tooLong] {
            #expect(throws: EnvNameError.self) {
                try EnvName.validate(name)
            }
        }
    }

    @Test func acceptsMaximumLength() throws {
        try EnvName.validate(String(repeating: "A", count: 256))
    }
}

@Suite struct EnvFormatTests {

    @Test func posixPlainValue() {
        #expect(EnvFormat.posix.line(key: "TOKEN", value: "abc123") == "export TOKEN='abc123'")
    }

    @Test func posixSingleQuote() {
        // 'a'\''b': close, escaped quote, reopen.
        #expect(EnvFormat.posix.line(key: "V", value: "a'b") == "export V='a'\\''b'")
    }

    @Test func posixHostileValuesStayLiteral() {
        for value in ["$HOME", "`id`", "a;rm -rf /", "line1\nline2", "back\\slash", "\"double\"", "-dash", "", "żółć"] {
            let line = EnvFormat.posix.line(key: "V", value: value)
            #expect(line.hasPrefix("export V='"))
            // Everything between the quotes is literal in POSIX except the
            // quote escape itself, which the single-quote test pins.
            #expect(line == "export V='\(value.replacingOccurrences(of: "'", with: "'\\''"))'")
        }
    }

    @Test func fishPlainValue() {
        #expect(EnvFormat.fish.line(key: "TOKEN", value: "abc123") == "set -gx TOKEN 'abc123'")
    }

    @Test func fishEscapesQuoteAndBackslash() {
        #expect(EnvFormat.fish.line(key: "V", value: "a'b") == "set -gx V 'a\\'b'")
        #expect(EnvFormat.fish.line(key: "V", value: "a\\b") == "set -gx V 'a\\\\b'")
        // Backslash doubles first, so a literal \' input survives as \\ then \'.
        #expect(EnvFormat.fish.line(key: "V", value: "a\\'b") == "set -gx V 'a\\\\\\'b'")
    }

    @Test func scriptSortsByKey() {
        let script = EnvFormat.posix.script(values: ["B": "2", "A": "1", "C": "3"])
        #expect(script == "export A='1'\nexport B='2'\nexport C='3'")
    }

    @Test func emptyScript() {
        #expect(EnvFormat.posix.script(values: [:]) == "")
    }
}
