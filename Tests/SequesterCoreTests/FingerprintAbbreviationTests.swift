import Testing
import Foundation
@testable import SequesterCore

/// A fingerprint shortened for a one-line notification keeps its hash
/// prefix and a fixed run of hash characters, and leaves short values alone.
@Suite struct FingerprintAbbreviationTests {

    private let full = "SHA256:qXvW9dDyU7bJ5pK2mN8rT4hL6sG1fA3cE0zY9wV8uB7"

    @Test func keepsPrefixAndTwentyHashCharacters() {
        #expect(OpenSSH.abbreviatedFingerprint(full) == "SHA256:qXvW9dDyU7bJ5pK2mN8r\u{2026}")
    }

    @Test func leavesAShortFingerprintAlone() {
        #expect(OpenSSH.abbreviatedFingerprint("SHA256:selftest") == "SHA256:selftest")
    }

    @Test func leavesAValueWithoutAPrefixAlone() {
        #expect(OpenSSH.abbreviatedFingerprint("github.com") == "github.com")
    }

    @Test func leavesAnExactFitAlone() {
        let exact = "SHA256:" + String(repeating: "a", count: 20)
        #expect(OpenSSH.abbreviatedFingerprint(exact) == exact)
    }
}
