import Testing
import Foundation
@testable import SequesterCore

/// The requester name shown in the signing-consent prompt derives from the
/// peer's executable basename, which the peer controls by naming its own
/// binary. These pin the sanitizer that keeps it from injecting into or
/// reordering the prompt text.
@Suite struct ProvenanceSanitizeTests {

    @Test func normalNamePreserved() {
        #expect(Provenance.sanitize("ssh") == "ssh")
    }

    @Test func localizedNameWithSpacePreserved() {
        #expect(Provenance.sanitize("Google Chrome") == "Google Chrome")
        #expect(Provenance.sanitize("Электрон") == "Электрон")
    }

    @Test func newlineAndTabCollapseToSpaceNoLineSplitting() {
        let result = Provenance.sanitize("ssh\nfor\tgithub")
        #expect(!result.contains("\n"))
        #expect(!result.contains("\t"))
        #expect(result == "ssh for github")
    }

    @Test func doubleQuoteRemoved() {
        let result = Provenance.sanitize("ssh\" with key \"work")
        #expect(!result.contains("\""))
        #expect(result == "ssh with key work")
    }

    @Test func bidiOverrideAndZeroWidthRemoved() {
        let result = Provenance.sanitize("a\u{202E}b\u{200B}c")
        #expect(!result.unicodeScalars.contains("\u{202E}"))
        #expect(!result.unicodeScalars.contains("\u{200B}"))
        #expect(result == "abc")
    }

    @Test func controlCharactersRemoved() {
        // A path basename from proc_pidpath is a C string, so it never carries
        // an interior NUL; other control characters (BEL, unit separator) are
        // the realistic case.
        #expect(Provenance.sanitize("a\u{0007}b\u{001F}c") == "abc")
    }

    @Test func repeatedAndUnicodeSpacesCollapse() {
        #expect(Provenance.sanitize("a\u{00A0}\u{2003}   b") == "a b")
    }

    @Test func overLengthTruncatedWithEllipsis() {
        let result = Provenance.sanitize(String(repeating: "a", count: 200))
        #expect(result.count == 64)
        #expect(result.hasSuffix("\u{2026}"))
    }

    @Test func truncationIsGraphemeSafe() {
        // A string of composed graphemes (e + combining acute) must not be cut
        // mid-cluster, leaving a dangling combining mark.
        let result = Provenance.sanitize(String(repeating: "e\u{0301}", count: 200))
        #expect(result.count <= 64)
        #expect(result.dropLast().allSatisfy { $0 == "é" || $0 == "e\u{0301}" })
    }

    @Test func allControlYieldsEmpty() {
        #expect(Provenance.sanitize("\u{0007}\u{202E}") == "")
    }
}

/// The consent label prefers the code-signature identity for verified peers
/// and clearly flags an unverified one, and the policy key is stable for
/// verified peers but absent for unverified ones.
@Suite struct ProvenanceIdentityTests {

    @Test func applePlatformLabel() {
        let p = Provenance(pid: 1, path: "/usr/bin/ssh", trust: .applePlatform,
                           signingIdentifier: "com.apple.ssh")
        #expect(p.displayName == "ssh (Apple)")
        #expect(p.isVerified)
    }

    @Test func developerIDLabelUsesTeam() {
        let p = Provenance(pid: 1, path: "/Applications/Foo.app/Contents/MacOS/Foo",
                           trust: .developerID, signingIdentifier: "com.example.Foo", teamID: "ABCDE12345")
        #expect(p.displayName == "Foo (Team ABCDE12345)")
    }

    @Test func developerIDLabelPrefersCertificateName() {
        let p = Provenance(pid: 1, path: "/Applications/Foo.app", trust: .developerID,
                           signingIdentifier: "com.example.Foo", teamID: "ABCDE12345",
                           developerName: "Jane Doe")
        #expect(p.displayName == "Foo (Jane Doe)")
        // The policy key ignores the display name and stays on the team id.
        #expect(p.identityKey == "devid:ABCDE12345:com.example.Foo")
    }

    @Test func certificateNameIsSanitizedInLabel() {
        let p = Provenance(pid: 1, path: "/Applications/Foo.app", trust: .developerID,
                           signingIdentifier: "com.example.Foo", teamID: "ABCDE12345",
                           developerName: "Jane\u{202E} \"Doe\"")
        #expect(p.displayName == "Foo (Jane Doe)")
    }

    @Test func developerNameParsing() {
        #expect(CodeSignatureInspector.developerName(
            fromSubjectSummary: "Developer ID Application: Jane Doe (ABCDE12345)") == "Jane Doe")
        #expect(CodeSignatureInspector.developerName(
            fromSubjectSummary: "Developer ID Application: Example Corp, Inc. (ABCDE12345)") == "Example Corp, Inc.")
        #expect(CodeSignatureInspector.developerName(fromSubjectSummary: "Software Signing") == nil)
        #expect(CodeSignatureInspector.developerName(fromSubjectSummary: "Developer ID Application: ") == nil)
        #expect(CodeSignatureInspector.developerName(fromSubjectSummary: "Apple Development: Jane Doe (X)") == nil)
    }

    @Test func bundlePathDropsDotAppSuffix() {
        // SecCodeCopyPath returns the .app bundle path for a GUI app.
        let p = Provenance(pid: 1, path: "/Applications/Foo.app", trust: .developerID,
                           signingIdentifier: "com.example.Foo", teamID: "ABCDE12345")
        #expect(p.displayName == "Foo (Team ABCDE12345)")
    }

    @Test func unverifiedLabelIsQuotedAndFlagged() {
        let p = Provenance(pid: 1, path: "/tmp/evil/ssh")
        #expect(p.displayName == "\"ssh\" (unverified)")
        #expect(!p.isVerified)
    }

    @Test func unverifiedLabelSanitizesInjection() {
        let p = Provenance(pid: 1, path: "/tmp/x/ssh\" for github.com")
        #expect(p.displayName == "\"ssh for github.com\" (unverified)")
    }

    @Test func nilPathFallsBackToPid() {
        #expect(Provenance(pid: 4242, path: nil).displayName == "\"pid 4242\" (unverified)")
    }

    @Test func identityKeyStableForVerified() {
        let apple = Provenance(pid: 1, path: "/usr/bin/ssh", trust: .applePlatform,
                               signingIdentifier: "com.apple.ssh")
        #expect(apple.identityKey == "apple:com.apple.ssh")
        let dev = Provenance(pid: 1, path: "/x/Foo", trust: .developerID,
                             signingIdentifier: "com.example.Foo", teamID: "ABCDE12345")
        #expect(dev.identityKey == "devid:ABCDE12345:com.example.Foo")
    }

    @Test func identityKeyNilForUnverified() {
        #expect(Provenance(pid: 1, path: "/tmp/evil").identityKey == nil)
    }
}
