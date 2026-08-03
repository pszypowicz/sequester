import Foundation
import Darwin
import Security

// The "responsible process" is the terminal or app a short-lived client (like
// ssh) was launched from. LaunchServices and the sandbox use this same
// libsystem notion; it is what lets a session grant follow the terminal
// instead of the ssh process that exits immediately.
@_silgen_name("responsibility_get_pid_responsible_for_pid")
private func responsibility_get_pid_responsible_for_pid(_ pid: pid_t) -> pid_t

/// Identity of the local process on the other end of an agent connection,
/// including whether its code signature could be verified.
public struct Provenance: Sendable, Hashable {

    /// How far the requester's identity can be trusted, derived from its code
    /// signature. Any failure to obtain or verify the signature lands on
    /// `.unverified`; a verified tier is only ever reached on a successful
    /// signature check, so the fail-safe direction is built in.
    public enum Trust: Sendable, Hashable {
        case applePlatform
        case developerID
        case unverified
    }

    public let pid: pid_t
    public let path: String?
    public let trust: Trust
    public let signingIdentifier: String?
    public let teamID: String?
    /// Human name from the Developer ID leaf certificate, display only.
    /// Policy keys stay on the team id, which survives certificate renewal.
    public let developerName: String?

    public init(pid: pid_t, path: String?, trust: Trust = .unverified,
                signingIdentifier: String? = nil, teamID: String? = nil,
                developerName: String? = nil) {
        self.pid = pid
        self.path = path
        self.trust = trust
        self.signingIdentifier = signingIdentifier
        self.teamID = teamID
        self.developerName = developerName
    }

    public var isVerified: Bool { trust != .unverified }

    /// A stable key for per-app policy that survives app updates, unlike a
    /// cdhash. `nil` for unverified peers, which therefore can never be
    /// remembered as allowed - only asked or blocked for the moment.
    public var identityKey: String? {
        guard let signingIdentifier else { return nil }
        switch trust {
        case .unverified: return nil
        case .applePlatform: return "apple:\(signingIdentifier)"
        case .developerID: return "devid:\(teamID ?? "-"):\(signingIdentifier)"
        }
    }

    /// Trustworthy, user-facing label. For verified peers the name comes from
    /// the code signature (via `SecCodeCopyPath`), not the attacker-controlled
    /// filename; the unverified name is the sanitized basename, quoted and
    /// flagged so it never reads as an authoritative identity. A Developer ID
    /// peer shows the developer name from its certificate, the same source
    /// Gatekeeper's dialogs use, with the team id as the fallback.
    public var displayName: String {
        let base = Self.sanitizedBasename(path: path, pid: pid)
        switch trust {
        case .applePlatform:
            return "\(base) (Apple)"
        case .developerID:
            if let developerName {
                let clean = Self.sanitize(developerName)
                if !clean.isEmpty { return "\(base) (\(clean))" }
            }
            if let teamID { return "\(base) (Team \(teamID))" }
            return "\(base) (signed)"
        case .unverified:
            return "\"\(base)\" (unverified)"
        }
    }

    static func sanitizedBasename(path: String?, pid: pid_t) -> String {
        guard let path else { return "pid \(pid)" }
        // For a verified GUI app SecCodeCopyPath returns the bundle path, so
        // the last component keeps the ".app" suffix; drop it so the label
        // reads as the app's name.
        var component = URL(filePath: path).lastPathComponent
        if component.hasSuffix(".app") {
            component = String(component.dropLast(4))
        }
        let cleaned = sanitize(component)
        return cleaned.isEmpty ? "pid \(pid)" : cleaned
    }

    /// Renders an untrusted executable basename safe to interpolate into the
    /// signing-consent prompt and the approval dialog. The peer chooses its
    /// own binary's name, and a macOS filename may hold anything but '/' and
    /// NUL: control characters, bidi overrides that reorder rendered text,
    /// the quote used to delimit the key name, embedded newlines, arbitrary
    /// length. Collapse every whitespace run to one space, drop characters
    /// that could inject into or reorder the prompt, remove the double quote,
    /// and bound the length on a grapheme boundary.
    static func sanitize(_ raw: String, limit: Int = 64) -> String {
        var scalars = String.UnicodeScalarView()
        var lastWasSpace = false
        for scalar in raw.unicodeScalars {
            if scalar.properties.isWhitespace {
                if !lastWasSpace {
                    scalars.append(" ")
                    lastWasSpace = true
                }
                continue
            }
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator,
                 .privateUse, .surrogate, .unassigned:
                continue
            default:
                break
            }
            if scalar == "\"" { continue }
            scalars.append(scalar)
            lastWasSpace = false
        }
        let trimmed = String(scalars).trimmingCharacters(in: .whitespaces)
        guard trimmed.count > limit else { return trimmed }
        return String(trimmed.prefix(limit - 1)) + "\u{2026}"
    }
}

public enum ProvenanceTracer {

    /// Resolves the peer of a connected Unix socket to a verified identity.
    /// The peer audit token (race-free, unlike a bare pid) is passed to
    /// Security.framework to inspect the peer's live code signature. Best
    /// effort: if the token or any signature check is unavailable, the result
    /// is `.unverified` with the pid+path filled in as far as possible.
    public static func provenance(socket fd: Int32) -> Provenance {
        guard let token = peerAuditToken(socket: fd) else {
            return legacyProvenance(socket: fd)
        }
        let pid = pid_t(bitPattern: token.val.5)
        let identity = CodeSignatureInspector.inspect(auditToken: token)
        return Provenance(
            pid: pid,
            path: identity.path ?? pathForPid(pid),
            trust: identity.trust,
            signingIdentifier: identity.signingIdentifier,
            teamID: identity.teamID,
            developerName: identity.developerName
        )
    }

    /// A human-readable resolution report for the `--selftest-provenance`
    /// probe, including the raw status of the sandbox-gated SecCode call.
    static func probeReport(socket fd: Int32) -> String {
        guard let token = peerAuditToken(socket: fd) else {
            return "no audit token: LOCAL_PEERTOKEN failed"
        }
        let guestStatus = CodeSignatureInspector.guestStatus(auditToken: token)
        let provenance = provenance(socket: fd)
        return """
        audit token: OK (pid \(provenance.pid))
        SecCodeCopyGuestWithAttributes status: \(guestStatus)
        trust: \(provenance.trust)
        signingIdentifier: \(provenance.signingIdentifier ?? "-")
        teamID: \(provenance.teamID ?? "-")
        path: \(provenance.path ?? "-")
        displayName: \(provenance.displayName)
        identityKey: \(provenance.identityKey ?? "-")
        """
    }

    /// A stable id for the responsible process instance - the terminal or IDE
    /// a short-lived client (like ssh) was launched from - used to scope
    /// "allow for this session" grants. Scoping to the responsible process
    /// rather than the ssh instance (which exits at once) is what makes the
    /// session grant span a terminal's connections. The start time makes a
    /// reused pid a different instance. Falls back to the connecting process
    /// when no responsible process resolves.
    static func responsibleInstanceID(forPid pid: pid_t) -> String? {
        guard pid > 0 else { return nil }
        let responsible = responsibility_get_pid_responsible_for_pid(pid)
        let target = responsible > 0 ? responsible : pid
        return "\(target).\(processStartTime(target))"
    }

    /// Resolves the responsible process of a connected peer to a verified
    /// identity, for policy keyed on the terminal or IDE rather than the
    /// short-lived client that connected. The lookup is by pid, which is
    /// racier than the peer audit token, but the responsible process is
    /// long-lived and the instance id pins a reused pid via the start time.
    public static func responsibleProvenance(forPid pid: pid_t) -> (provenance: Provenance, instanceID: String?) {
        guard pid > 0 else { return (Provenance(pid: -1, path: nil), nil) }
        let responsible = responsibility_get_pid_responsible_for_pid(pid)
        let target = responsible > 0 ? responsible : pid
        let identity = CodeSignatureInspector.inspect(pid: target)
        let provenance = Provenance(
            pid: target,
            path: identity.path ?? pathForPid(target),
            trust: identity.trust,
            signingIdentifier: identity.signingIdentifier,
            teamID: identity.teamID,
            developerName: identity.developerName
        )
        return (provenance, "\(target).\(processStartTime(target))")
    }

    private static func processStartTime(_ pid: pid_t) -> UInt64 {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        let rc = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size)
        return rc == size ? UInt64(info.pbi_start_tvsec) : 0
    }

    static func peerAuditToken(socket fd: Int32) -> audit_token_t? {
        var token = audit_token_t()
        var length = socklen_t(MemoryLayout<audit_token_t>.size)
        let rc = withUnsafeMutablePointer(to: &token) { pointer in
            getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, pointer, &length)
        }
        guard rc == 0, length == socklen_t(MemoryLayout<audit_token_t>.size) else { return nil }
        return token
    }

    private static func pathForPid(_ pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4096)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        let bytes = buffer.prefix(Int(length)).map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func legacyProvenance(socket fd: Int32) -> Provenance {
        var pid: pid_t = -1
        var size = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0 else {
            return Provenance(pid: -1, path: nil)
        }
        return Provenance(pid: pid, path: pathForPid(pid))
    }
}

/// Inspects a peer's code signature from its audit token. Every failure path
/// returns `.unverified`; the trust tier is upgraded only when the relevant
/// `SecCodeCheckValidity` succeeds.
enum CodeSignatureInspector {

    struct Result {
        var trust: Provenance.Trust
        var signingIdentifier: String?
        var teamID: String?
        var path: String?
        var developerName: String?

        static let unverified = Result(trust: .unverified, signingIdentifier: nil, teamID: nil, path: nil)
    }

    static func inspect(auditToken token: audit_token_t) -> Result {
        guard let code = copyGuest(auditToken: token) else { return .unverified }
        return inspect(code: code)
    }

    /// Pid-based lookup for a process that is not a socket peer (the
    /// responsible process). Racier than the audit-token path: the pid could
    /// in principle be reused between lookup and use, so callers pair the
    /// result with a pid+start-time instance id.
    static func inspect(pid: pid_t) -> Result {
        var code: SecCode?
        let attributes = [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code else {
            return .unverified
        }
        return inspect(code: code)
    }

    private static func inspect(code: SecCode) -> Result {
        let unverified = Result.unverified

        // The signature must be intact and satisfy its own designated
        // requirement before any of its claimed attributes are trusted.
        guard SecCodeCheckValidity(code, [], nil) == errSecSuccess else { return unverified }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode else { return unverified }

        var information: CFDictionary?
        SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
        let info = information as? [String: Any]
        let signingID = info?[kSecCodeInfoIdentifier as String] as? String
        let teamID = info?[kSecCodeInfoTeamIdentifier as String] as? String

        var pathURL: CFURL?
        SecCodeCopyPath(staticCode, [], &pathURL)
        let path = (pathURL as URL?)?.path

        let trust: Provenance.Trust
        if satisfies(code, "anchor apple") {
            trust = .applePlatform
        } else if satisfies(code, "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists") {
            trust = .developerID
        } else {
            trust = .unverified
        }
        return Result(trust: trust, signingIdentifier: signingID, teamID: teamID, path: path,
                      developerName: trust == .developerID ? leafDeveloperName(info) : nil)
    }

    /// The developer name from the leaf certificate of a verified Developer
    /// ID signature, for display. The chain rides in the signing-information
    /// dictionary the inspection already fetched.
    private static func leafDeveloperName(_ info: [String: Any]?) -> String? {
        guard let chain = info?[kSecCodeInfoCertificates as String] as? [AnyObject],
              let first = chain.first,
              CFGetTypeID(first) == SecCertificateGetTypeID() else {
            return nil
        }
        let leaf = first as! SecCertificate
        guard let summary = SecCertificateCopySubjectSummary(leaf) as String? else { return nil }
        return developerName(fromSubjectSummary: summary)
    }

    /// Extracts the human name from a Developer ID subject summary, e.g.
    /// "Developer ID Application: Jane Doe (TEAM123456)" becomes "Jane Doe".
    /// Nil for any other shape, which falls back to the team-id label.
    static func developerName(fromSubjectSummary summary: String) -> String? {
        let prefix = "Developer ID Application: "
        guard summary.hasPrefix(prefix) else { return nil }
        var name = String(summary.dropFirst(prefix.count))
        if name.hasSuffix(")"), let open = name.range(of: " (", options: .backwards) {
            name = String(name[..<open.lowerBound])
        }
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Raw status of the sandbox-gated dynamic-code lookup, for the probe.
    static func guestStatus(auditToken token: audit_token_t) -> OSStatus {
        var code: SecCode?
        return SecCodeCopyGuestWithAttributes(nil, guestAttributes(token), [], &code)
    }

    private static func copyGuest(auditToken token: audit_token_t) -> SecCode? {
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, guestAttributes(token), [], &code) == errSecSuccess else {
            return nil
        }
        return code
    }

    private static func guestAttributes(_ token: audit_token_t) -> CFDictionary {
        let tokenData = withUnsafeBytes(of: token) { Data($0) } as CFData
        return [kSecGuestAttributeAudit: tokenData] as CFDictionary
    }

    private static func satisfies(_ code: SecCode, _ requirementText: String) -> Bool {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess,
              let requirement else {
            return false
        }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }
}
