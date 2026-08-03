import Foundation

public enum EnvNameError: LocalizedError {
    case invalid(String)

    public var errorDescription: String? {
        switch self {
        case .invalid(let name):
            "\"\(name)\" is not a valid variable name. Use letters, digits, and underscores, not starting with a digit."
        }
    }
}

public enum EnvName {
    /// Variable names land unquoted in export lines and go straight into
    /// setenv, so only strict identifiers are accepted.
    public static func validate(_ name: String) throws {
        let pattern = /^[A-Za-z_][A-Za-z0-9_]{0,255}$/
        guard name.wholeMatch(of: pattern) != nil else { throw EnvNameError.invalid(name) }
    }
}

/// Shell-specific rendering of KEY=value pairs as export lines. Values are
/// always single-quoted; inside single quotes each shell treats everything
/// as literal except the sequences escaped here, so newlines and other
/// hostile content survive verbatim.
public enum EnvFormat: String, Codable, Sendable, CaseIterable {
    case posix
    case fish

    public func line(key: String, value: String) -> String {
        switch self {
        case .posix:
            // POSIX single quotes cannot contain a single quote; the
            // '\'' sequence closes the string, escapes one quote, reopens.
            "export \(key)='\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
        case .fish:
            // fish single quotes honor two escapes, \\ and \'; the
            // backslash must be doubled first so it cannot re-escape the
            // quote replacement.
            "set -gx \(key) '\(value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "'", with: "\\'"))'"
        }
    }

    /// All variables of a profile as one script, sorted by key so output is
    /// deterministic.
    public func script(values: [String: String]) -> String {
        values.sorted { $0.key < $1.key }
            .map { line(key: $0.key, value: $0.value) }
            .joined(separator: "\n")
    }
}
