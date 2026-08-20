import Foundation

/// A name as it stands in an editing form: trimmed of the whitespace a text
/// field accepts, and measured against the rule the store applies on submit.
/// The stores validate again and stay the authority. This mirrors the rule
/// into the form so a sheet can disable its button and name the rule while
/// the name is typed, instead of refusing it afterwards.
///
/// The trimming is not only tidiness. AppKit's text layout does not advance
/// the caret for whitespace at the end of a line, so a trailing space is
/// invisible in the field that holds it, and a name that looks right is
/// rejected for a character its author cannot see.
public struct CheckedName: Sendable {

    /// The name without leading or trailing whitespace. This is the value to
    /// hand to the store.
    public let value: String

    /// The rule to show, or nil while the name is acceptable. An empty name
    /// carries no message, since a field nobody has filled in yet is not a
    /// mistake to report.
    public let message: String?

    /// True when the name is present and passes the rule.
    public var isUsable: Bool { !value.isEmpty && message == nil }

    /// - Parameters:
    ///   - raw: the text as typed.
    ///   - rule: the store-side validator, for example `ProfileName.validate`.
    public init(_ raw: String, rule: (String) throws -> Void) {
        value = Self.trimmed(raw)
        guard !value.isEmpty else {
            message = nil
            return
        }
        do {
            try rule(value)
            message = nil
        } catch {
            message = error.localizedDescription
        }
    }

    /// The whitespace a text field accepts, dropped from both ends. Newlines
    /// count: a name arrives by paste as often as by typing.
    public static func trimmed(_ raw: String) -> String {
        raw.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
