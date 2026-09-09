import Foundation

/// The window lengths offered for a remembered tap or confirmation, and
/// their labels. Off is the default everywhere: a remembered tap is a
/// deliberate trade of a confirmation for convenience, so nothing opts into
/// it silently.
public enum RememberWindow {

    public static let choices: [TimeInterval] = [0, 60, 300, 900, 1800, 3600]

    public static func label(seconds: TimeInterval) -> String {
        switch seconds {
        case ..<1: "Off"
        case ..<120: "1 minute"
        case ..<3600: "\(Int(seconds / 60)) minutes"
        case ..<7200: "1 hour"
        default: "\(Int(seconds / 3600)) hours"
        }
    }
}
