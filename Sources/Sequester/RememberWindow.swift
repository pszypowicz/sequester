import SwiftUI

/// The window lengths offered in settings, and their labels. Off is the
/// default everywhere: a remembered tap is a deliberate trade of a
/// confirmation for convenience, so nothing opts into it silently.
enum RememberWindow {

    static let choices: [TimeInterval] = [0, 60, 300, 900]

    static func label(seconds: TimeInterval) -> String {
        switch seconds {
        case ..<1: "Off"
        case ..<120: "1 minute"
        default: "\(Int(seconds / 60)) minutes"
        }
    }

    @ViewBuilder
    static func picker(selection: Binding<TimeInterval>, info: String) -> some View {
        Picker(selection: selection) {
            ForEach(choices, id: \.self) { seconds in
                Text(label(seconds: seconds)).tag(seconds)
            }
        } label: {
            HStack(spacing: 4) {
                Text("Remember confirmation")
                InfoDot(text: info)
            }
        }
    }
}
