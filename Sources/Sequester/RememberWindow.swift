import SwiftUI
import SequesterCore

extension RememberWindow {

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
