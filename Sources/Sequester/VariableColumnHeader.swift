import SwiftUI

/// The column header row of the variable tables in the profile sheets. The
/// name column is fixed-width so the header and every entry row align; the
/// trailing slot mirrors the width of the per-row remove button.
struct VariableColumnHeader: View {

    static let nameWidth: CGFloat = 170

    var body: some View {
        HStack(spacing: 8) {
            Text("Name")
                .frame(width: Self.nameWidth, alignment: .leading)
            Divider()
            Text("Value")
            Spacer()
            Color.clear.frame(width: 20, height: 1)
        }
        .font(.caption)
        .foregroundStyle(.secondary)
    }
}
