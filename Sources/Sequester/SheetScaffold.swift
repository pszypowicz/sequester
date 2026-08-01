import SwiftUI

/// Shared chrome for the small editing sheets: a grouped form, a divider,
/// then an error caption and Cancel / primary buttons. Each sheet supplies
/// only its form sections and its primary action.
struct SheetScaffold<Content: View>: View {

    let primaryTitle: String
    var primaryRole: ButtonRole? = nil
    var primaryDisabled: Bool = false
    var error: String?
    let size: CGSize
    let onPrimary: () -> Void
    @ViewBuilder let content: () -> Content

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Form { content() }
                .formStyle(.grouped)

            Divider()
            HStack {
                if let error {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                primaryButton
            }
            .padding()
        }
        .frame(width: size.width, height: size.height)
    }

    /// The default-action button. A destructive action gets a red prominent
    /// fill so it reads as dangerous rather than as the ordinary blue default.
    @ViewBuilder private var primaryButton: some View {
        let button = Button(primaryTitle, role: primaryRole, action: onPrimary)
            .keyboardShortcut(.defaultAction)
            .disabled(primaryDisabled)
        if primaryRole == .destructive {
            button.buttonStyle(.borderedProminent).tint(.red)
        } else {
            button
        }
    }
}
