import SwiftUI

/// A selectable monospaced value with an inline copy button, used for
/// paths, fingerprints, and key material across the settings UI.
struct CopyableText: View {

    let text: String
    var lineLimit: Int? = 1

    var body: some View {
        HStack(spacing: 6) {
            Text(text)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .lineLimit(lineLimit)
                .truncationMode(.middle)
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copy")
        }
    }
}
