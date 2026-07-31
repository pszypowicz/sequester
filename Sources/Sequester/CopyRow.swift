import SwiftUI
import SequesterCore

/// A two-row form field: an icon-and-label header with action buttons at
/// the trailing edge (reveal in Finder when a URL is given, always copy),
/// then the value itself on its own line.
struct CopyRow: View {

    let icon: String
    let label: String
    let value: String
    var revealURL: URL?

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Label(label, systemImage: icon)
                Spacer()
                if let revealURL {
                    Button {
                        NSWorkspace.shared.activateFileViewerSelecting([revealURL])
                    } label: {
                        Image(systemName: "folder")
                    }
                    .buttonStyle(.borderless)
                    .help("Show in Finder")
                }
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(value, forType: .string)
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .help("Copy")
            }
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 2)
    }
}
