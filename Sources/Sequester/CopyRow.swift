import SwiftUI
import SequesterCore

/// A single form row: label on the left, selectable monospaced value
/// truncating in the middle, then optional reveal-in-Finder and copy
/// buttons at the trailing edge.
struct CopyRow: View {

    let label: String
    let value: String
    var revealURL: URL?

    var body: some View {
        HStack(spacing: 8) {
            Text(label)
            Spacer()
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .lineLimit(1)
                .truncationMode(.middle)
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
    }
}
