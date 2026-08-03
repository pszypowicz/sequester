import SwiftUI
import SequesterCore

/// Drives the brief "copied" confirmation after a copy action: flips on
/// with a quick ease-in, then fades back out after a second. Re-triggering
/// restarts the timer.
@MainActor
@Observable
final class CopyFlash {

    private(set) var active = false
    @ObservationIgnored private var reset: Task<Void, Never>?

    func trigger() {
        reset?.cancel()
        withAnimation(.easeIn(duration: 0.1)) { active = true }
        reset = Task { [weak self] in
            try? await Task.sleep(for: .seconds(1))
            guard !Task.isCancelled else { return }
            withAnimation(.easeOut(duration: 0.4)) { self?.active = false }
        }
    }
}

/// A two-row form field: an icon-and-label header with action buttons at
/// the trailing edge (reveal in Finder when a URL is given, always copy),
/// then the value itself on its own line. Copying confirms itself with a
/// checkmark and a brief highlight of the row.
struct CopyRow: View {

    let icon: String
    let label: String
    let value: String
    var revealURL: URL?

    @State private var flash = CopyFlash()

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
                    flash.trigger()
                } label: {
                    Image(systemName: flash.active ? "checkmark" : "doc.on.doc")
                        .foregroundStyle(flash.active ? AnyShapeStyle(.green) : AnyShapeStyle(.tint))
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
        .padding(.horizontal, 4)
        .background(flash.active ? Color.green.opacity(0.12) : Color.clear,
                    in: RoundedRectangle(cornerRadius: 4))
        .padding(.horizontal, -4)
    }
}
