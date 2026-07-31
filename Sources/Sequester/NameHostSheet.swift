import SwiftUI
import SequesterCore

/// A fingerprint being named, wrapped so it can drive a sheet.
struct NamingTarget: Identifiable {
    let id: String
}

/// Names a host key fingerprint. The name applies wherever that host
/// appears, for every key.
struct NameHostSheet: View {

    @Environment(HostNameStore.self) private var hostNames
    @Environment(\.dismiss) private var dismiss

    let fingerprint: String
    @State private var name = ""

    var body: some View {
        SheetScaffold(primaryTitle: "Save", size: CGSize(width: 460, height: 230)) {
            hostNames.setName(name, for: fingerprint)
            dismiss()
        } content: {
            Section {
                TextField("Name", text: $name, prompt: Text("e.g. github"))
                LabeledContent("Host key") {
                    Text(fingerprint)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            } footer: {
                Text("The name is shown wherever this host appears, for every key. Clearing it goes back to the fingerprint.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .onAppear {
            name = hostNames.name(for: fingerprint) ?? ""
        }
    }
}
