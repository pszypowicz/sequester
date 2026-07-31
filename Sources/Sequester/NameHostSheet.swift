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
        VStack(alignment: .leading, spacing: 0) {
            Form {
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
            .formStyle(.grouped)

            Divider()
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                Button("Save") {
                    hostNames.setName(name, for: fingerprint)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
            .padding()
        }
        .frame(width: 460, height: 230)
        .onAppear {
            name = hostNames.name(for: fingerprint) ?? ""
        }
    }
}
