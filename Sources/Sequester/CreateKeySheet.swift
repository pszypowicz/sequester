import SwiftUI
import SequesterCore

struct CreateKeySheet: View {

    @Environment(KeyStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var keyDescription = ""
    @State private var authRequired = true
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Form {
                Section {
                    TextField("Name", text: $name, prompt: Text("e.g. github"))
                    TextField("Description", text: $keyDescription, prompt: Text("optional"))
                }
                Section {
                    Toggle("Require Touch ID for every signature", isOn: $authRequired)
                } footer: {
                    Text("The Touch ID requirement is baked into the key at creation and is permanent. Name and description can be changed anytime; the public key filename is derived from the key itself, so renaming never breaks SSH config. Approval settings live on the key's page.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                if let errorMessage {
                    Text(errorMessage)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                Button("Create") { create() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(name.isEmpty)
            }
            .padding()
        }
        .frame(width: 460, height: 340)
    }

    private func create() {
        do {
            try store.create(name: name, description: keyDescription, authRequired: authRequired)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
