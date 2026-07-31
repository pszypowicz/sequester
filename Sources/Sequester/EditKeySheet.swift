import SwiftUI
import SequesterCore

/// Edits a key's name and description. Everything else about a key is
/// either read-only or changed directly on its page.
struct EditKeySheet: View {

    @Environment(KeyStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    let key: KeyMetadata
    let onRename: (String) -> Void

    @State private var name: String
    @State private var keyDescription: String
    @State private var errorMessage: String?

    init(key: KeyMetadata, onRename: @escaping (String) -> Void) {
        self.key = key
        self.onRename = onRename
        _name = State(initialValue: key.name)
        _keyDescription = State(initialValue: key.keyDescription)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Form {
                Section {
                    TextField("Name", text: $name)
                    TextField("Description", text: $keyDescription, prompt: Text("optional"))
                } footer: {
                    Text("The public key filename is derived from the key itself, so renaming never breaks SSH config.")
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
                Button("Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(name.isEmpty)
            }
            .padding()
        }
        .frame(width: 420, height: 220)
    }

    private func save() {
        do {
            if name != key.name {
                try store.rename(name: key.name, to: name)
                onRename(name)
            }
            if keyDescription != key.keyDescription {
                try store.setDescription(name: name, description: keyDescription)
            }
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
