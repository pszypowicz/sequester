import SwiftUI
import SequesterCore

/// Confirms deleting a key by requiring its exact name to be typed. Destroying
/// a Secure Enclave key is irreversible - it cannot be exported or recovered -
/// so this guards against an accidental click.
struct DeleteKeySheet: View {

    @Environment(KeyStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    let key: KeyMetadata
    let onDeleted: () -> Void

    @State private var typed = ""
    @State private var errorMessage: String?

    private var matches: Bool {
        typed.trimmingCharacters(in: .whitespaces) == key.name
    }

    var body: some View {
        SheetScaffold(primaryTitle: "Delete", primaryRole: .destructive,
                      primaryDisabled: !matches, error: errorMessage,
                      size: CGSize(width: 440, height: 280), onPrimary: delete) {
            Section {
                TextField("Type the key name to confirm", text: $typed, prompt: Text(key.name))
            } header: {
                Text("Delete \u{201C}\(key.name)\u{201D}?")
            } footer: {
                Text("The Secure Enclave key is destroyed and its public key file is removed. Hosts using this key will stop accepting logins, and the key cannot be exported or recovered. This cannot be undone.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func delete() {
        do {
            try store.delete(name: key.name)
            onDeleted()
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
