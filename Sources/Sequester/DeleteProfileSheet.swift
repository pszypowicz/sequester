import SwiftUI
import SequesterCore

/// Confirms deleting a profile by requiring its exact name to be typed. The
/// keychain item holds the only copies of the Enclave key handle and the
/// ciphertext, so deletion is irreversible.
struct DeleteProfileSheet: View {

    @Environment(ProfileStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    let profile: ProfileMetadata
    let onDeleted: () -> Void

    @State private var typed = ""
    @State private var errorMessage: String?

    private var matches: Bool {
        typed.trimmingCharacters(in: .whitespaces) == profile.name
    }

    var body: some View {
        SheetScaffold(primaryTitle: "Delete", primaryRole: .destructive,
                      primaryDisabled: !matches, error: errorMessage,
                      size: CGSize(width: 440, height: 260), onPrimary: delete) {
            Section {
                TextField("Type the profile name to confirm", text: $typed, prompt: Text(profile.name))
            } header: {
                Text("Delete \u{201C}\(profile.name)\u{201D}?")
            } footer: {
                Text("The Secure Enclave key and the encrypted values are destroyed together. The values cannot be exported or recovered. This cannot be undone.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func delete() {
        do {
            try store.delete(name: profile.name)
            onDeleted()
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
