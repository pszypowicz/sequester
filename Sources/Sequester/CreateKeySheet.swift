import SwiftUI
import SequesterCore

struct CreateKeySheet: View {

    @Environment(KeyStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var keyDescription = ""
    @State private var comment = ""
    @State private var authRequired = true
    @State private var errorMessage: String?

    var body: some View {
        SheetScaffold(primaryTitle: "Create", primaryDisabled: name.isEmpty,
                      error: errorMessage, size: CGSize(width: 460, height: 380),
                      onPrimary: create) {
            Section {
                TextField("Name", text: $name, prompt: Text("e.g. github"))
                TextField("Description", text: $keyDescription, prompt: Text("optional"))
                TextField("Comment", text: $comment,
                          prompt: Text("\(name.isEmpty ? "name" : name)@sequester"))
            }
            Section {
                Toggle("Require Touch ID for every signature", isOn: $authRequired)
            } footer: {
                Text("The Touch ID requirement is baked into the key at creation and is permanent. Name, description, and comment can be changed anytime, and the public key filename is derived from the key itself, so renaming never breaks SSH config. Approval settings live on the key's page.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func create() {
        do {
            try store.create(name: name, description: keyDescription, authRequired: authRequired,
                             comment: comment.isEmpty ? nil : comment)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
