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
    @State private var comment: String
    @State private var errorMessage: String?

    init(key: KeyMetadata, onRename: @escaping (String) -> Void) {
        self.key = key
        self.onRename = onRename
        _name = State(initialValue: key.name)
        _keyDescription = State(initialValue: key.keyDescription)
        _comment = State(initialValue: key.comment ?? "")
    }

    var body: some View {
        SheetScaffold(primaryTitle: "Save", primaryDisabled: name.isEmpty,
                      error: errorMessage, size: CGSize(width: 420, height: 260),
                      onPrimary: save) {
            Section {
                TextField("Name", text: $name)
                TextField("Description", text: $keyDescription, prompt: Text("optional"))
                TextField("Comment", text: $comment,
                          prompt: Text("\(name.isEmpty ? "name" : name)@sequester"))
            } footer: {
                Text("The public key comment defaults to name@sequester.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
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
            if comment != (key.comment ?? "") {
                try store.setComment(name: name, comment: comment.isEmpty ? nil : comment)
            }
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
