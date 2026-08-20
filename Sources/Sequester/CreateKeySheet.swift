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

    private var checkedName: CheckedName {
        CheckedName(name, rule: KeyName.validate)
    }

    var body: some View {
        SheetScaffold(primaryTitle: "Create", primaryDisabled: !checkedName.isUsable,
                      error: checkedName.message ?? errorMessage,
                      size: CGSize(width: 460, height: 380),
                      onPrimary: create) {
            Section {
                TextField("Name", text: $name, prompt: Text("e.g. github"))
                TextField("Description", text: $keyDescription, prompt: Text("optional"))
                TextField("Comment", text: $comment,
                          prompt: Text("\(checkedName.value.isEmpty ? "name" : checkedName.value)@sequester"))
            }
            Section {
                Toggle("Require Touch ID for every signature", isOn: $authRequired)
            } footer: {
                Text("The Touch ID requirement is baked into the key at creation and is permanent. Name, description, and comment can be changed anytime. Approval settings live on the key's page.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func create() {
        // The comment becomes the tail of the public key line, where a
        // trailing space is as invisible as it is in the field.
        let trimmedComment = CheckedName.trimmed(comment)
        do {
            try store.create(name: checkedName.value, description: keyDescription,
                             authRequired: authRequired,
                             comment: trimmedComment.isEmpty ? nil : trimmedComment)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
