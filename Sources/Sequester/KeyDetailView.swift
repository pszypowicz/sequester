import SwiftUI
import SequesterCore

struct KeyDetailView: View {

    @Environment(KeyStore.self) private var store

    let key: KeyMetadata
    @State private var descriptionDraft: String
    @State private var confirmDelete = false
    @State private var errorMessage: String?

    init(key: KeyMetadata) {
        self.key = key
        _descriptionDraft = State(initialValue: key.keyDescription)
    }

    var body: some View {
        Form {
            Section {
                LabeledContent("Name", value: key.name)
                LabeledContent("Fingerprint", value: key.fingerprint)
                LabeledContent("Created", value: key.createdAt.formatted(date: .abbreviated, time: .shortened))
                LabeledContent("Touch ID", value: key.authRequired ? "Required for every signature" : "Not required")
            }

            Section {
                TextField("Description", text: $descriptionDraft, prompt: Text("optional"))
                    .onSubmit(saveDescription)
                if descriptionDraft != key.keyDescription {
                    Button("Save Description", action: saveDescription)
                }
                Picker("Behavior", selection: policyBinding) {
                    ForEach(SigningPolicy.allCases, id: \.self) { policy in
                        Text(policy.displayName).tag(policy)
                    }
                }
            }

            Section("Public key") {
                Text(key.publicKeyLine)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .lineLimit(3)
                HStack {
                    Button("Copy Public Key") {
                        copyToPasteboard(key.publicKeyLine)
                    }
                    Button("Copy File Path") {
                        copyToPasteboard(SequesterPaths.publicKeyURL(name: key.name).path)
                    }
                }
            }

            Section {
                Button("Delete Key…", role: .destructive) {
                    confirmDelete = true
                }
            }

            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
        .formStyle(.grouped)
        .confirmationDialog(
            "Delete \"\(key.name)\"?",
            isPresented: $confirmDelete
        ) {
            Button("Delete", role: .destructive) {
                attempt { try store.delete(name: key.name) }
            }
        } message: {
            Text("The Secure Enclave key is destroyed and \(key.name).pub is removed. Hosts using this key will stop accepting logins. This cannot be undone.")
        }
    }

    private var policyBinding: Binding<SigningPolicy> {
        Binding(
            get: { key.policy },
            set: { newValue in attempt { try store.setPolicy(name: key.name, policy: newValue) } }
        )
    }

    private func saveDescription() {
        attempt { try store.setDescription(name: key.name, description: descriptionDraft) }
    }

    private func attempt(_ body: () throws -> Void) {
        do {
            try body()
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func copyToPasteboard(_ string: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
    }
}
