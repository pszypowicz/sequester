import SwiftUI
import SequesterCore

struct KeyDetailView: View {

    @Environment(KeyStore.self) private var store

    let key: KeyMetadata
    @Binding var selection: SidebarItem?
    @State private var nameDraft: String
    @State private var descriptionDraft: String
    @State private var errorMessage: String?

    init(key: KeyMetadata, selection: Binding<SidebarItem?>) {
        self.key = key
        _selection = selection
        _nameDraft = State(initialValue: key.name)
        _descriptionDraft = State(initialValue: key.keyDescription)
    }

    var body: some View {
        Form {
            Section {
                TextField("Name", text: $nameDraft)
                    .onSubmit(saveName)
                if nameDraft != key.name {
                    Button("Save Name", action: saveName)
                }
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

            Section {
                LabeledContent("Created", value: key.createdAt.formatted(date: .abbreviated, time: .shortened))
                LabeledContent("Touch ID", value: key.authRequired ? "Required for every signature" : "Not required")
                LabeledContent("SHA256 fingerprint") {
                    CopyableText(text: key.fingerprint)
                }
                LabeledContent("MD5 fingerprint") {
                    CopyableText(text: key.fingerprintMD5)
                }
            }

            Section("Public key") {
                LabeledContent("File path") {
                    CopyableText(text: key.publicKeyFileURL.path)
                }
                LabeledContent("Public key") {
                    CopyableText(text: key.publicKeyLine)
                }
            }

            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
        .formStyle(.grouped)
    }

    private var policyBinding: Binding<SigningPolicy> {
        Binding(
            get: { key.policy },
            set: { newValue in attempt { try store.setPolicy(name: key.name, policy: newValue) } }
        )
    }

    private func saveName() {
        let newName = nameDraft
        attempt {
            try store.rename(name: key.name, to: newName)
            selection = .key(newName)
        }
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
}
