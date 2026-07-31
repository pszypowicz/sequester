import SwiftUI
import SequesterCore

/// Read-only view of a key. Name and description are edited through the
/// sidebar row's Edit action; only the behavior policy changes here.
struct KeyDetailView: View {

    @Environment(KeyStore.self) private var store

    let key: KeyMetadata
    @State private var errorMessage: String?

    var body: some View {
        Form {
            Section {
                LabeledContent("Name", value: key.name)
                if !key.keyDescription.isEmpty {
                    LabeledContent("Description", value: key.keyDescription)
                }
                LabeledContent("Created", value: key.createdAt.formatted(date: .abbreviated, time: .shortened))
                LabeledContent("Touch ID", value: key.authRequired ? "Required for every signature" : "Not required")
                Picker("Behavior", selection: policyBinding) {
                    ForEach(SigningPolicy.allCases, id: \.self) { policy in
                        Text(policy.displayName).tag(policy)
                    }
                }
            }

            Section("Public key") {
                CopyRow(icon: "doc.text", label: "Public key path", value: key.publicKeyFileURL.path, revealURL: key.publicKeyFileURL)
                CopyRow(icon: "key", label: "Public key", value: key.publicKeyLine)
                CopyRow(icon: "touchid", label: "SHA256 fingerprint", value: key.fingerprint)
                CopyRow(icon: "touchid", label: "MD5 fingerprint", value: key.fingerprintMD5)
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
            set: { newValue in
                do {
                    try store.setPolicy(name: key.name, policy: newValue)
                    errorMessage = nil
                } catch {
                    errorMessage = error.localizedDescription
                }
            }
        )
    }
}
