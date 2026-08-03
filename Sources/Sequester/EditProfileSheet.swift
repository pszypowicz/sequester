import SwiftUI
import SequesterCore

/// Renames a profile. Everything else about a profile is changed directly
/// on its page.
struct EditProfileSheet: View {

    @Environment(ProfileStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    let profile: ProfileMetadata
    let onRename: (String) -> Void

    @State private var name: String
    @State private var errorMessage: String?

    init(profile: ProfileMetadata, onRename: @escaping (String) -> Void) {
        self.profile = profile
        self.onRename = onRename
        _name = State(initialValue: profile.name)
    }

    var body: some View {
        SheetScaffold(primaryTitle: "Save", primaryDisabled: name.isEmpty,
                      error: errorMessage, size: CGSize(width: 420, height: 200),
                      onPrimary: save) {
            Section {
                TextField("Name", text: $name)
            } footer: {
                Text("Scripts and shell commands referring to the old name stop resolving; update them to the new name.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func save() {
        do {
            if name != profile.name {
                try store.rename(name: profile.name, to: name)
                onRename(name)
            }
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
