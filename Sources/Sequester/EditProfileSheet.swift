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

    private var checkedName: CheckedName {
        CheckedName(name, rule: ProfileName.validate)
    }

    var body: some View {
        SheetScaffold(primaryTitle: "Save", primaryDisabled: !checkedName.isUsable,
                      error: checkedName.message ?? errorMessage,
                      size: CGSize(width: 420, height: 200),
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
        let newName = checkedName.value
        do {
            if newName != profile.name {
                try store.rename(name: profile.name, to: newName)
                onRename(newName)
            }
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
