import SwiftUI
import SequesterCore

/// Edits a profile's values: existing variables can get a new value or be
/// removed, and new variables can be added. Values are write-only here; the
/// current ones are never displayed.
struct EditProfileValuesSheet: View {

    @Environment(ProfileStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    let profile: ProfileMetadata

    @State private var existing: [ExistingEntry]
    @State private var added: [NewEntry] = []
    @State private var errorMessage: String?

    struct ExistingEntry: Identifiable {
        let id: String
        var value = ""
        var removed = false
    }

    struct NewEntry: Identifiable {
        let id = UUID()
        var name = ""
        var value = ""
    }

    init(profile: ProfileMetadata) {
        self.profile = profile
        _existing = State(initialValue: profile.variableNames.map { ExistingEntry(id: $0) })
    }

    private var hasChange: Bool {
        existing.contains { $0.removed || !$0.value.isEmpty }
            || added.contains { !$0.name.isEmpty || !$0.value.isEmpty }
    }

    var body: some View {
        SheetScaffold(primaryTitle: "Save", primaryDisabled: !hasChange,
                      error: errorMessage, size: CGSize(width: 480, height: 440),
                      onPrimary: save) {
            Section {
                VariableColumnHeader()
                ForEach($existing) { $entry in
                    HStack(spacing: 8) {
                        Text(entry.id)
                            .font(.system(.body, design: .monospaced))
                            .strikethrough(entry.removed)
                            .foregroundStyle(entry.removed ? .secondary : .primary)
                            .frame(width: VariableColumnHeader.nameWidth, alignment: .leading)
                        Divider()
                        SecureField("Value", text: $entry.value, prompt: Text("Leave blank to keep"))
                            .labelsHidden()
                            .disabled(entry.removed)
                        Button {
                            entry.removed.toggle()
                        } label: {
                            Image(systemName: entry.removed ? "arrow.uturn.backward" : "trash")
                        }
                        .buttonStyle(.borderless)
                        .help(entry.removed ? "Keep this variable" : "Remove this variable")
                    }
                }
                ForEach($added) { $entry in
                    HStack(spacing: 8) {
                        TextField("Name", text: $entry.name, prompt: Text("GITHUB_TOKEN"))
                            .labelsHidden()
                            .font(.system(.body, design: .monospaced))
                            .frame(width: VariableColumnHeader.nameWidth)
                        Divider()
                        SecureField("Value", text: $entry.value, prompt: Text("ghp_example"))
                            .labelsHidden()
                        Button {
                            added.removeAll { $0.id == entry.id }
                        } label: {
                            Image(systemName: "trash")
                        }
                        .buttonStyle(.borderless)
                    }
                }
                Button {
                    added.append(NewEntry())
                } label: {
                    Label("Add Variable", systemImage: "plus")
                }
            } header: {
                Text("Variables")
            } footer: {
                Text(profile.tier == .everyRead
                     ? "Saving decrypts and re-encrypts the profile, so it costs one Touch ID prompt."
                     : "Saving decrypts and re-encrypts the profile.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func save() {
        var setting: [String: String] = [:]
        var removing: Set<String> = []
        for entry in existing {
            if entry.removed {
                removing.insert(entry.id)
            } else if !entry.value.isEmpty {
                setting[entry.id] = entry.value
            }
        }
        for entry in added where !entry.name.isEmpty || !entry.value.isEmpty {
            guard !entry.name.isEmpty, !entry.value.isEmpty else {
                errorMessage = "Every new variable needs a name and a value."
                return
            }
            guard setting[entry.name] == nil else {
                errorMessage = "Variable \(entry.name) is listed twice."
                return
            }
            setting[entry.name] = entry.value
        }
        do {
            try store.updateValues(name: profile.name, setting: setting, removing: removing)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
