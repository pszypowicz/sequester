import SwiftUI
import SequesterCore
import SecretsWire

struct CreateProfileSheet: View {

    @Environment(ProfileStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var tier: SecretTier = .everyRead
    @State private var exportDisabled = false
    @State private var entries: [VariableEntry] = [VariableEntry()]
    @State private var errorMessage: String?

    struct VariableEntry: Identifiable {
        let id = UUID()
        var name = ""
        var value = ""
    }

    private var checkedName: CheckedName {
        CheckedName(name, rule: ProfileName.validate)
    }

    /// The first variable name that breaks the rule, so a bad one is named
    /// as it is typed rather than when the sheet submits.
    private var variableMessage: String? {
        for entry in entries {
            if let message = CheckedName(entry.name, rule: EnvName.validate).message {
                return message
            }
        }
        return nil
    }

    private var hasVariable: Bool {
        entries.contains { !CheckedName.trimmed($0.name).isEmpty && !$0.value.isEmpty }
    }

    var body: some View {
        SheetScaffold(primaryTitle: "Create",
                      primaryDisabled: !checkedName.isUsable || variableMessage != nil || !hasVariable,
                      error: checkedName.message ?? variableMessage ?? errorMessage,
                      size: CGSize(width: 480, height: 520),
                      onPrimary: create) {
            Section {
                TextField("Name", text: $name, prompt: Text("e.g. deploy"))
            }
            Section {
                Picker("Confirmation", selection: $tier) {
                    ForEach(SecretTier.allCases, id: \.self) { tier in
                        Text(tier.displayLabel).tag(tier)
                    }
                }
                Toggle("Disable env export", isOn: $exportDisabled)
            } footer: {
                Text("The confirmation choice is permanent. \u{201C}\(SecretTier.everyRead.displayLabel)\u{201D} is enforced by the Secure Enclave itself; the other choices are enforced by Sequester in front of a key it could use without them. Every read posts a notification whichever you pick. Disabling export keeps values off stdout, so they reach programs only through env exec.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section {
                VariableColumnHeader()
                ForEach($entries) { $entry in
                    HStack(spacing: 8) {
                        TextField("Name", text: $entry.name, prompt: Text("GITHUB_TOKEN"))
                            .labelsHidden()
                            .font(.system(.body, design: .monospaced))
                            .frame(width: VariableColumnHeader.nameWidth)
                        Divider()
                        SecureField("Value", text: $entry.value, prompt: Text("ghp_example"))
                            .labelsHidden()
                        Button {
                            entries.removeAll { $0.id == entry.id }
                        } label: {
                            Image(systemName: "trash")
                        }
                        .buttonStyle(.borderless)
                        .disabled(entries.count == 1)
                    }
                }
                Button {
                    entries.append(VariableEntry())
                } label: {
                    Label("Add Variable", systemImage: "plus")
                }
            } header: {
                Text("Variables")
            }
        }
    }

    private func create() {
        var values: [String: String] = [:]
        // Only the name is trimmed. A value is a secret, and stripping a
        // character the token really carries would break it silently.
        for entry in entries {
            let variable = CheckedName.trimmed(entry.name)
            guard !variable.isEmpty || !entry.value.isEmpty else { continue }
            guard !variable.isEmpty, !entry.value.isEmpty else {
                errorMessage = "Every variable needs a name and a value."
                return
            }
            guard values[variable] == nil else {
                errorMessage = "Variable \(variable) is listed twice."
                return
            }
            values[variable] = entry.value
        }
        do {
            try store.create(name: checkedName.value, tier: tier, exportDisabled: exportDisabled,
                             values: values)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
