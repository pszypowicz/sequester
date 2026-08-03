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

    private var hasVariable: Bool {
        entries.contains { !$0.name.isEmpty && !$0.value.isEmpty }
    }

    var body: some View {
        SheetScaffold(primaryTitle: "Create", primaryDisabled: name.isEmpty || !hasVariable,
                      error: errorMessage, size: CGSize(width: 480, height: 520),
                      onPrimary: create) {
            Section {
                TextField("Name", text: $name, prompt: Text("e.g. deploy"))
            }
            Section {
                Picker("Touch ID", selection: $tier) {
                    ForEach(SecretTier.allCases, id: \.self) { tier in
                        Text(tier.displayLabel).tag(tier)
                    }
                }
                Toggle("Disable env export", isOn: $exportDisabled)
            } footer: {
                Text("The Touch ID choice is permanent. \u{201C}\(SecretTier.everyRead.displayLabel)\u{201D} is enforced by the Secure Enclave itself; the other tiers are enforced by Sequester in front of a key it could use without them. Disabling export keeps values off stdout, so they reach programs only through env exec.")
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
                        SecureField("Value", text: $entry.value)
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
        for entry in entries where !entry.name.isEmpty || !entry.value.isEmpty {
            guard !entry.name.isEmpty, !entry.value.isEmpty else {
                errorMessage = "Every variable needs a name and a value."
                return
            }
            guard values[entry.name] == nil else {
                errorMessage = "Variable \(entry.name) is listed twice."
                return
            }
            values[entry.name] = entry.value
        }
        do {
            try store.create(name: name, tier: tier, exportDisabled: exportDisabled, values: values)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
