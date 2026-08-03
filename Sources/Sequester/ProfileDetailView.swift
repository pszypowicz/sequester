import SwiftUI
import SequesterCore
import SecretsWire

/// Read-only view of a secrets profile. The name is edited through the
/// sidebar row's Edit action, values through the Edit Values sheet; the
/// other settings change here. Values themselves are never displayed.
struct ProfileDetailView: View {

    @Environment(ProfileStore.self) private var store

    let profile: ProfileMetadata
    @State private var errorMessage: String?
    @State private var editingValues = false

    private var cliPath: String {
        Bundle.main.bundleURL.appending(path: "Contents/MacOS/sequester-cli").path
    }

    var body: some View {
        Form {
            Section {
                LabeledContent("Name", value: profile.name)
                LabeledContent("Security") {
                    HStack(spacing: 4) {
                        Text(profile.tier.displayLabel)
                        InfoDot(text: enforcementInfo)
                    }
                }
                LabeledContent("Created", value: profile.createdAt.formatted(date: .abbreviated, time: .shortened))
                LabeledContent("Updated", value: profile.updatedAt.formatted(date: .abbreviated, time: .shortened))
            }

            Section("Access") {
                Toggle(isOn: exportDisabledBinding) {
                    settingLabel("Disable env export",
                                 "Refuses reads made for env export, so values never land on stdout where a transcript or an AI agent's context would capture them. env exec still works. This guards against accidents; a caller controls what it declares.")
                }
            }

            Section {
                if profile.variableNames.isEmpty {
                    Text("No variables")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(profile.variableNames, id: \.self) { name in
                        Text(name)
                            .font(.system(.body, design: .monospaced))
                    }
                }
                Button("Edit Values…") {
                    editingValues = true
                }
            } header: {
                sectionHeader("Variables", info: "Only the names are stored in the clear; the values live in the encrypted blob and are shown nowhere.")
            }

            Section("Use from the terminal") {
                CopyRow(icon: "terminal", label: "Run a command with these values",
                        value: "sequester env exec \(profile.name) -- <command>")
                if !profile.exportDisabled {
                    CopyRow(icon: "square.and.arrow.up", label: "Print export lines",
                            value: "sequester env export \(profile.name)")
                }
            }

            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
            }

        }
        .formStyle(.grouped)
        .sheet(isPresented: $editingValues) {
            EditProfileValuesSheet(profile: profile)
        }
    }

    private var enforcementInfo: String {
        switch profile.tier {
        case .everyRead:
            "\(profile.tier.enforcementLabel): the requirement is baked into the Enclave key's access control, so every read costs a tap."
        case .confirmEveryRead:
            "\(profile.tier.enforcementLabel): Sequester asks in a dialog before decrypting, and the dialog can waive the next few minutes."
        case .noPrompt:
            "\(profile.tier.enforcementLabel): reads proceed without confirmation. Every read still posts a notification."
        }
    }

    private func settingLabel(_ title: String, _ info: String) -> some View {
        HStack(spacing: 4) {
            Text(title)
            InfoDot(text: info)
        }
    }

    private func sectionHeader(_ title: String, info: String) -> some View {
        HStack(spacing: 4) {
            Text(title)
            InfoDot(text: info)
        }
    }

    private var exportDisabledBinding: Binding<Bool> {
        Binding(
            get: { profile.exportDisabled },
            set: { disabled in
                do {
                    try store.setExportDisabled(name: profile.name, disabled: disabled)
                    errorMessage = nil
                } catch {
                    errorMessage = error.localizedDescription
                }
            }
        )
    }
}
