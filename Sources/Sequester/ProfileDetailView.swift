import SwiftUI
import SequesterCore
import SecretsWire

/// Read-only view of a secrets profile. The name is edited through the
/// sidebar row's Edit action, values through the Edit Values sheet; the
/// other settings change here. Values themselves are never displayed.
struct ProfileDetailView: View {

    @Environment(ProfileStore.self) private var store
    @Environment(AppAuthStore.self) private var appAuth

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
                Toggle(isOn: approveAllBinding) {
                    settingLabel("Read without asking",
                                 "Hands values to callers you have not authorized, without a dialog. Blocked apps are still denied, and a \u{201C}\(SecretTier.everyRead.displayLabel)\u{201D} profile still prompts in the Enclave. For automation that cannot answer dialogs.")
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

            Section {
                if profile.appRules.isEmpty {
                    Text("No per-profile overrides. This profile uses the global app authorizations.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(profile.appRules) { rule in
                        HStack(spacing: 10) {
                            Image(systemName: rule.state == .blocked ? "xmark.shield.fill" : "checkmark.shield.fill")
                                .foregroundStyle(rule.state == .blocked ? .red : .green)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(rule.displayName)
                                Text(rule.identity)
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                            Spacer()
                            Picker("", selection: appRuleBinding(rule)) {
                                Text("Allowed").tag(AppState.allowed)
                                Text("Blocked").tag(AppState.blocked)
                            }
                            .pickerStyle(.segmented)
                            .fixedSize()
                            Button {
                                store.removeAppRule(name: profile.name, identity: rule.identity)
                            } label: {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.borderless)
                        }
                        .padding(.vertical, 2)
                    }
                }
                let candidates = appAuth.secrets.filter { auth in
                    !profile.appRules.contains { $0.identity == auth.identity }
                }
                if !candidates.isEmpty {
                    Menu("Add override…") {
                        ForEach(candidates) { auth in
                            Menu(auth.displayName) {
                                Button("Allow for this profile") {
                                    store.setAppRule(name: profile.name, identity: auth.identity,
                                                     displayName: auth.displayName, state: .allowed)
                                }
                                Button("Block for this profile") {
                                    store.setAppRule(name: profile.name, identity: auth.identity,
                                                     displayName: auth.displayName, state: .blocked)
                                }
                            }
                        }
                    }
                }
            } header: {
                sectionHeader("App overrides", info: "Override the global authorization of a specific app for this profile only. The app is the terminal or IDE the read was started from, not the CLI itself.")
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
            "\(profile.tier.enforcementLabel): the requirement is baked into the Enclave key's access control, so even an approved app costs a tap."
        case .unapprovedOnly:
            "\(profile.tier.enforcementLabel): approved apps read silently; everyone else must pass a Touch ID check the app evaluates before decrypting."
        case .policyOnly:
            "\(profile.tier.enforcementLabel): unknown apps get an approval dialog, with no biometric check."
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

    private var approveAllBinding: Binding<Bool> {
        Binding(
            get: { profile.approveAll },
            set: { enabled in
                do {
                    try store.setApproveAll(name: profile.name, enabled: enabled)
                    errorMessage = nil
                } catch {
                    errorMessage = error.localizedDescription
                }
            }
        )
    }

    private func appRuleBinding(_ rule: AppRule) -> Binding<AppState> {
        Binding(
            get: { rule.state },
            set: { store.setAppRule(name: profile.name, identity: rule.identity,
                                    displayName: rule.displayName, state: $0) }
        )
    }
}
