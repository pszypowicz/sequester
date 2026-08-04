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
                RememberWindow.picker(
                    selection: rememberBinding,
                    info: "After you confirm a read, later reads of this profile skip the confirmation until the window runs out. Locking the screen closes it, as does changing the profile. Off means every read confirms."
                )
                .disabled(profile.tier == .noPrompt)
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

            Section {
                FollowGlobalToggle(followsGlobal: followsGlobalNotificationsBinding)
                if profile.notifications != nil {
                    NotificationToggle(title: NotificationWording.secretsReadSilently.0,
                                       info: NotificationWording.secretsReadSilently.1,
                                       isOn: notificationBinding(\.readSilently))
                    NotificationToggle(title: NotificationWording.secretsReadAfterPrompt.0,
                                       info: NotificationWording.secretsReadAfterPrompt.1,
                                       isOn: notificationBinding(\.readAfterPrompt))
                }
            } header: {
                sectionHeader("Notifications", info: "Which of this profile's events are announced. Turning off the global settings switch gives this profile its own copy of them to edit.")
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

    /// Switching off takes a copy of the global settings as they stand, so
    /// the profile starts from what it was already doing.
    private var followsGlobalNotificationsBinding: Binding<Bool> {
        Binding(
            get: { profile.notifications == nil },
            set: { follows in
                writeNotifications(follows ? nil : NotificationSettings.current.profileOverride)
            }
        )
    }

    private func notificationBinding(_ field: WritableKeyPath<ProfileNotificationOverride, Bool>) -> Binding<Bool> {
        Binding(
            get: { profile.notifications?[keyPath: field] ?? true },
            set: { enabled in
                guard var override = profile.notifications else { return }
                override[keyPath: field] = enabled
                writeNotifications(override)
            }
        )
    }

    private func writeNotifications(_ override: ProfileNotificationOverride?) {
        do {
            try store.setNotifications(name: profile.name, override: override)
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private var rememberBinding: Binding<TimeInterval> {
        Binding(
            get: { profile.rememberSeconds },
            set: { seconds in
                do {
                    try store.setRememberSeconds(name: profile.name, seconds: seconds)
                    errorMessage = nil
                } catch {
                    errorMessage = error.localizedDescription
                }
            }
        )
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
