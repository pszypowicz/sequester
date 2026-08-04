import SwiftUI
import UserNotifications
import SequesterCore

/// The first page of settings, shown when no key is selected: agent state,
/// app options, and how to point ssh at the agent.
struct SetupView: View {

    @AppStorage("showMenuBarIcon") private var showMenuBarIcon = true
    @AppStorage(NotificationSettings.Key.signedSilently)
    private var signedSilently = NotificationSettings.Default.signedSilently
    @AppStorage(NotificationSettings.Key.signedAfterPrompt)
    private var signedAfterPrompt = NotificationSettings.Default.signedAfterPrompt
    @AppStorage(NotificationSettings.Key.signedNewDestination)
    private var signedNewDestination = NotificationSettings.Default.signedNewDestination
    @AppStorage(NotificationSettings.Key.refusedAppBlocked)
    private var refusedAppBlocked = NotificationSettings.Default.refusedAppBlocked
    @AppStorage(NotificationSettings.Key.refusedDestinationBlocked)
    private var refusedDestinationBlocked = NotificationSettings.Default.refusedDestinationBlocked
    @AppStorage(NotificationSettings.Key.refusedKeyLocked)
    private var refusedKeyLocked = NotificationSettings.Default.refusedKeyLocked
    @State private var confirmSilentOff = false
    @State private var systemNotificationsOff = false
    @State private var loginEnabled = LoginItem.isEnabled
    @State private var snippetFlash = CopyFlash()

    private var cliPath: String {
        Bundle.main.bundleURL.appending(path: "Contents/MacOS/sequester-cli").path
    }

    private var snippet: String {
        """
        Host *
            IdentityAgent \(SequesterPaths.socketURL.path)

        Host myserver
            HostName myserver.example.com
            IdentityFile \(SequesterPaths.directory.path)/<key file>.pub
            IdentitiesOnly yes
        """
    }

    var body: some View {
        Form {
            Section("Agent") {
                CopyRow(icon: "link", label: "Socket path", value: SequesterPaths.socketURL.path)
            }

            Section {
                CopyRow(icon: "terminal", label: "Bundled CLI", value: cliPath)
                CopyRow(icon: "link.badge.plus", label: "Put \u{201C}sequester\u{201D} on PATH",
                        value: "\"\(cliPath)\" install-cli")
            } header: {
                Text("Command line")
            } footer: {
                Text("The CLI manages secrets profiles (sequester secret, sequester env) by talking to this app; install-cli symlinks it into /usr/local/bin.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("App") {
                Toggle("Start at login", isOn: $loginEnabled)
                    .onChange(of: loginEnabled) { _, enabled in
                        do {
                            try LoginItem.setEnabled(enabled)
                        } catch {
                            loginEnabled = LoginItem.isEnabled
                        }
                    }
                Toggle("Show menu bar icon", isOn: $showMenuBarIcon)
                if !showMenuBarIcon {
                    Text("With the icon hidden, open the app again (Finder, Spotlight, or Launchpad) to get back to settings.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section {
                if systemNotificationsOff {
                    HStack(spacing: 6) {
                        Image(systemName: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                        Text("macOS is not delivering Sequester's notifications, so these settings have no effect.")
                            .font(.caption)
                        Button("Open System Settings") {
                            openNotificationSettings()
                        }
                        .font(.caption)
                    }
                }
                Toggle(isOn: silentBinding) {
                    settingLabel("Signed without any prompt",
                                 "A signature that showed no dialog and no Touch ID prompt. This notification is the only evidence such a use happened.")
                }
                Toggle(isOn: $signedAfterPrompt) {
                    settingLabel("Signed after a prompt",
                                 "A signature you just approved at a dialog or a Touch ID prompt, so the notification repeats what you have already seen.")
                }
                Toggle(isOn: $signedNewDestination) {
                    settingLabel("Signed for a new destination",
                                 "The first time a key signs for a host over a given route. Shown even when the two settings above are off.")
                }
                Toggle(isOn: $refusedAppBlocked) {
                    settingLabel("Refused: app blocked",
                                 "A request from an app you have blocked, refused before any prompt.")
                }
                Toggle(isOn: $refusedDestinationBlocked) {
                    settingLabel("Refused: destination blocked",
                                 "A request for a destination you have blocked, or a forwarded request to a key that refuses them.")
                }
                Toggle(isOn: $refusedKeyLocked) {
                    settingLabel("Refused: key locked",
                                 "A locked key asked to sign for a destination not on its list, which is how you learn it is being probed.")
                }
            } header: {
                Text("Notifications")
            } footer: {
                Text("A refused request tells the terminal only that the agent refused the operation, and a signature with no prompt shows nothing at all, so these notifications are the only account of what the agent did.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("SSH config") {
                Text("Add this to ~/.ssh/config. Each key's public half lives next to the socket (copy the exact path from the key's page), so per-host IdentityFile entries work the same way they do with plain key files.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(snippet)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button {
                    copyToPasteboard(snippet)
                    snippetFlash.trigger()
                } label: {
                    Label(snippetFlash.active ? "Copied" : "Copy Config Snippet",
                          systemImage: snippetFlash.active ? "checkmark" : "doc.on.doc")
                        .foregroundStyle(snippetFlash.active ? AnyShapeStyle(.green) : AnyShapeStyle(.tint))
                }
            }

            Section {
                Text("Sequester \(BuildMetadata.version) (\(BuildMetadata.gitHash))")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
        .formStyle(.grouped)
        .sheet(isPresented: $confirmSilentOff) {
            ConfirmSilentNotificationsOffSheet {
                signedSilently = false
            }
        }
        .onAppear {
            loginEnabled = LoginItem.isEnabled
            refreshNotificationAuthorization()
        }
    }

    /// Turning this one off is the only settings change that removes the
    /// sole account of a use, so it goes through a confirmation. Turning it
    /// back on is an ordinary write.
    private var silentBinding: Binding<Bool> {
        Binding(
            get: { signedSilently },
            set: { enabled in
                if enabled {
                    signedSilently = true
                } else {
                    confirmSilentOff = true
                }
            }
        )
    }

    private func settingLabel(_ title: String, _ info: String) -> some View {
        HStack(spacing: 4) {
            Text(title)
            InfoDot(text: info)
        }
    }

    private func refreshNotificationAuthorization() {
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            let delivering = settings.authorizationStatus == .authorized
                || settings.authorizationStatus == .provisional
            Task { @MainActor in
                systemNotificationsOff = !delivering
            }
        }
    }

    private func openNotificationSettings() {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension") else { return }
        NSWorkspace.shared.open(url)
    }

    private func copyToPasteboard(_ string: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
    }
}

/// Spells out what is lost before the only notification for an unprompted
/// signature is switched off.
private struct ConfirmSilentNotificationsOffSheet: View {

    @Environment(\.dismiss) private var dismiss
    let onConfirm: () -> Void

    var body: some View {
        SheetScaffold(primaryTitle: "Turn Off", primaryRole: .destructive,
                      size: CGSize(width: 440, height: 260),
                      onPrimary: {
                          onConfirm()
                          dismiss()
                      }) {
            Section {
                Text("A signature that shows no dialog and no Touch ID prompt leaves no other trace on screen. With this off, an approved app signing with an approved key does so with nothing to see, and the only record is the log.")
                    .font(.callout)
            } header: {
                Text("Stop announcing signatures that show no prompt?")
            }
        }
    }
}
