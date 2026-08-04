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
    @AppStorage(NotificationSettings.Key.secretsReadSilently)
    private var secretsReadSilently = NotificationSettings.Default.secretsReadSilently
    @AppStorage(NotificationSettings.Key.secretsReadAfterPrompt)
    private var secretsReadAfterPrompt = NotificationSettings.Default.secretsReadAfterPrompt
    @AppStorage(NotificationSettings.Key.secretsChanged)
    private var secretsChanged = NotificationSettings.Default.secretsChanged
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
                NotificationToggle(title: NotificationWording.signedSilently.0,
                                   info: NotificationWording.signedSilently.1,
                                   isOn: silentBinding)
                NotificationToggle(title: NotificationWording.signedAfterPrompt.0,
                                   info: NotificationWording.signedAfterPrompt.1,
                                   isOn: $signedAfterPrompt)
                NotificationToggle(title: NotificationWording.signedNewDestination.0,
                                   info: NotificationWording.signedNewDestination.1,
                                   isOn: $signedNewDestination)
                NotificationToggle(title: NotificationWording.refusedAppBlocked.0,
                                   info: NotificationWording.refusedAppBlocked.1,
                                   isOn: $refusedAppBlocked)
                NotificationToggle(title: NotificationWording.refusedDestinationBlocked.0,
                                   info: NotificationWording.refusedDestinationBlocked.1,
                                   isOn: $refusedDestinationBlocked)
                NotificationToggle(title: NotificationWording.refusedKeyLocked.0,
                                   info: NotificationWording.refusedKeyLocked.1,
                                   isOn: $refusedKeyLocked)
            } header: {
                Text("Notifications: keys")
            } footer: {
                Text("A refused request tells the terminal only that the agent refused the operation, and a signature with no prompt shows nothing at all, so these notifications are the only account of what the agent did. A key can set its own on its page.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section {
                NotificationToggle(title: NotificationWording.secretsReadSilently.0,
                                   info: NotificationWording.secretsReadSilently.1,
                                   isOn: $secretsReadSilently)
                NotificationToggle(title: NotificationWording.secretsReadAfterPrompt.0,
                                   info: NotificationWording.secretsReadAfterPrompt.1,
                                   isOn: $secretsReadAfterPrompt)
                NotificationToggle(title: NotificationWording.secretsChanged.0,
                                   info: NotificationWording.secretsChanged.1,
                                   isOn: $secretsChanged)
            } header: {
                Text("Notifications: secrets profiles")
            } footer: {
                Text("A profile can set its own on its page.")
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
