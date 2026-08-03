import SwiftUI
import SequesterCore

/// The first page of settings, shown when no key is selected: agent state,
/// app options, and how to point ssh at the agent.
struct SetupView: View {

    @AppStorage("showMenuBarIcon") private var showMenuBarIcon = true
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
        .onAppear {
            loginEnabled = LoginItem.isEnabled
        }
    }

    private func copyToPasteboard(_ string: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
    }
}
