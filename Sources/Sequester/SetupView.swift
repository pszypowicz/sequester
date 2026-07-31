import SwiftUI
import SequesterCore

/// The first page of settings, shown when no key is selected: agent state,
/// app options, and how to point ssh at the agent.
struct SetupView: View {

    @Environment(AgentStatus.self) private var agentStatus
    @AppStorage("showMenuBarIcon") private var showMenuBarIcon = true
    @State private var loginEnabled = LoginItem.isEnabled

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
                LabeledContent("Status") {
                    if agentStatus.running {
                        Label("Running", systemImage: "circle.fill")
                            .foregroundStyle(.green)
                    } else {
                        Label(agentStatus.error ?? "Not running", systemImage: "circle.fill")
                            .foregroundStyle(.red)
                    }
                }
                CopyRow(icon: "link", label: "Socket path", value: SequesterPaths.socketURL.path)
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

            Section("ssh config") {
                Text("Add this to ~/.ssh/config. Each key's public half lives next to the socket under a filename derived from the key itself (copy the exact path from the key's page), so per-host IdentityFile entries work the same way they do with plain key files and survive renames.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(snippet)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button("Copy Config Snippet") {
                    copyToPasteboard(snippet)
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
