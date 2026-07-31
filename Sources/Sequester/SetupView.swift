import SwiftUI
import SequesterCore

/// Shown when no key is selected: how to point ssh at the agent.
struct SetupView: View {

    private var snippet: String {
        """
        Host *
            IdentityAgent \(SequesterPaths.socketURL.path)

        Host myserver
            HostName myserver.example.com
            IdentityFile \(SequesterPaths.directory.path)/<name>.pub
            IdentitiesOnly yes
        """
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Setup")
                .font(.title2.bold())
            Text("Point ssh at the agent socket in ~/.ssh/config. Each key's public half lives at ~/.sequester/<name>.pub, so per-host IdentityFile entries work the same way they do with plain key files.")
                .foregroundStyle(.secondary)
            GroupBox {
                Text(snippet)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(4)
            }
            Button("Copy Config Snippet") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(snippet, forType: .string)
            }
            Spacer()
            Text("Sequester \(BuildMetadata.version) (\(BuildMetadata.gitHash))")
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}
