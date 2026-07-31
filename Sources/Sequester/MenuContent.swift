import SwiftUI
import SequesterCore

struct MenuContent: View {

    @Environment(AgentStatus.self) private var agentStatus
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button("Open Sequester") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }

        Divider()

        if agentStatus.running {
            Text("Agent: running")
        } else {
            Text("Agent: \(agentStatus.error ?? "not running")")
        }
        Button("Copy Socket Path") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(SequesterPaths.socketURL.path, forType: .string)
        }

        Divider()

        Toggle("Start at Login", isOn: loginBinding)

        Divider()

        Button("Quit Sequester") {
            NSApp.terminate(nil)
        }
    }

    private var loginBinding: Binding<Bool> {
        Binding(
            get: { LoginItem.isEnabled },
            set: { enabled in try? LoginItem.setEnabled(enabled) }
        )
    }
}
