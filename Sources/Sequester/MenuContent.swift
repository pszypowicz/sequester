import SwiftUI
import SequesterCore

struct MenuContent: View {

    @Environment(AgentStatus.self) private var agentStatus
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if agentStatus.running {
            Text("Agent: running")
        } else {
            Text("Agent: \(agentStatus.error ?? "not running")")
        }

        Divider()

        Button("Settings…", systemImage: "gearshape") {
            NSApp.setActivationPolicy(.regular)
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }

        Toggle("Start at Login", isOn: loginBinding)

        Divider()

        Button("About Sequester", systemImage: "info.circle") {
            NSApp.activate(ignoringOtherApps: true)
            NSApp.orderFrontStandardAboutPanel(nil)
        }

        Button("Quit Sequester", systemImage: "power") {
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
