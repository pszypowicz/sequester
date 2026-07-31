import SwiftUI
import SequesterCore

struct MenuContent: View {

    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button("Settings…", systemImage: "gearshape") {
            NSApp.setActivationPolicy(.regular)
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }

        Divider()

        Button("About Sequester", systemImage: "info.circle") {
            NSApp.activate(ignoringOtherApps: true)
            NSApp.orderFrontStandardAboutPanel(nil)
        }

        Button("Quit Sequester", systemImage: "power") {
            NSApp.terminate(nil)
        }
    }
}
