import SwiftUI
import SequesterCore

struct MenuContent: View {

    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button("Settings…", systemImage: "gearshape") {
            Navigator.shared.showSettings()
        }

        Divider()

        Button("About Sequester", systemImage: "info.circle") {
            openWindow(id: "about")
            NSApp.activate(ignoringOtherApps: true)
        }

        Button("Quit Sequester", systemImage: "power") {
            NSApp.terminate(nil)
        }
    }
}
