import AppKit
import Observation
import SequesterCore

@Observable
final class AgentStatus {
    var running = false
    var error: String?
}

final class AppDelegate: NSObject, NSApplicationDelegate {

    let agentStatus = AgentStatus()
    private var server: AgentServer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let agent = Agent(approver: DialogApprover())
        let server = AgentServer(socketPath: SequesterPaths.socketURL.path, agent: agent)
        do {
            try server.start()
            self.server = server
            agentStatus.running = true
        } catch {
            agentStatus.error = error.localizedDescription
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        server?.stop()
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        true
    }
}
