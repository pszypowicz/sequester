import Foundation
import Observation
import SequesterCore

/// UI-facing view of the host names, which live outside key metadata
/// because a host is the same host for every key that reaches it.
@MainActor
@Observable
final class HostNameStore {

    private(set) var names: [String: String] = HostNames.shared.all()
    private var observer: (any NSObjectProtocol)?

    init() {
        // Refresh when a host is named anywhere, including from the approval
        // dialog on the agent thread, so an open key page updates in place.
        observer = NotificationCenter.default.addObserver(
            forName: .sequesterHostNamesDidChange, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.names = HostNames.shared.all() }
        }
    }

    func name(for fingerprint: String) -> String? {
        names[fingerprint]
    }

    func label(for fingerprint: String) -> String {
        names[fingerprint] ?? fingerprint
    }

    func setName(_ name: String?, for fingerprint: String) {
        HostNames.shared.setName(name, for: fingerprint)
        names = HostNames.shared.all()
    }
}
