import Foundation
import Observation
import SequesterCore

/// UI-facing view of the host names, which live outside key metadata
/// because a host is the same host for every key that reaches it.
@MainActor
@Observable
final class HostNameStore {

    private(set) var names: [String: String] = HostNames.shared.all()

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
