import SwiftUI
import Observation
import SequesterCore

/// UI-facing view of the global app-authorization lists, one per domain,
/// kept in sync with the keychain-backed store.
@MainActor
@Observable
final class AppAuthStore {

    private(set) var ssh: [AppAuthorization] = []
    private(set) var secrets: [AppAuthorization] = []

    @ObservationIgnored nonisolated(unsafe) private var observer: (any NSObjectProtocol)?

    init() {
        reload()
        observer = NotificationCenter.default.addObserver(
            forName: .sequesterAppsDidChange, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.reload() }
        }
    }

    deinit {
        if let observer {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    func reload() {
        ssh = sorted(AppAuthorizationStore.list(domain: .ssh))
        secrets = sorted(AppAuthorizationStore.list(domain: .secrets))
    }

    private func sorted(_ items: [AppAuthorization]) -> [AppAuthorization] {
        items.sorted { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
    }

    func setState(_ authorization: AppAuthorization, state: AppState, domain: AuthorizationDomain) {
        AppAuthorizationStore.setState(identity: authorization.identity, displayName: authorization.displayName,
                                       state: state, domain: domain, now: Date())
        reload()
    }

    func remove(_ authorization: AppAuthorization, domain: AuthorizationDomain) {
        AppAuthorizationStore.remove(identity: authorization.identity, domain: domain)
        reload()
    }
}

/// Lists the apps that have been permanently allowed or blocked, separately
/// for SSH keys and for secrets profiles, with controls to flip or forget
/// each one. These are the durable records; per-request and per-session
/// decisions are made in the approval dialogs and are not shown here.
struct AppsView: View {

    @Environment(AppAuthStore.self) private var store

    var body: some View {
        Form {
            section(
                title: "Authorized for SSH keys",
                info: "Decisions made in signing dialogs. They say nothing about secrets profiles; the two lists never mix.",
                items: store.ssh,
                empty: "When an app first asks to use a key, you can allow or block it. Your permanent choices appear here.",
                domain: .ssh
            )
            section(
                title: "Authorized for secrets profiles",
                info: "Decisions made in secrets dialogs, keyed on the terminal or IDE a read was started from. Allowing an app for SSH does not allow it here.",
                items: store.secrets,
                empty: "When an app first asks to read a profile, you can allow or block it. Your permanent choices appear here.",
                domain: .secrets
            )
        }
        .formStyle(.grouped)
    }

    private func section(title: String, info: String, items: [AppAuthorization],
                         empty: String, domain: AuthorizationDomain) -> some View {
        Section {
            if items.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    Text("No app authorizations yet")
                    Text(empty)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 2)
            } else {
                ForEach(items) { authorization in
                    row(authorization, domain: domain)
                }
            }
        } header: {
            HStack(spacing: 4) {
                Text(title)
                InfoDot(text: info + " Identity is the app's code signature, so a renamed or unsigned copy cannot inherit an authorization.")
            }
        }
    }

    private func row(_ authorization: AppAuthorization, domain: AuthorizationDomain) -> some View {
        HStack(spacing: 10) {
            Image(systemName: authorization.state == .blocked ? "xmark.shield.fill" : "checkmark.shield.fill")
                .foregroundStyle(authorization.state == .blocked ? .red : .green)
            VStack(alignment: .leading, spacing: 1) {
                Text(authorization.displayName)
                Text(authorization.identity)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }
            Spacer()
            Picker("", selection: Binding(
                get: { authorization.state },
                set: { store.setState(authorization, state: $0, domain: domain) }
            )) {
                Text("Allowed").tag(AppState.allowed)
                Text("Blocked").tag(AppState.blocked)
            }
            .pickerStyle(.segmented)
            .fixedSize()
            Button {
                store.remove(authorization, domain: domain)
            } label: {
                Image(systemName: "trash")
                    .foregroundStyle(.red)
            }
            .buttonStyle(.borderless)
            .help("Forget this app; it will ask again next time.")
        }
        .padding(.vertical, 2)
    }
}
