import SwiftUI
import Observation
import SequesterCore

/// UI-facing view of the global app-authorization list, kept in sync with the
/// keychain-backed store.
@MainActor
@Observable
final class AppAuthStore {

    private(set) var authorizations: [AppAuthorization] = []

    @ObservationIgnored nonisolated(unsafe) private var observers: [any NSObjectProtocol] = []

    init() {
        reload()
        observers = [
            NotificationCenter.default.addObserver(
                forName: .sequesterAppsDidChange, object: nil, queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.reload() }
            },
            // The change notification is in-process, so a second
            // instance run from a terminal can edit the keychain
            // without this one hearing it. Refresh whenever the app
            // comes forward, which is when a stale list would show.
            NotificationCenter.default.addObserver(
                forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.reload() }
            },
        ]
    }

    deinit {
        for observer in observers {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    func reload() {
        authorizations = AppAuthorizationStore.list()
            .sorted { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
    }

    func setState(_ authorization: AppAuthorization, state: AppState) {
        AppAuthorizationStore.setState(identity: authorization.identity, displayName: authorization.displayName,
                                       state: state, now: Date())
        reload()
    }

    func remove(_ authorization: AppAuthorization) {
        AppAuthorizationStore.remove(identity: authorization.identity)
        reload()
    }
}

/// Lists the apps that have been permanently allowed or blocked, with controls
/// to flip or forget each one. This is the durable record; per-request and
/// per-session decisions are made in the approval dialog and are not shown
/// here.
struct AppsView: View {

    @Environment(AppAuthStore.self) private var store

    var body: some View {
        Form {
            Section {
                if store.authorizations.isEmpty {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("No app authorizations yet")
                        Text("When an app first asks to use a key, you can allow or block it. Your permanent choices appear here.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 2)
                } else {
                    ForEach(store.authorizations) { authorization in
                        row(authorization)
                    }
                }
            } header: {
                HStack(spacing: 4) {
                    Text("Authorized apps")
                    InfoDot(text: "Identity is the app's code signature, so a renamed or unsigned copy cannot inherit an authorization.")
                }
            }
        }
        .formStyle(.grouped)
    }

    private func row(_ authorization: AppAuthorization) -> some View {
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
                set: { store.setState(authorization, state: $0) }
            )) {
                Text("Allowed").tag(AppState.allowed)
                Text("Blocked").tag(AppState.blocked)
            }
            .pickerStyle(.segmented)
            .fixedSize()
            Button {
                store.remove(authorization)
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
