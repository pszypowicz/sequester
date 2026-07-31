import SwiftUI
import SequesterCore

/// Read-only view of a key. Name and description are edited through the
/// sidebar row's Edit action; approval settings change here.
struct KeyDetailView: View {

    @Environment(KeyStore.self) private var store

    let key: KeyMetadata
    @State private var errorMessage: String?

    var body: some View {
        Form {
            Section {
                LabeledContent("Name", value: key.name)
                if !key.keyDescription.isEmpty {
                    LabeledContent("Description", value: key.keyDescription)
                }
                LabeledContent("Created", value: key.createdAt.formatted(date: .abbreviated, time: .shortened))
            }

            Section {
                LabeledContent("Touch ID", value: key.authRequired ? "Required for every signature" : "Not required")
                Toggle("Block forwarded requests", isOn: blockForwardedBinding)
            } header: {
                Text("Approval")
            } footer: {
                Text(approvalCaption)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section {
                if key.destinations.isEmpty {
                    Text("No requests observed yet. Destinations appear here as the key gets used, each one the exact path a request took.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(key.destinations.sorted { $0.lastUsed > $1.lastUsed }) { record in
                        DestinationRow(
                            record: record,
                            allowApprove: !key.authRequired,
                            onState: { state in store.setDestinationState(name: key.name, id: record.id, state: state) },
                            onDelete: { store.removeDestination(name: key.name, id: record.id) }
                        )
                        .listRowBackground(rowBackground(record.state))
                    }
                }
            } header: {
                Text("Destinations")
            }

            Section("Public key") {
                CopyRow(icon: "doc.text", label: "Public key path", value: key.publicKeyFileURL.path, revealURL: key.publicKeyFileURL)
                CopyRow(icon: "key", label: "Public key", value: key.publicKeyLine)
                CopyRow(icon: "touchid", label: "SHA256 fingerprint", value: key.fingerprint)
                CopyRow(icon: "touchid", label: "MD5 fingerprint", value: key.fingerprintMD5)
            }

            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
        .formStyle(.grouped)
        .onAppear {
            store.reload()
        }
    }

    private var approvalCaption: String {
        if key.authRequired {
            "Touch ID is enforced by the Secure Enclave and cannot be bypassed or replaced by Sequester. Blocked destinations and blocked forwarded requests are denied before any prompt appears."
        } else {
            "Sequester asks before each signature unless the destination is approved. Blocked destinations and blocked forwarded requests are denied without asking."
        }
    }

    private var blockForwardedBinding: Binding<Bool> {
        Binding(
            get: { key.blockForwarded },
            set: { blocked in
                do {
                    try store.setBlockForwarded(name: key.name, blocked: blocked)
                    errorMessage = nil
                } catch {
                    errorMessage = error.localizedDescription
                }
            }
        )
    }

    private func rowBackground(_ state: DestinationState) -> Color? {
        switch state {
        case .blocked: Color.red.opacity(0.14)
        case .approved: Color.green.opacity(0.14)
        case .neutral: nil
        }
    }
}

/// One observed signing path: destination, route, usage stats, and the
/// standing controls (approve only where the app dialog is the gate).
private struct DestinationRow: View {

    let record: DestinationRecord
    let allowApprove: Bool
    let onState: (DestinationState) -> Void
    let onDelete: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(record.destination?.fingerprint ?? "unknown")
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    if record.isForwarded {
                        Text("FORWARDED")
                            .font(.caption2.bold())
                            .padding(.horizontal, 4)
                            .padding(.vertical, 1)
                            .background(.orange.opacity(0.25), in: RoundedRectangle(cornerRadius: 3))
                    }
                }
                Text(routeDescription)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if allowApprove {
                stateButton(.approved, icon: "checkmark.shield", tint: .green, help: "Sign without asking")
            }
            stateButton(.neutral, icon: "questionmark.circle", tint: .secondary, help: "Ask before signing")
            stateButton(.blocked, icon: "xmark.shield", tint: .red, help: "Deny without asking")
            Button {
                onDelete()
            } label: {
                Image(systemName: "trash")
            }
            .buttonStyle(.borderless)
            .help("Forget this destination")
        }
        .padding(.vertical, 2)
    }

    private var routeDescription: String {
        let route: String
        if record.hops.count > 1 {
            let via = record.hops.dropLast().map { shortFingerprint($0.fingerprint) }.joined(separator: ", ")
            route = "via \(via)"
        } else {
            route = record.isForwarded ? "forwarded" : "local"
        }
        let uses = record.count == 1 ? "1 use" : "\(record.count) uses"
        return "\(route) · \(uses) · last \(record.lastUsed.formatted(.relative(presentation: .named)))"
    }

    private func shortFingerprint(_ fingerprint: String) -> String {
        String(fingerprint.replacingOccurrences(of: "SHA256:", with: "").prefix(12))
    }

    private func stateButton(_ state: DestinationState, icon: String, tint: Color, help: String) -> some View {
        Button {
            onState(state)
        } label: {
            Image(systemName: record.state == state ? "\(icon).fill" : icon)
                .foregroundStyle(record.state == state ? tint : Color.secondary)
        }
        .buttonStyle(.borderless)
        .help(help)
    }
}
