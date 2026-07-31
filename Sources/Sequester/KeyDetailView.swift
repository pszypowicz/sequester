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
                    Text("No requests observed yet. Destinations appear here as the key gets used, each one the exact path a request took, with forwarding hops as branches.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(DestinationTree.build(key.destinations)) { node in
                        DestinationNodeView(
                            node: node,
                            allowApprove: !key.authRequired,
                            onState: { id, state in store.setDestinationState(name: key.name, id: id, state: state) },
                            onDelete: { id in store.removeDestination(name: key.name, id: id) }
                        )
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

}

/// One tree node: a bare record row for leaves, a disclosure branch for
/// hops, with a merged host's direct-use record as the branch's first row.
private struct DestinationNodeView: View {

    let node: DestinationTree.Node
    let allowApprove: Bool
    let onState: (String, DestinationState) -> Void
    let onDelete: (String) -> Void

    @State private var expanded = true

    var body: some View {
        if node.children.isEmpty, let record = node.record {
            DestinationRecordRow(
                record: record,
                allowApprove: allowApprove,
                onState: { onState(record.id, $0) },
                onDelete: { onDelete(record.id) }
            )
        } else {
            DisclosureGroup(isExpanded: $expanded) {
                if let record = node.record {
                    DestinationRecordRow(
                        record: record,
                        allowApprove: allowApprove,
                        onState: { onState(record.id, $0) },
                        onDelete: { onDelete(record.id) }
                    )
                }
                ForEach(node.children) { child in
                    DestinationNodeView(
                        node: child,
                        allowApprove: allowApprove,
                        onState: onState,
                        onDelete: onDelete
                    )
                }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "arrow.triangle.branch")
                        .foregroundStyle(.secondary)
                    Text(node.fingerprint)
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(node.algorithm)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

/// One observed signing path: destination, route, usage stats, and the
/// standing controls (approve only where the app dialog is the gate).
private struct DestinationRecordRow: View {

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
                Text(usageDescription)
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
        .listRowBackground(rowBackground)
    }

    private var rowBackground: Color? {
        switch record.state {
        case .blocked: Color.red.opacity(0.14)
        case .approved: Color.green.opacity(0.14)
        case .neutral: nil
        }
    }

    private var usageDescription: String {
        let route = record.isForwarded ? "forwarded" : "local"
        let uses = record.count == 1 ? "1 use" : "\(record.count) uses"
        return "\(route) · \(uses) · last \(record.lastUsed.formatted(.relative(presentation: .named)))"
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
