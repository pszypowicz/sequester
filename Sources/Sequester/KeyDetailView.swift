import SwiftUI
import SequesterCore

/// Read-only view of a key. Name and description are edited through the
/// sidebar row's Edit action; approval settings change here.
struct KeyDetailView: View {

    @Environment(KeyStore.self) private var store
    @Environment(HostNameStore.self) private var hostNames

    let key: KeyMetadata
    @State private var errorMessage: String?
    @State private var namingTarget: NamingTarget?

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
                if !key.authRequired {
                    Toggle("Approve local requests without asking", isOn: autoApproveBinding)
                }
            } header: {
                Text("Approval")
            } footer: {
                Text(approvalCaption)
                    .font(.caption)
                    .foregroundStyle(.secondary)
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

            Section {
                if key.destinations.isEmpty {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("No usage yet")
                        Text("Destinations appear here as the key gets used, each one the exact path a request took, with forwarding hops as branches.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 2)
                } else {
                    ForEach(DestinationTree.build(key.destinations)) { node in
                        DestinationNodeView(
                            node: node,
                            allowApprove: !key.authRequired,
                            label: { hostNames.label(for: $0) },
                            branchState: { id in key.branchRules.first { $0.id == id }?.state ?? .neutral },
                            onRecordState: { id, state in store.setDestinationState(name: key.name, id: id, state: state) },
                            onBranchState: { hops, state in store.setBranchRule(name: key.name, hops: hops, state: state) },
                            onDelete: { id in store.removeDestination(name: key.name, id: id) },
                            onName: { namingTarget = NamingTarget(id: $0) }
                        )
                    }
                }
            } header: {
                Text("Destinations")
            } footer: {
                Text("A standing on a hop covers every path through it. A block anywhere on the path wins; otherwise the most specific standing applies. Right-click a host to name it.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .sheet(item: $namingTarget) { target in
            NameHostSheet(fingerprint: target.id)
        }
        .onAppear {
            store.reload()
        }
    }

    private var approvalCaption: String {
        if key.authRequired {
            "Touch ID is enforced by the Secure Enclave and cannot be bypassed or replaced by Sequester. Blocked destinations and blocked forwarded requests are denied before any prompt appears."
        } else if key.autoApprove {
            "This key signs local (non-forwarded) requests with no dialog and no naming prompt. Forwarded requests still ask, and blocked destinations are always denied."
        } else {
            "Sequester asks before each signature unless the destination is approved. Blocked destinations and blocked forwarded requests are denied without asking."
        }
    }

    private var autoApproveBinding: Binding<Bool> {
        Binding(
            get: { key.autoApprove },
            set: { enabled in
                do {
                    try store.setAutoApprove(name: key.name, enabled: enabled)
                    errorMessage = nil
                } catch {
                    errorMessage = error.localizedDescription
                }
            }
        )
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

/// Sits next to every fingerprint so naming and renaming a host is always
/// one visible click away.
private struct NameButton: View {

    let isNamed: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: isNamed ? "pencil" : "tag")
        }
        .buttonStyle(.borderless)
        .help(isNamed ? "Rename this host" : "Name this host")
    }
}

/// One tree node: a bare record row for leaves, a disclosure branch for
/// hops, with a merged host's direct-use record as the branch's first row.
private struct DestinationNodeView: View {

    let node: DestinationTree.Node
    let allowApprove: Bool
    let label: (String) -> String
    let branchState: (String) -> DestinationState
    let onRecordState: (String, DestinationState) -> Void
    let onBranchState: ([ChainHop], DestinationState) -> Void
    let onDelete: (String) -> Void
    let onName: (String) -> Void

    @State private var expanded = true

    var body: some View {
        if node.children.isEmpty, let record = node.record {
            DestinationRecordRow(
                record: record,
                allowApprove: allowApprove,
                label: label,
                onState: { onRecordState(record.id, $0) },
                onDelete: { onDelete(record.id) },
                onName: onName
            )
        } else {
            DisclosureGroup(isExpanded: $expanded) {
                if let record = node.record {
                    DestinationRecordRow(
                        record: record,
                        allowApprove: allowApprove,
                        label: label,
                        onState: { onRecordState(record.id, $0) },
                        onDelete: { onDelete(record.id) },
                        onName: onName
                    )
                }
                ForEach(node.children) { child in
                    DestinationNodeView(
                        node: child,
                        allowApprove: allowApprove,
                        label: label,
                        branchState: branchState,
                        onRecordState: onRecordState,
                        onBranchState: onBranchState,
                        onDelete: onDelete,
                        onName: onName
                    )
                }
            } label: {
                branchLabel
            }
        }
    }

    private var branchLabel: some View {
        let state = branchState(DestinationRecord.chainID(node.hops))
        let name = label(node.fingerprint)
        return HStack(spacing: 6) {
            Image(systemName: "arrow.triangle.branch")
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 1) {
                Text(name)
                    .font(name == node.fingerprint ? .system(.caption, design: .monospaced) : .body)
                    .lineLimit(1)
                    .truncationMode(.middle)
                if name != node.fingerprint {
                    Text(node.fingerprint)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            NameButton(isNamed: name != node.fingerprint) { onName(node.fingerprint) }
            Spacer()
            if allowApprove {
                branchButton(state, .approved, icon: "checkmark.shield", tint: .green,
                             help: "Sign without asking for everything through this hop")
            }
            branchButton(state, .neutral, icon: "questionmark.circle", tint: .secondary,
                         help: "No branch standing")
            branchButton(state, .blocked, icon: "xmark.shield", tint: .red,
                         help: "Deny everything through this hop")
        }
    }

    private func branchButton(_ current: DestinationState, _ state: DestinationState,
                              icon: String, tint: Color, help: String) -> some View {
        Button {
            onBranchState(node.hops, state)
        } label: {
            Image(systemName: current == state ? "\(icon).fill" : icon)
                .foregroundStyle(current == state ? tint : Color.secondary)
        }
        .buttonStyle(.borderless)
        .help(help)
    }
}

/// One observed signing path: destination, route, usage stats, and the
/// standing controls (approve only where the app dialog is the gate).
private struct DestinationRecordRow: View {

    let record: DestinationRecord
    let allowApprove: Bool
    let label: (String) -> String
    let onState: (DestinationState) -> Void
    let onDelete: () -> Void
    let onName: (String) -> Void

    var body: some View {
        let fingerprint = record.destination?.fingerprint ?? "unknown"
        let name = label(fingerprint)
        return HStack(alignment: .center, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(name)
                        .font(name == fingerprint ? .system(.caption, design: .monospaced) : .body)
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
                if name != fingerprint {
                    Text(fingerprint)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Text(usageDescription)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            NameButton(isNamed: name != fingerprint) { onName(fingerprint) }
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
