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
    @State private var collapsed: Set<String> = []

    var body: some View {
        Form {
            Section {
                LabeledContent("Name", value: key.name)
                if !key.keyDescription.isEmpty {
                    LabeledContent("Description", value: key.keyDescription)
                }
                LabeledContent("Created", value: key.createdAt.formatted(date: .abbreviated, time: .shortened))
            }

            Section("Approval") {
                LabeledContent("Touch ID", value: key.authRequired ? "Required for every signature" : "Not required")
                if !key.authRequired {
                    Toggle(isOn: approveAllBinding) {
                        settingLabel("Approve all requests without asking",
                                     "Signs every request with no dialog, forwarded or not, except destinations you have blocked. The broadest setting; it overrides approve-local and lock.")
                    }
                    Toggle(isOn: autoApproveBinding) {
                        settingLabel("Approve local requests without asking",
                                     "Signs local (non-forwarded) requests with no dialog or naming prompt. Forwarded requests still ask, and blocks always win.")
                    }
                    .disabled(key.approveAll)
                }
                Toggle(isOn: blockForwardedBinding) {
                    settingLabel("Block forwarded requests",
                                 "Denies every request that arrives through a forwarded agent connection, regardless of the destination's standing.")
                }
                .disabled(key.approveAll)
                Toggle(isOn: lockedBinding) {
                    settingLabel("Lock to current destinations",
                                 "Signs only for destinations you have already approved; everything else is denied without asking. Turn off to allow new destinations again.")
                }
                .disabled(key.approveAll)
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
                        Text("Destination hosts appear here as the key gets used, each one the binding chain a request took, with forwarding hops as branches.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 2)
                } else {
                    ForEach(DestinationTree.build(key.destinations).rows(collapsed: collapsed)) { row in
                        DestinationRowView(
                            row: row,
                            allowApprove: !key.authRequired,
                            label: { hostNames.label(for: $0) },
                            branchState: rowState,
                            isCollapsed: { collapsed.contains($0) },
                            onToggle: { id in
                                if collapsed.contains(id) { collapsed.remove(id) } else { collapsed.insert(id) }
                            },
                            onRecordState: { id, state in store.setDestinationState(name: key.name, id: id, state: state) },
                            onBranchState: { hops, state in store.setBranchRule(name: key.name, hops: hops, state: state) },
                            onDelete: { id in store.removeDestination(name: key.name, id: id) },
                            onDeleteBranch: { hops in store.removeDestinationsUnder(name: key.name, prefix: hops) },
                            onName: { namingTarget = NamingTarget(id: $0) }
                        )
                        .listRowBackground(rowTint(for: row))
                    }
                }
            } header: {
                Text("Destinations")
            } footer: {
                Text("Each row is a binding chain: forwarding hops branch, and the last host key is the destination host reached. A standing on a hop covers every chain through it. A block anywhere on the chain wins; otherwise the most specific standing applies.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .sheet(item: $namingTarget) { target in
            NameHostSheet(fingerprint: target.id)
        }
    }

    private func settingLabel(_ title: String, _ info: String) -> some View {
        HStack(spacing: 4) {
            Text(title)
            InfoDot(text: info)
        }
    }

    private var lockedBinding: Binding<Bool> {
        Binding(
            get: { key.locked },
            set: { locked in
                do {
                    try store.setLocked(name: key.name, locked: locked)
                    errorMessage = nil
                } catch {
                    errorMessage = error.localizedDescription
                }
            }
        )
    }

    private var approveAllBinding: Binding<Bool> {
        Binding(
            get: { key.approveAll },
            set: { enabled in
                do {
                    try store.setApproveAll(name: key.name, enabled: enabled)
                    errorMessage = nil
                } catch {
                    errorMessage = error.localizedDescription
                }
            }
        )
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

    private func rowState(_ hops: [BindingHop]) -> DestinationState {
        key.branchRules.first { $0.id == DestinationRecord.bindingChainID(hops) }?.state ?? .neutral
    }

    /// Full-row tint for a standing. Applied on the ForEach element so the
    /// grouped Form colors the whole row edge to edge.
    private func rowTint(for row: DestinationRow) -> Color? {
        let state: DestinationState = switch row.kind {
        case .route(let node): rowState(node.hops)
        case .destination(let record): record.state
        }
        return switch state {
        case .approved: Color.green.opacity(0.22)
        case .blocked: Color.red.opacity(0.22)
        case .neutral: nil
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

/// An info dot that reveals text in a popover after a brief hover, matching
/// the interaction used elsewhere in these apps' settings.
private struct InfoDot: View {

    let text: String
    var monospaced: Bool = false
    @State private var shown = false
    @State private var hoverDelay: Task<Void, Never>?

    var body: some View {
        Image(systemName: "info.circle")
            .font(.caption)
            .foregroundStyle(.secondary)
            .onHover { inside in
                hoverDelay?.cancel()
                if inside {
                    hoverDelay = Task {
                        try? await Task.sleep(nanoseconds: 150_000_000)
                        guard !Task.isCancelled else { return }
                        shown = true
                    }
                } else {
                    shown = false
                }
            }
            .popover(isPresented: $shown) {
                Text(text)
                    .font(monospaced ? .system(.callout, design: .monospaced) : .callout)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(width: monospaced ? nil : 280, alignment: .leading)
                    .padding(12)
            }
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

/// One line of the flattened destination tree. Every row - route hop or
/// destination - uses the identical trailing control cluster pinned to the
/// right by a Spacer, so the columns line up exactly regardless of depth or
/// row kind. Indentation and a fixed-width disclosure slot keep the leading
/// icons aligned too.
private struct DestinationRowView: View {

    private static let indentWidth: CGFloat = 16
    private static let slotWidth: CGFloat = 18

    let row: DestinationRow
    let allowApprove: Bool
    let label: (String) -> String
    let branchState: ([BindingHop]) -> DestinationState
    let isCollapsed: (String) -> Bool
    let onToggle: (String) -> Void
    let onRecordState: (String, DestinationState) -> Void
    let onBranchState: ([BindingHop], DestinationState) -> Void
    let onDelete: (String) -> Void
    let onDeleteBranch: ([BindingHop]) -> Void
    let onName: (String) -> Void

    var body: some View {
        HStack(spacing: 6) {
            Color.clear.frame(width: CGFloat(row.depth) * Self.indentWidth, height: 0)
            disclosure
            content
            Spacer(minLength: 8)
            controls
        }
        .padding(.vertical, 2)
    }

    // MARK: leading

    @ViewBuilder private var disclosure: some View {
        switch row.kind {
        case .route(let node):
            Button {
                onToggle(node.id)
            } label: {
                Image(systemName: isCollapsed(node.id) ? "chevron.right" : "chevron.down")
                    .foregroundStyle(.secondary)
                    .frame(width: Self.slotWidth)
            }
            .buttonStyle(.borderless)
        case .destination:
            Color.clear.frame(width: Self.slotWidth, height: 0)
        }
    }

    @ViewBuilder private var content: some View {
        switch row.kind {
        case .route(let node):
            hostLabel(fingerprint: node.fingerprint, icon: "arrow.triangle.branch")
        case .destination(let record):
            hostLabel(fingerprint: record.destination?.fingerprint ?? "unknown", icon: "mappin.and.ellipse")
        }
    }

    /// A single line: the name when the host is named (with an info icon
    /// whose hover reveals the fingerprint), otherwise the fingerprint
    /// itself.
    private func hostLabel(fingerprint: String, icon: String) -> some View {
        let name = label(fingerprint)
        let named = name != fingerprint
        return HStack(spacing: 6) {
            Image(systemName: icon).foregroundStyle(.secondary)
            Text(name)
                .font(named ? .body : .system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .lineLimit(1)
                .truncationMode(.middle)
            if named {
                InfoDot(text: fingerprint, monospaced: true)
            }
            NameButton(isNamed: named) { onName(fingerprint) }
        }
    }

    // MARK: trailing

    @ViewBuilder private var controls: some View {
        let state = currentState
        if allowApprove {
            stateButton(state, .approved, icon: "checkmark.shield", tint: .green, help: approveHelp)
        }
        stateButton(state, .neutral, icon: "questionmark.circle", tint: .secondary, help: neutralHelp)
        stateButton(state, .blocked, icon: "xmark.shield", tint: .red, help: blockHelp)
        Button {
            switch row.kind {
            case .route(let node): onDeleteBranch(node.hops)
            case .destination(let record): onDelete(record.id)
            }
        } label: {
            Image(systemName: "trash")
        }
        .buttonStyle(.borderless)
        .help(row.isRoute ? "Forget all destinations through this hop" : "Forget this destination")
    }

    private func stateButton(_ current: DestinationState, _ state: DestinationState,
                             icon: String, tint: Color, help: String) -> some View {
        Button {
            switch row.kind {
            case .route(let node): onBranchState(node.hops, state)
            case .destination(let record): onRecordState(record.id, state)
            }
        } label: {
            Image(systemName: current == state ? "\(icon).fill" : icon)
                .foregroundStyle(current == state ? tint : Color.secondary)
        }
        .buttonStyle(.borderless)
        .help(help)
    }

    // MARK: helpers

    private var currentState: DestinationState {
        switch row.kind {
        case .route(let node): branchState(node.hops)
        case .destination(let record): record.state
        }
    }

    private var approveHelp: String {
        row.isRoute ? "Sign without asking for everything through this hop" : "Sign without asking"
    }
    private var neutralHelp: String { row.isRoute ? "No branch standing" : "Ask before signing" }
    private var blockHelp: String {
        row.isRoute ? "Deny everything through this hop" : "Deny without asking"
    }
}

private extension DestinationRow {
    var isRoute: Bool {
        if case .route = kind { return true }
        return false
    }
}
