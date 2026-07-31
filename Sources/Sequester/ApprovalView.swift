import SwiftUI
import SequesterCore

/// The signing approval dialog, shown as a route: this Mac, each forwarding
/// hop, and the destination. Host names are used where set; the full
/// fingerprint stays visible and selectable on every row.
struct ApprovalView: View {

    struct Hop: Identifiable {
        let id = UUID()
        let name: String?
        let fingerprint: String
        let forwarded: Bool
        let isDestination: Bool
    }

    let keyName: String
    let requester: String
    let hops: [Hop]
    let canName: Bool
    let canRemember: Bool
    let complete: (ApprovalDecision) -> Void

    @State private var name = ""
    @State private var remember = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                Image(systemName: "key.fill")
                    .font(.title)
                    .foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Allow SSH signature?").font(.headline)
                    Text("Key \u{201C}\(keyName)\u{201D}").font(.subheadline).foregroundStyle(.secondary)
                }
            }

            GroupBox {
                VStack(alignment: .leading, spacing: 0) {
                    routeRow(icon: "laptopcomputer", tint: .secondary, title: "This Mac",
                             fingerprint: nil, role: requester, emphasize: false, last: hops.isEmpty)
                    if hops.isEmpty {
                        routeRow(icon: "questionmark.circle", tint: .orange, title: "Unbound",
                                 fingerprint: nil, role: "no session binding - destination unknown",
                                 emphasize: false, last: true)
                    }
                    ForEach(Array(hops.enumerated()), id: \.element.id) { index, hop in
                        routeRow(
                            icon: hop.isDestination ? "mappin.and.ellipse" : "arrow.triangle.branch",
                            tint: hop.isDestination ? .accentColor : (hop.forwarded ? .orange : .secondary),
                            title: hop.name ?? "Unnamed host",
                            fingerprint: hop.fingerprint,
                            role: hop.isDestination ? "destination host" : "forwarding hop",
                            emphasize: hop.isDestination,
                            last: index == hops.count - 1
                        )
                    }
                }
            }

            if canName {
                TextField("Name this host (optional)", text: $name)
                    .textFieldStyle(.roundedBorder)
            }
            if canRemember {
                Toggle("Don't ask again for this destination", isOn: $remember)
                    .toggleStyle(.checkbox)
                if remember {
                    Text("Allow approves it; Deny blocks it. Either way, further requests to this destination stop asking.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }

            HStack {
                Spacer()
                Button("Deny") {
                    complete(ApprovalDecision(
                        allowed: false,
                        remember: canRemember && remember,
                        destinationName: name.isEmpty ? nil : name
                    ))
                }
                .keyboardShortcut(.cancelAction)
                Button("Allow") {
                    complete(ApprovalDecision(
                        allowed: true,
                        remember: canRemember && remember,
                        destinationName: name.isEmpty ? nil : name
                    ))
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 400)
    }

    private func routeRow(icon: String, tint: Color, title: String, fingerprint: String?,
                          role: String, emphasize: Bool, last: Bool) -> some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(spacing: 0) {
                Image(systemName: icon)
                    .foregroundStyle(tint)
                    .frame(width: 22, height: 22)
                if !last {
                    Rectangle()
                        .fill(.secondary.opacity(0.3))
                        .frame(width: 1.5)
                        .frame(maxHeight: .infinity)
                }
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(title).fontWeight(emphasize ? .semibold : .regular)
                if let fingerprint {
                    Text(fingerprint)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                Text(role)
                    .font(.caption2)
                    .foregroundStyle(role == "forwarding hop" ? .orange : .secondary)
            }
            .padding(.bottom, last ? 0 : 8)
            Spacer(minLength: 0)
        }
    }
}
