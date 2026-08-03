import SwiftUI
import SequesterCore
import SecretsWire

/// The secrets confirmation dialog: what is being done to which profile,
/// which variables are involved, and, as context only, what the request was
/// attributed to.
struct SecretsApprovalView: View {

    let kind: SecretsApprovalRequest.Kind
    let profileName: String
    let tier: SecretTier
    let variableNames: [String]
    let requester: String
    /// Whether the grace checkbox is offered; only a read of a
    /// confirm-every-read profile can use one.
    let offersGrace: Bool
    let complete: (SecretsApprovalDecision) -> Void

    @State private var grantGrace = false

    private var headline: String {
        switch kind {
        case .read: "Allow reading secrets?"
        case .create: "Create secrets profile?"
        case .update: "Update secrets profile?"
        case .delete: "Delete secrets profile?"
        }
    }

    private var allowTitle: String {
        switch kind {
        case .read: "Allow"
        case .create: "Create"
        case .update: "Update"
        case .delete: "Delete"
        }
    }

    private var graceTitle: String {
        "Don't ask again for \(Int(SecretsGraceWindows.duration / 60)) minutes"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                Image(systemName: "lock.rectangle.stack.fill")
                    .font(.title)
                    .foregroundStyle(kind == .delete ? Color.red : Color.accentColor)
                VStack(alignment: .leading, spacing: 2) {
                    Text(headline).font(.headline)
                    Text("Profile \u{201C}\(profileName)\u{201D}").font(.subheadline).foregroundStyle(.secondary)
                }
            }

            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    detailRow(title: "Attributed to", value: requester)
                    if !variableNames.isEmpty {
                        detailRow(title: "Variables", value: variableNames.joined(separator: ", "))
                    }
                    detailRow(title: tier.displayLabel, value: tier.enforcementLabel)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            if offersGrace {
                Toggle(graceTitle, isOn: $grantGrace)
                    .toggleStyle(.checkbox)
            }

            // The attribution is what macOS holds responsible for the
            // command, which any local process can arrange; it identifies
            // the request, it does not vouch for it.
            Label("Any program you run can ask for this. The name above is where the request came from, not proof of who sent it.",
                  systemImage: "info.circle")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack {
                Spacer()
                Button("Deny") {
                    complete(.deny)
                }
                .keyboardShortcut(.cancelAction)
                Button(allowTitle) {
                    complete(SecretsApprovalDecision(allowed: true, grantGrace: offersGrace && grantGrace))
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .tint(kind == .delete ? .red : .accentColor)
            }
        }
        .padding(20)
        .frame(width: 400)
    }

    private func detailRow(title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value)
                .lineLimit(3)
                .truncationMode(.tail)
                .textSelection(.enabled)
        }
    }
}
