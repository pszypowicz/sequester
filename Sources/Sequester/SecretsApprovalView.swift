import SwiftUI
import SequesterCore
import SecretsWire

/// The secrets approval dialog: what is being done to which profile, which
/// variables are involved, who is asking, and for reads from an unknown app
/// the same once/session/always choice the signing dialog offers.
struct SecretsApprovalView: View {

    let kind: SecretsApprovalRequest.Kind
    let profileName: String
    let tier: SecretTier
    let variableNames: [String]
    let requester: String
    /// Whether the requesting app has a verified identity, and so can be
    /// remembered as allowed. Unverified peers can only be allowed once.
    let verified: Bool
    /// Whether an app-authorization decision is being asked for: a read
    /// from an app with no standing yet.
    let appDecisionNeeded: Bool
    let complete: (SecretsApprovalDecision) -> Void

    @State private var appScope: AppScope = .once

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
                    detailRow(title: "Requested by", value: requester)
                    if !variableNames.isEmpty {
                        detailRow(title: "Variables", value: variableNames.joined(separator: ", "))
                    }
                    detailRow(title: tier.displayLabel, value: tier.enforcementLabel)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            if appDecisionNeeded {
                if verified {
                    Picker("When I allow:", selection: $appScope) {
                        Text("Just this time").tag(AppScope.once)
                        Text("For this session").tag(AppScope.session)
                        Text("Always allow this app").tag(AppScope.always)
                    }
                    .pickerStyle(.menu)
                    .fixedSize()
                } else {
                    Label("Unverified app: it can be allowed only for this one request.",
                          systemImage: "exclamationmark.shield")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }

            HStack {
                if appDecisionNeeded {
                    Button("Block App", role: .destructive) {
                        complete(SecretsApprovalDecision(allowed: false, appScope: .block))
                    }
                }
                Spacer()
                Button("Deny") {
                    complete(.deny)
                }
                .keyboardShortcut(.cancelAction)
                if kind == .delete {
                    Button(allowTitle) {
                        complete(SecretsApprovalDecision(allowed: true))
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                } else {
                    Button(allowTitle) {
                        complete(SecretsApprovalDecision(
                            allowed: true,
                            appScope: (appDecisionNeeded && verified) ? appScope : .once
                        ))
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                }
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
