import SwiftUI
import SequesterCore

/// An unreadable item queued for deletion. Keys and profiles share the
/// sheet, so the candidate carries which store the name belongs to.
struct UnreadableCandidate: Identifiable {
    enum Kind {
        case key
        case profile
    }

    let kind: Kind
    let name: String
    var id: String { "\(kind)-\(name)" }
}

/// Confirms deleting an unreadable keychain item by requiring its exact
/// name to be typed. The item cannot be opened or inspected in the app, but
/// a key item may still hold a Secure Enclave key, so deletion gets the
/// same guard as a readable one.
struct DeleteUnreadableSheet: View {

    @Environment(KeyStore.self) private var store
    @Environment(ProfileStore.self) private var profileStore
    @Environment(\.dismiss) private var dismiss

    let candidate: UnreadableCandidate

    @State private var typed = ""
    @State private var errorMessage: String?

    private var matches: Bool {
        typed.trimmingCharacters(in: .whitespaces) == candidate.name
    }

    private var explanation: String {
        switch candidate.kind {
        case .key:
            return "This item was stored by a different version of Sequester and cannot be read. It may still hold a Secure Enclave key, which is destroyed with it and cannot be recovered. Deleting it frees the name for a new key. This cannot be undone."
        case .profile:
            return "This item was stored by a different version of Sequester and cannot be read. Its sealed values are destroyed with it and cannot be recovered. Deleting it frees the name for a new profile. This cannot be undone."
        }
    }

    var body: some View {
        SheetScaffold(primaryTitle: "Delete", primaryRole: .destructive,
                      primaryDisabled: !matches, error: errorMessage,
                      size: CGSize(width: 440, height: 300), onPrimary: delete) {
            Section {
                TextField("Type the name to confirm", text: $typed, prompt: Text(candidate.name))
            } header: {
                Text("Delete unreadable item \u{201C}\(candidate.name)\u{201D}?")
            } footer: {
                Text(explanation)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func delete() {
        do {
            switch candidate.kind {
            case .key:
                try store.deleteUnreadable(name: candidate.name)
            case .profile:
                try profileStore.delete(name: candidate.name)
            }
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
