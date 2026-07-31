import SwiftUI
import SequesterCore

enum SidebarItem: Hashable {
    case general
    case key(String)
}

struct KeyListView: View {

    @Environment(KeyStore.self) private var store
    @State private var selection: SidebarItem? = .general
    @State private var showCreate = false
    @State private var deleteCandidate: String?

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Label("General", systemImage: "gearshape")
                    .tag(SidebarItem.general)

                Section("Keys") {
                    if store.keys.isEmpty {
                        Text("No keys yet")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(store.keys) { key in
                        VStack(alignment: .leading, spacing: 2) {
                            Label(key.name, systemImage: key.authRequired ? "touchid" : "key")
                            if !key.keyDescription.isEmpty {
                                Text(key.keyDescription)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                        }
                        .padding(.vertical, 2)
                        .tag(SidebarItem.key(key.name))
                        .contextMenu {
                            Button("Delete \"\(key.name)\"…", role: .destructive) {
                                deleteCandidate = key.name
                            }
                        }
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 220)
            .safeAreaInset(edge: .bottom) {
                Button {
                    showCreate = true
                } label: {
                    Label("New Key", systemImage: "plus")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .keyboardShortcut("n", modifiers: .command)
                .disabled(!store.enclaveAvailable)
                .padding(12)
            }
        } detail: {
            if case .key(let name) = selection,
               let key = store.keys.first(where: { $0.name == name }) {
                KeyDetailView(key: key, selection: $selection)
                    .id(key.name)
            } else {
                SetupView()
            }
        }
        .sheet(isPresented: $showCreate) {
            CreateKeySheet()
        }
        .confirmationDialog(
            "Delete \"\(deleteCandidate ?? "")\"?",
            isPresented: Binding(
                get: { deleteCandidate != nil },
                set: { if !$0 { deleteCandidate = nil } }
            )
        ) {
            Button("Delete", role: .destructive) {
                guard let name = deleteCandidate else { return }
                try? store.delete(name: name)
                if selection == .key(name) {
                    selection = .general
                }
                deleteCandidate = nil
            }
        } message: {
            Text("The Secure Enclave key is destroyed and its public key file is removed. Hosts using this key will stop accepting logins. This cannot be undone.")
        }
        .onAppear {
            store.reload()
        }
    }
}
