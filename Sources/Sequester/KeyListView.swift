import SwiftUI
import SequesterCore

struct KeyListView: View {

    @Environment(KeyStore.self) private var store
    @State private var selection: String?
    @State private var showCreate = false

    var body: some View {
        NavigationSplitView {
            List(store.keys, selection: $selection) { key in
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
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 220)
            .overlay {
                if store.keys.isEmpty {
                    ContentUnavailableView(
                        "No Keys",
                        systemImage: "key.slash",
                        description: Text("Create a key to get started.")
                    )
                }
            }
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
            if let selected = selection, let key = store.keys.first(where: { $0.name == selected }) {
                KeyDetailView(key: key, selection: $selection)
                    .id(key.name)
            } else {
                SetupView()
            }
        }
        .sheet(isPresented: $showCreate) {
            CreateKeySheet()
        }
        .onAppear {
            store.reload()
        }
    }
}
