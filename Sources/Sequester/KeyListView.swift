import SwiftUI
import SequesterCore

enum SidebarItem: Hashable {
    case general
    case apps
    case key(String)
}

struct KeyListView: View {

    @Environment(KeyStore.self) private var store
    @State private var selection: SidebarItem? = .general
    @State private var showCreate = false
    @State private var editCandidate: KeyMetadata?
    @State private var deleteCandidate: KeyMetadata?

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Label("General", systemImage: "gearshape")
                    .tag(SidebarItem.general)
                Label("Apps", systemImage: "app.badge.checkmark")
                    .tag(SidebarItem.apps)

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
                            Button("Edit…") {
                                editCandidate = key
                            }
                            Divider()
                            Button("Delete \"\(key.name)\"…", role: .destructive) {
                                deleteCandidate = key
                            }
                        }
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 220, max: 360)
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
            switch selection {
            case .key(let name):
                if let key = store.keys.first(where: { $0.name == name }) {
                    KeyDetailView(key: key)
                        .id(key.name)
                } else {
                    SetupView()
                }
            case .apps:
                AppsView()
            case .general, .none:
                SetupView()
            }
        }
        .sheet(isPresented: $showCreate) {
            CreateKeySheet()
        }
        .sheet(item: $editCandidate) { key in
            EditKeySheet(key: key) { newName in
                if selection == .key(key.name) {
                    selection = .key(newName)
                }
            }
        }
        .sheet(item: $deleteCandidate) { key in
            DeleteKeySheet(key: key) {
                if selection == .key(key.name) {
                    selection = .general
                }
            }
        }
    }
}
