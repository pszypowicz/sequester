import SwiftUI
import SequesterCore

enum SidebarItem: Hashable {
    case general
    case apps
    case key(String)
    case profile(String)
}

struct KeyListView: View {

    @Environment(KeyStore.self) private var store
    @Environment(ProfileStore.self) private var profileStore
    @State private var navigator = Navigator.shared
    @State private var selection: SidebarItem? = .general
    @State private var showCreate = false
    @State private var editCandidate: KeyMetadata?
    @State private var deleteCandidate: KeyMetadata?
    @State private var showCreateProfile = false
    @State private var editProfileCandidate: ProfileMetadata?
    @State private var deleteProfileCandidate: ProfileMetadata?
    @State private var deleteUnreadableCandidate: UnreadableCandidate?

    /// Titlebar text that names the section the user is in, so the window
    /// tells you where you are the same way the sidebar does.
    private var windowTitle: String {
        switch selection {
        case .apps:
            return "Apps"
        case .key(let name):
            return "Keys - \(name)"
        case .profile(let name):
            return "Profiles - \(name)"
        case .general, .none:
            return "Settings"
        }
    }

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Label("Settings", systemImage: "gearshape")
                    .tag(SidebarItem.general)
                Label("Apps", systemImage: "app.badge.checkmark")
                    .tag(SidebarItem.apps)

                Section("Keys") {
                    if store.keys.isEmpty && store.unreadable.isEmpty {
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
                    ForEach(store.unreadable) { item in
                        UnreadableRow(name: item.name)
                            .contextMenu {
                                Button("Delete \"\(item.name)\"…", role: .destructive) {
                                    deleteUnreadableCandidate = UnreadableCandidate(kind: .key, name: item.name)
                                }
                            }
                    }
                }

                Section("Secrets Profiles") {
                    if profileStore.profiles.isEmpty && profileStore.unreadable.isEmpty {
                        Text("No profiles yet")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(profileStore.profiles) { profile in
                        Label(profile.name, systemImage: profileIcon(profile))
                            .padding(.vertical, 2)
                            .tag(SidebarItem.profile(profile.name))
                            .contextMenu {
                                Button("Rename…") {
                                    editProfileCandidate = profile
                                }
                                Divider()
                                Button("Delete \"\(profile.name)\"…", role: .destructive) {
                                    deleteProfileCandidate = profile
                                }
                            }
                    }
                    ForEach(profileStore.unreadable) { item in
                        UnreadableRow(name: item.name)
                            .contextMenu {
                                Button("Delete \"\(item.name)\"…", role: .destructive) {
                                    deleteUnreadableCandidate = UnreadableCandidate(kind: .profile, name: item.name)
                                }
                            }
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 220, max: 360)
            .safeAreaInset(edge: .bottom) {
                VStack(spacing: 8) {
                    Button {
                        showCreate = true
                    } label: {
                        Label("New Key", systemImage: "plus")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .keyboardShortcut("n", modifiers: .command)
                    Button {
                        showCreateProfile = true
                    } label: {
                        Label("New Profile", systemImage: "plus")
                            .frame(maxWidth: .infinity)
                    }
                    .controlSize(.large)
                }
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
            case .profile(let name):
                if let profile = profileStore.profiles.first(where: { $0.name == name }) {
                    ProfileDetailView(profile: profile)
                        .id(profile.name)
                } else {
                    SetupView()
                }
            case .apps:
                AppsView()
            case .general, .none:
                SetupView()
            }
        }
        .navigationTitle(windowTitle)
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
        .sheet(isPresented: $showCreateProfile) {
            CreateProfileSheet()
        }
        .sheet(item: $editProfileCandidate) { profile in
            EditProfileSheet(profile: profile) { newName in
                if selection == .profile(profile.name) {
                    selection = .profile(newName)
                }
            }
        }
        .sheet(item: $deleteUnreadableCandidate) { candidate in
            DeleteUnreadableSheet(candidate: candidate)
        }
        .sheet(item: $deleteProfileCandidate) { profile in
            DeleteProfileSheet(profile: profile) {
                if selection == .profile(profile.name) {
                    selection = .general
                }
            }
        }
        // Honor a jump requested while the window was closed (applied here)
        // or already open (onChange).
        .onAppear {
            applyPendingSelection()
        }
        .onChange(of: navigator.pendingSelection) {
            applyPendingSelection()
        }
    }

    private func applyPendingSelection() {
        guard let pending = navigator.pendingSelection else { return }
        selection = pending
        navigator.pendingSelection = nil
    }

    private func profileIcon(_ profile: ProfileMetadata) -> String {
        switch profile.tier {
        case .everyRead: "touchid"
        case .confirmEveryRead: "lock.shield"
        case .noPrompt: "lock.open"
        }
    }
}

/// Sidebar row for a keychain item this version cannot read. It has no page
/// to open, so it stays unselectable; the context menu offers deletion.
private struct UnreadableRow: View {
    let name: String

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Label(name, systemImage: "exclamationmark.triangle")
            Text("Unreadable")
                .font(.caption)
                .lineLimit(1)
        }
        .foregroundStyle(.secondary)
        .padding(.vertical, 2)
        .selectionDisabled()
        .help("Stored by a different version of Sequester and cannot be read. Right-click to delete it.")
    }
}
