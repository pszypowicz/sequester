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
    @Environment(\.openWindow) private var openWindow
    @State private var navigator = Navigator.shared
    @State private var selection: SidebarItem? = .general
    @State private var showCreate = false
    @State private var editCandidate: KeyMetadata?
    @State private var deleteCandidate: KeyMetadata?
    @State private var showCreateProfile = false
    @State private var editProfileCandidate: ProfileMetadata?
    @State private var deleteProfileCandidate: ProfileMetadata?

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

                Section("Secrets Profiles") {
                    if profileStore.profiles.isEmpty {
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
        .sheet(item: $deleteProfileCandidate) { profile in
            DeleteProfileSheet(profile: profile) {
                if selection == .profile(profile.name) {
                    selection = .general
                }
            }
        }
        // Hand the window-opening action to the navigator so a notification
        // click can reopen this window, and honor a jump requested while the
        // window was closed (applied here) or already open (onChange).
        .onAppear {
            navigator.openWindow = openWindow
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
        case .unapprovedOnly: "lock.shield"
        case .policyOnly: "lock.open"
        }
    }
}
