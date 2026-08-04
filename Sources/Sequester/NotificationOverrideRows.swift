import SwiftUI
import SequesterCore

/// One notification class in a key's or profile's own settings: a toggle
/// with the same label and explanation the global settings use.
struct NotificationToggle: View {

    let title: String
    let info: String
    @Binding var isOn: Bool

    var body: some View {
        Toggle(isOn: $isOn) {
            HStack(spacing: 4) {
                Text(title)
                InfoDot(text: info)
            }
        }
    }
}

/// The header row shared by both detail pages: follow the global settings,
/// or give this credential its own.
struct FollowGlobalToggle: View {

    @Binding var followsGlobal: Bool

    var body: some View {
        Toggle(isOn: $followsGlobal) {
            HStack(spacing: 4) {
                Text("Use global settings")
                InfoDot(text: "On, this follows the notification settings on the Settings page. Off, the choices below apply to this one only, and later changes to the global settings leave it alone.")
            }
        }
    }
}

/// Wording shared between the global settings and both override sections,
/// so a class means the same thing wherever it is set.
enum NotificationWording {
    static let signedSilently = (
        "Signed without any prompt",
        "A signature that showed no dialog and no Touch ID prompt. This notification is the only evidence such a use happened."
    )
    static let signedAfterPrompt = (
        "Signed after a prompt",
        "A signature you just approved at a dialog or a Touch ID prompt, so the notification repeats what you have already seen."
    )
    static let signedNewDestination = (
        "Signed for a new destination",
        "The first time a key signs for a host over a given route. Shown even when the two settings above are off."
    )
    static let refusedAppBlocked = (
        "Refused: app blocked",
        "A request from an app you have blocked, refused before any prompt."
    )
    static let refusedDestinationBlocked = (
        "Refused: destination blocked",
        "A request for a destination you have blocked, or a forwarded request to a key that refuses them."
    )
    static let refusedKeyLocked = (
        "Refused: key locked",
        "A locked key asked to sign for a destination not on its list, which is how you learn it is being probed."
    )
    static let secretsReadSilently = (
        "Read without any prompt",
        "A profile read that showed no dialog and no Touch ID prompt, either because its confirmation is set to none or because a remembered tap covered it."
    )
    static let secretsReadAfterPrompt = (
        "Read after a prompt",
        "A profile read you just confirmed at a dialog or a Touch ID prompt."
    )
}
