import LocalAuthentication
import SequesterCore

/// The app-evaluated Touch ID check gating unapprovedOnly profile reads.
/// deviceOwnerAuthentication allows the password fallback, matching the
/// semantics of the Enclave's userPresence requirement on everyRead
/// profiles.
struct LABiometricGate: BiometricGate {

    func evaluate(reason: String) async -> Bool {
        let context = LAContext()
        do {
            return try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        } catch {
            Log.app.log("Biometric gate refused: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }
}
