import Foundation

public enum SecretsSocket {
    /// Environment variable that overrides the socket path, for test rigs
    /// serving the protocol from a scratch socket.
    public static let environmentOverride = "SEQUESTER_SECRETS_SOCK"

    /// The app serves the protocol from inside its sandbox container. The
    /// CLI runs unsandboxed with the real home directory, so it builds the
    /// container path explicitly rather than resolving ~/.sequester.
    public static func path(home: String) -> String {
        home + "/Library/Containers/cz.szypowi.sequester/Data/.sequester/secrets.sock"
    }

    public static func resolvedPath(
        home: String,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> String {
        environment[environmentOverride] ?? path(home: home)
    }
}
