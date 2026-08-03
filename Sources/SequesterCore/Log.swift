import OSLog

/// Shared loggers for the unified logging system. Stream everything with:
///   log stream --predicate 'subsystem == "cz.szypowi.sequester"' --level debug
/// (also exposed as `make logs`). Key names, fingerprints, and process names
/// are logged with public privacy on purpose: they identify which key and
/// requester an event concerns, contain no secret material, and a redacted
/// debug log would be useless for exactly the situations it exists for.
public enum Log {
    public static let subsystem = "cz.szypowi.sequester"

    public static let agent = Logger(subsystem: subsystem, category: "agent")
    public static let server = Logger(subsystem: subsystem, category: "server")
    public static let store = Logger(subsystem: subsystem, category: "store")
    public static let app = Logger(subsystem: subsystem, category: "app")
    /// Secrets events log the operation, profile name, requester, and
    /// decision. Never a value.
    public static let secrets = Logger(subsystem: subsystem, category: "secrets")
}
