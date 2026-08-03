import ArgumentParser

@main
struct SequesterCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sequester",
        abstract: "Enclave-gated secrets profiles served by the Sequester app.",
        discussion: """
        Profiles are encrypted under a Secure Enclave key and decrypted by \
        the Sequester app after its policy check, so commands may wait for \
        an approval dialog or a Touch ID prompt. Exit codes: 0 success, \
        1 failure, 2 refused by policy or authentication, 3 Sequester is \
        not running.
        """,
        version: "\(BuildMetadata.version) (\(BuildMetadata.gitHash))",
        subcommands: [Secret.self, Env.self, InstallCLI.self]
    )
}
