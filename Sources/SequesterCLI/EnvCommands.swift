import Foundation
import Darwin
import ArgumentParser
import SecretsWire

extension EnvFormat: ExpressibleByArgument {}

struct Env: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "env",
        abstract: "Use a profile's variables in the environment.",
        subcommands: [EnvExec.self, EnvExport.self],
        defaultSubcommand: nil
    )
}

struct EnvExec: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "exec",
        abstract: "Run a command with the profile's variables in its environment.",
        discussion: "The recommended way to consume a profile: values go straight into the child process and never touch stdout or a shell. Example: sequester env exec deploy -- terraform apply"
    )

    @Argument(help: "Profile name.")
    var profile: String

    @Argument(parsing: .postTerminator, help: "Command and arguments, after --.")
    var command: [String]

    func validate() throws {
        guard !command.isEmpty else {
            throw ValidationError("Provide a command after --, e.g. sequester env exec \(profile) -- terraform apply")
        }
    }

    func run() throws {
        do {
            let response = try SecretsClient()
                .send(SecretsRequest(op: .get, profile: profile, purpose: .exec))
                .unwrap()
            for (key, value) in response.values ?? [:] {
                setenv(key, value, 1)
            }
            let argv = command.map { strdup($0) } + [nil]
            execvp(argv[0]!, argv)
            // execvp only returns on failure.
            printError("exec \(command[0]): \(String(cString: strerror(errno)))")
            throw ExitCode(127)
        } catch let error as CLIError {
            printError(error.message)
            throw ExitCode(error.code)
        }
    }
}

struct EnvExport: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "export",
        abstract: "Print shell lines exporting the profile's variables.",
        discussion: "Plaintext lands on stdout, where a transcript or session recording can capture it; prefer env exec. Consume with: eval \"$(sequester env export deploy)\" or, for fish, sequester env export deploy --format fish | source"
    )

    @Argument(help: "Profile name.")
    var profile: String

    @Option(help: "Output format: posix or fish.")
    var format: EnvFormat = .posix

    func run() throws {
        do {
            let response = try SecretsClient()
                .send(SecretsRequest(op: .get, profile: profile, purpose: .export))
                .unwrap()
            let script = format.script(values: response.values ?? [:])
            if !script.isEmpty {
                print(script)
            }
        } catch let error as CLIError {
            printError(error.message)
            throw ExitCode(error.code)
        }
    }
}
