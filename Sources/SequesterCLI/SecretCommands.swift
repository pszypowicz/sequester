import Foundation
import ArgumentParser
import SecretsWire

struct Secret: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "secret",
        abstract: "Manage secrets profiles.",
        subcommands: [SecretSet.self, SecretList.self, SecretRm.self]
    )
}

/// The CLI spelling of the confirmation tiers.
enum PromptOption: String, ExpressibleByArgument, CaseIterable {
    case touchID = "touch-id"
    case confirm
    case none

    var tier: SecretTier {
        switch self {
        case .touchID: .everyRead
        case .confirm: .confirmEveryRead
        case .none: .noPrompt
        }
    }
}

struct SecretSet: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "set",
        abstract: "Create a profile or set variable values.",
        discussion: "Values are prompted on the terminal with echo off; they never appear on the command line. The --prompt and --no-export flags apply only when the profile is created and are permanent."
    )

    @Argument(help: "Profile name.")
    var profile: String

    @Argument(help: "Variable names to set; each value is prompted.")
    var keys: [String]

    @Option(name: .customLong("prompt"),
            help: "How reads are confirmed when creating: touch-id (Enclave-enforced, the default), confirm, or none.")
    var prompt: PromptOption?

    @Flag(name: .customLong("no-export"),
          help: "When creating, refuse env export for this profile so values stay off stdout.")
    var noExport = false

    func validate() throws {
        guard !keys.isEmpty else {
            throw ValidationError("Provide at least one KEY to set.")
        }
        for key in keys {
            do {
                try EnvName.validate(key)
            } catch {
                throw ValidationError(error.localizedDescription)
            }
        }
    }

    func run() throws {
        do {
            var values: [String: String] = [:]
            for key in keys {
                values[key] = try ValuePrompt.read(key: key)
            }
            let create: CreateOptions? = (prompt != nil || noExport)
                ? CreateOptions(tier: (prompt ?? .touchID).tier, exportDisabled: noExport)
                : nil
            let response = try SecretsClient()
                .send(SecretsRequest(op: .set, profile: profile, values: values, create: create))
                .unwrap()
            let variables = response.variables ?? []
            if response.created == true {
                printError("Created profile \(profile) (\(variables.count) variable\(variables.count == 1 ? "" : "s")).")
            } else {
                printError("Updated profile \(profile) (now: \(variables.joined(separator: ", "))).")
            }
        } catch let error as CLIError {
            printError(error.message)
            throw ExitCode(error.code)
        }
    }
}

struct SecretList: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "list",
        abstract: "List profiles, how each confirms reads, and their variable names."
    )

    func run() throws {
        do {
            let response = try SecretsClient().send(SecretsRequest(op: .list)).unwrap()
            let profiles = response.profiles ?? []
            guard !profiles.isEmpty else {
                printError("No profiles. Create one with: sequester secret set <profile> KEY")
                return
            }
            for profile in profiles {
                var line = "\(profile.name)  [\(profile.tier.displayLabel)]"
                if profile.exportDisabled {
                    line += " (no export)"
                }
                line += "  \(profile.variables.joined(separator: ", "))"
                print(line)
            }
        } catch let error as CLIError {
            printError(error.message)
            throw ExitCode(error.code)
        }
    }
}

struct SecretRm: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "rm",
        abstract: "Delete a profile. Sequester asks for confirmation.",
        discussion: "The Enclave key and the encrypted values are destroyed together; values cannot be recovered."
    )

    @Argument(help: "Profile name.")
    var profile: String

    func run() throws {
        do {
            try SecretsClient().send(SecretsRequest(op: .rm, profile: profile)).unwrap()
            printError("Deleted profile \(profile).")
        } catch let error as CLIError {
            printError(error.message)
            throw ExitCode(error.code)
        }
    }
}
