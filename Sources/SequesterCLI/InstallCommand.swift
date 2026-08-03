import Foundation
import Darwin
import ArgumentParser

struct InstallCLI: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "install-cli",
        abstract: "Symlink this executable into /usr/local/bin as \"sequester\"."
    )

    private static let target = "/usr/local/bin/sequester"

    func run() throws {
        do {
            let executable = try resolvedExecutablePath()
            if !executable.contains(".app/Contents/MacOS/") {
                printError("warning: \(executable) is not inside an app bundle; the link breaks when the build directory is cleaned")
            }
            let manager = FileManager.default
            let target = Self.target

            if let attributes = try? manager.attributesOfItem(atPath: target),
               let type = attributes[.type] as? FileAttributeType {
                guard type == .typeSymbolicLink else {
                    printError("\(target) exists and is not a symlink; refusing to replace it.")
                    throw ExitCode(1)
                }
                if (try? manager.destinationOfSymbolicLink(atPath: target)) == executable {
                    print("Already linked: \(target) -> \(executable)")
                    return
                }
                try manager.removeItem(atPath: target)
            }

            var isDirectory: ObjCBool = false
            let directory = (target as NSString).deletingLastPathComponent
            guard manager.fileExists(atPath: directory, isDirectory: &isDirectory),
                  isDirectory.boolValue,
                  access(directory, W_OK) == 0 else {
                printError("""
                \(directory) is not writable. Run:
                  sudo mkdir -p \(directory) && sudo ln -sf "\(executable)" \(target)
                """)
                throw ExitCode(1)
            }
            try manager.createSymbolicLink(atPath: target, withDestinationPath: executable)
            print("Linked \(target) -> \(executable)")
        } catch let error as CLIError {
            printError(error.message)
            throw ExitCode(error.code)
        }
    }

    private func resolvedExecutablePath() throws -> String {
        var capacity = UInt32(PATH_MAX)
        var buffer = [CChar](repeating: 0, count: Int(capacity))
        if _NSGetExecutablePath(&buffer, &capacity) != 0 {
            buffer = [CChar](repeating: 0, count: Int(capacity))
            _NSGetExecutablePath(&buffer, &capacity)
        }
        var resolved = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard realpath(buffer, &resolved) != nil else {
            throw CLIError.local("Could not resolve this executable's path.")
        }
        let bytes = resolved.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }
}
