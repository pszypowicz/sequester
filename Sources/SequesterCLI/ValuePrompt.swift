import Foundation
import Darwin

/// Reads a secret value from the controlling terminal with echo off, so it
/// never appears in argv, the environment, or the transcript.
enum ValuePrompt {

    static func read(key: String) throws -> String {
        guard let tty = fopen("/dev/tty", "r+") else {
            throw CLIError.local("Values must be entered interactively, and no terminal is available.")
        }
        defer { fclose(tty) }
        let fd = fileno(tty)

        var original = termios()
        guard tcgetattr(fd, &original) == 0 else {
            throw CLIError.local("Could not read terminal attributes.")
        }
        var muted = original
        // Only echo is cleared; signals stay enabled so Ctrl-C still works
        // and the shell restores the terminal afterwards.
        muted.c_lflag &= ~tcflag_t(ECHO)
        guard tcsetattr(fd, TCSAFLUSH, &muted) == 0 else {
            throw CLIError.local("Could not disable terminal echo.")
        }
        defer {
            tcsetattr(fd, TCSAFLUSH, &original)
            fputs("\n", tty)
            fflush(tty)
        }

        fputs("Value for \(key): ", tty)
        fflush(tty)

        var buffer = [CChar](repeating: 0, count: 64 * 1024 + 2)
        guard fgets(&buffer, Int32(buffer.count), tty) != nil else {
            throw CLIError.local("No value entered for \(key).")
        }
        let bytes = buffer.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }
        var line = String(decoding: bytes, as: UTF8.self)
        if line.hasSuffix("\n") {
            line.removeLast()
        }
        guard !line.isEmpty else {
            throw CLIError.local("Empty value for \(key).")
        }
        return line
    }
}
