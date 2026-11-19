---
name: sequester
description: Use when a command needs an API token or other secret kept in a Sequester secrets profile, when running ssh, scp, rsync, or git over SSH on a Mac where Sequester is the SSH agent, when such a command hangs or fails with "agent refused operation", "sign_and_send_pubkey: signing failed", "Permission denied (publickey)", or "The agent has no identities", when the sequester CLI exits with status 2 or 3, or when writing a script that reads tokens from environment variables.
---

# Sequester

Sequester is a macOS menu bar app that keeps SSH keys in the Secure Enclave and serves them as the SSH agent. It also stores API tokens as secrets profiles, which its `sequester` CLI loads into one command's environment. Signing with a key and reading a profile can each wait for the user to approve in person, with Touch ID or a dialog. You can't approve anything yourself, so plan for the user being away.

## Quick reference

| Task                           | Command                                                                          |
| ------------------------------ | -------------------------------------------------------------------------------- |
| Find profiles                  | `sequester secret list` (never prompts, never prints values)                     |
| Run one command with a profile | `sequester env exec <profile> -- <command> [args...]`                            |
| Several commands, one approval | `sequester env exec <profile> -- sh -c '<cmd1>; <cmd2>'` (single quotes)         |
| Create or update a profile     | The user runs `sequester secret set <profile> KEY...` in their own terminal      |
| Recent Sequester decisions     | `/usr/bin/log show --last 10m --predicate 'subsystem == "cz.szypowi.sequester"'` |

If `sequester` is not on `PATH`, call `/Applications/Sequester.app/Contents/MacOS/sequester-cli` directly. Its `install-cli` subcommand links it into `/usr/local/bin`, so leave that to the user.

## Secrets profiles

`sequester secret list` prints one line per profile with its name, how it confirms reads, and its variable names:

```
deploy  [Touch ID on every read]  GITHUB_TOKEN, NPM_TOKEN
ci  [No prompt] (no export)  CI_TOKEN
```

Choose the profile by its variable names, and ask the user when more than one could fit. Then run the command through `env exec`, which puts the values into the child's environment and nowhere else:

```sh
sequester env exec deploy -- ./scripts/release.sh
```

Each `env exec` is one read, and a read may prompt. When you already know you need several commands, run them under one read with `sh -c`. Use single quotes so the variables expand inside the child. With double quotes your own shell expands them first, to empty strings.

```sh
sequester env exec deploy -- sh -c 'gh api rate_limit; gh pr list -R acme/widgets'
```

### Never expose a value

These rules hold while debugging too, and they cover any part of a value.

- Don't print it. That rules out `echo`, `printenv`, `env`, `set -x`, verbose flags that dump headers (`curl -v`), and showing a prefix, a suffix, or its last bytes. To check that a variable arrived, test it without printing it: `sh -c 'test -n "$CLOUDFLARE_API_TOKEN" && echo set || echo missing'`.
- Don't use `sequester env export`, and don't capture a value with `$(...)` into your own shell. Both put plaintext where the session transcript can capture it.
- Don't write it to a file, a config, the Keychain, the clipboard, or a commit.
- Don't pass it as a command-line argument, where `ps` shows it to other processes. Prefer tools that read the variable themselves (`gh` reads `GITHUB_TOKEN`). For curl, hand the header over stdin with the shell's builtin `printf`:

  ```sh
  sequester env exec cf -- sh -c 'printf "header = \"Authorization: Bearer %s\"\n" "$CLOUDFLARE_API_TOKEN" | curl -sS -K - https://api.cloudflare.com/client/v4/user/tokens/verify'
  ```

- Don't paste command output that contains a value. Summarize it instead.
- When the user wants a value for themselves, give them a command to run, and don't run it yourself. That way the value leaves Sequester only through their own action:

  ```sh
  sequester env exec deploy -- sh -c 'printf %s "$GITHUB_TOKEN" | pbcopy'
  ```

### Creating, updating, and deleting profiles

`sequester secret set <profile> KEY...` reads each value from the terminal with echo off. Your shell has no terminal, so it fails with "Values must be entered interactively, and no terminal is available." Don't try to feed it through a pipe, `script`, `expect`, or a file. Give the user the exact command to run in a terminal window of their own, and never ask them to paste a value into the chat. If they already pasted one, store nothing yourself. Tell them it is now in the transcript and suggest rotating it.

Two `secret set` flags apply only when a profile is created and can't be changed later, so ask before using them: `--prompt touch-id|confirm|none` (Touch ID is the default) and `--no-export`. `sequester secret rm <profile>` destroys the values permanently, so run it only when the user asks for it. The app confirms every create, update, and delete in a dialog of its own.

## Approvals and waiting

Each profile confirms reads with Touch ID, with a dialog, or not at all, as `secret list` shows. A profile or key can also remember an approval for a window of up to an hour. Windows are off by default, locking the screen closes them, and changing a profile closes its window. So you can't predict whether the next command will prompt.

While an approval is pending, `sequester` prints "Waiting for approval in Sequester..." to stderr and blocks with no timeout of its own. Run it with a timeout of about two minutes.

| `sequester` exit status | Meaning                                                                                                  |
| ----------------------- | -------------------------------------------------------------------------------------------------------- |
| 0, or the command's own | Success. `env exec` replaces itself with the command, so you see the command's status.                   |
| 1                       | Local failure: bad arguments, no profile by that name, no terminal for `secret set`.                     |
| 2                       | Refused: the user clicked Deny, Touch ID was canceled or failed, the screen is locked, or export is off. |
| 3                       | Sequester is not running. Ask the user to open it.                                                       |
| 127                     | The command after `--` was not found.                                                                    |

After a 2, don't retry on your own. Ask the user, because they may have said no on purpose.

## SSH through the agent

ssh, scp, sftp, rsync over SSH, and git over SSH all ask Sequester for a signature, and so does git commit signing with an SSH key held in the agent. Every new connection asks again, so putting several SSH commands on one shell line saves no approvals. Run them at their natural granularity. After one approval, later commands often go through without a prompt, depending on how the key is set up.

Never add `-A` or `ForwardAgent` to get something working. Sequester treats forwarded requests more strictly, and the key may deny them.

## When an SSH or secrets command doesn't go through

Make one attempt with a timeout of about two minutes. If it fails, assume the user has to act, and stop asking Sequester for signatures or reads.

| What you see                                                                     | Likely cause                                                                                                                                                                                                                                                                               |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| No output until the timeout                                                      | A prompt is waiting and the user is not at the Mac.                                                                                                                                                                                                                                        |
| `agent refused operation` or `sign_and_send_pubkey: signing failed` after a wait | The user denied it, or Touch ID was canceled.                                                                                                                                                                                                                                              |
| The same error within a second or so                                             | A setting refused without asking: the destination is blocked, the key is locked to its current destinations, forwarded requests are blocked, or the requesting app was blocked. Sequester has no global lock to undo. The user changes this on the key's page or the Apps page in the app. |
| `Permission denied (publickey)` with no agent error                              | The server rejected every key offered. The ssh config may point at another `IdentityFile`, or the public key isn't on the server.                                                                                                                                                          |
| `The agent has no identities`, or `Error connecting to agent`                    | ssh isn't talking to Sequester's socket, or Sequester is not running.                                                                                                                                                                                                                      |

Don't route around it. Each of these trades the user's hardware-gated key for something weaker, or burns another prompt.

- No retry loop, and no second attempt to "see where it stalls". `ssh -v` asks for a signature too.
- No other keys: no `-i`, no `ssh-add` of a key file, no `GIT_SSH_COMMAND`, and no old files from `~/.ssh`.
- No HTTPS remote, personal access token, `gh auth setup-git`, or pushing through an API.
- No edits to the ssh config or the remote URL.

These checks never ask for a signature, so they are safe to run:

```sh
ssh -G github.com | grep -iE '^(identityagent|identityfile|identitiesonly) '
SSH_AUTH_SOCK="$HOME/Library/Containers/cz.szypowi.sequester/Data/.sequester/agent.sock" ssh-add -l
/usr/bin/log show --last 10m --predicate 'subsystem == "cz.szypowi.sequester"'
```

The log records every sign request and profile read with the decision Sequester made, which usually tells a policy refusal from a denial.

Then keep going with everything that doesn't need the blocked step: commit locally, run tests, write docs. Anything downstream of it waits, such as opening the PR, tagging, or releasing. Tell the user plainly what is done, what is blocked and why, and the exact command for them to run when they're back. In Claude Code they can run it with the `!` prefix, so its output lands in the session:

```
! git push -u origin fix-cache
```

## Writing tools that need secrets

A script or CLI that needs a token reads it from a named environment variable and knows nothing about Sequester. The caller wraps it in `sequester env exec`, and the same tool then works under any other secret store or in CI.

- Name each variable in `--help` and in the README.
- When a variable is missing, the error names the variable and nothing else, for example `CLOUDFLARE_API_TOKEN is not set`. Don't name a profile or a `sequester` command in it.
- Never write the value anywhere: no cache file, no Keychain copy, no log line. If the tool has its own credential store as a fallback, never copy an environment-supplied value into it.
- Keep it out of child processes' arguments. Use the language's HTTP client, or stdin.
- Document how to run it in the README or the calling skill, as `sequester env exec <profile> -- <tool>`.

## Red flags

Stop if you catch yourself thinking any of these:

- "I'll just show the last few characters to prove it's the right token."
- "I can pipe the pasted key into `secret set`."
- "One more `ssh -v` will show where it stalls."
- "The user wants the PR open, so HTTPS with the gh token is fine this once."
- "Sequester is probably locked, so I'll ask the user to unlock it."
- "`env export` is quicker than wrapping every command."
- "The user asked for the token, so I'll copy it to the clipboard for them."
