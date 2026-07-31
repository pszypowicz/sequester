# Sequester

> **Beta:** Sequester is pre-1.0. Backward compatibility is not guaranteed until version 1.0.0 is reached.

A macOS menu bar app that keeps SSH keys in the Secure Enclave and serves them to ssh through the standard agent protocol. Private keys are generated inside the Enclave and cannot be exported, so there is no key file on disk to steal or leak. Each key's public half is written to disk under a filename derived from the key material itself, which means per-host `IdentityFile` entries in ssh config keep working exactly as they do with plain key files and never break when a key is renamed.

The idea and several implementation patterns come from [Secretive](https://github.com/maxgoedjen/secretive) (MIT). Sequester exists to add per-key signing behavior aimed at agent forwarding abuse. When you forward your agent to a remote host, a compromised host can request signatures with any of your keys and hop onward to other servers. Sequester lets each key declare how it behaves when that happens.

## Status

Early proof of concept. Working today:

- ECDSA P-256 key generation in the Secure Enclave, with an optional Touch ID requirement enforced by the Enclave itself.
- SSH agent over a Unix socket (identity listing and signing).
- Public key files on disk, one per key.
- Per-key behavior with two modes, editable at any time.
- Start at login via the system login items mechanism, with no separate daemon.
- Fully sandboxed: the app is confined to its container, with no network access.

## Keys

A key is created with four settings:

| Setting              | Changeable later                                                          |
| -------------------- | ------------------------------------------------------------------------- |
| Name                 | Yes                                                                       |
| Touch ID requirement | No. It is baked into the key's access control by the Enclave at creation. |
| Description          | Yes                                                                       |
| Approval settings    | Yes                                                                       |

The on-disk `.pub` filename is derived from a hash of the key material, so it is stable for the life of the key. The file is the contract ssh config references; the name is a label. Deleting a key destroys it permanently. There is no export, because there is nothing exportable.

## Approval

Every signature request needs confirmation by default. For keys with the Touch ID requirement the Enclave's own prompt is the confirmation, carrying the requesting process and destination in its text; Sequester never stacks a second dialog on top. For other keys Sequester shows an approval dialog naming the requester and the session the request is bound to.

Each key records the destinations it is asked to sign for, keyed by the exact binding chain of the connection: "github reached locally", "github reached through vm1", and "github reached through vm2" are three separate records. Each record has a standing you can set on the key's page:

- **Neutral** (default): ask before signing.
- **Approved**: sign without asking. Offered as a "don't ask again for this destination" checkbox in the approval dialog, and only for keys without the Touch ID requirement, since the Enclave prompts regardless. Approval covers exactly the observed path, so trusting github locally says nothing about forwarded use, and trusting it through vm1 says nothing about vm2. A standing set on a hop covers every path through it, so a whole branch can be governed at once.
- **Blocked**: deny without any prompt, including the Touch ID prompt. Useful for silencing noise and for defeating prompt-fatigue attacks from a compromised host.

A per-key **block forwarded requests** toggle denies everything arriving through a forwarded agent connection outright, taking precedence over approved records. A per-key **approve local requests** toggle (keys without Touch ID only) signs non-forwarded requests without a dialog; forwarded requests still ask, and blocks always win.

Path detection uses the `session-bind@openssh.com` extension that OpenSSH 8.9 and later sends on every agent connection, one binding per hop. Each binding's signature is verified against the destination host key, and a silent signature additionally requires the request's own session identifier to match the destination binding, so an intermediate host cannot forge a downstream hop or reuse a binding to authorize a different session. Unknown and unbound paths always ask.

Every signature posts a notification identifying the key and destination, worded to stand out when the signature happened with no prompt at all, so unexpected use is visible.

## Setup

The socket and the public key files live in the app's sandbox container. Copy the exact paths from the app (the socket path is on the General page, each key's file path is on its page) and point ssh at them:

```
Host *
    IdentityAgent ~/Library/Containers/cz.szypowi.sequester/Data/.sequester/agent.sock

Host myserver
    HostName myserver.example.com
    IdentityFile ~/Library/Containers/cz.szypowi.sequester/Data/.sequester/<key file>.pub
    IdentitiesOnly yes
```

## Security model

- Private keys live in the Secure Enclave. The app and the agent only ever hold an encrypted key handle that is useless on any other machine, and signing happens inside the Enclave.
- The Touch ID requirement is enforced by the Enclave's access control, independently of any app-level dialog.
- Approval dialogs are an app-level policy layer on top. They are enforced for every signature the agent performs, but a local process running as your user could talk to the Enclave-backed keychain items with its own code if it were signed appropriately, so the dialogs are a usability and forwarding defense rather than a hardware boundary.
- The app runs in the App Sandbox with no network entitlement: its file access is confined to the container, and a compromised agent process has no way to phone home.
- Session bindings are cryptographically verified, so a compromised forwarding host cannot fabricate a downstream destination to reach a silent approval. It can still make genuine onward connections with a forwarded key it holds, which no agent can prevent; that is a reason to prefer not forwarding into untrusted hosts.
- Key handles and metadata are stored in the login keychain.

## Building

Requires Xcode command line tools and a Developer ID certificate.

```
make build      # signed bundle in .build/Sequester.app
make install    # copy to /Applications
make dev        # build and (re)launch
make test       # unit tests
```

`scripts/bundle.sh --identity adhoc` produces an unsigned local build. `scripts/build-icon.sh` regenerates `Resources/Sequester.icns` from `scripts/generate-icon.swift`. `scripts/agent-e2e.py` exercises the running agent end to end over the socket, and the app binary accepts a hidden `--selftest` flag that checks Enclave and keychain access headlessly.

## Debugging

The app logs to the unified logging system under the subsystem `cz.szypowi.sequester`, with categories `agent` (protocol events, sign decisions), `server` (socket lifecycle, connection provenance), `store` (key CRUD and Enclave operations), and `app` (launch, approval dialogs, login item). Stream it live with

```
make logs
```

or directly:

```
log stream --predicate 'subsystem == "cz.szypowi.sequester"' --level debug --style compact
```

For past events use `log show --last 1h --predicate 'subsystem == "cz.szypowi.sequester"'`, or filter for the subsystem in Console.app. Key names, fingerprints, and requesting process names are logged with public privacy so the log stays readable; no secret material passes through any log line.

## License

MIT. See LICENSE.
