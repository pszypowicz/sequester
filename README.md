# Sequester

> **Beta:** Sequester is pre-1.0. Backward compatibility is not guaranteed until version 1.0.0.

A macOS menu bar app that keeps SSH keys in the Secure Enclave and serves them to ssh through the standard agent protocol. Private keys are generated inside the Enclave and cannot be exported, so there is no key file on disk to steal. Each key's public half is written to disk under a filename derived from the key material, so per-host `IdentityFile` entries in ssh config keep working and never break when a key is renamed.

Sequester adds a per-key signing policy aimed at agent-forwarding abuse. When you forward your agent to a remote host, a compromised host can request signatures with any of your keys and hop onward to other servers. Sequester lets each key declare how it behaves when that happens.

## Status

Early proof of concept. Working today:

- ECDSA P-256 key generation in the Secure Enclave, with an optional Touch ID requirement enforced by the Enclave itself.
- SSH agent over a Unix socket (identity listing and signing).
- Public key files on disk, one per key.
- Per-key approval policy: per-destination standings plus block-forwarded, approve-local, approve-all, and lock, editable at any time.
- Start at login via the system login items mechanism, with no separate daemon.

## Keys

A key is created with four settings:

| Setting              | Changeable later                                                          |
| -------------------- | ------------------------------------------------------------------------- |
| Name                 | Yes                                                                       |
| Touch ID requirement | No. It is baked into the key's access control by the Enclave at creation. |
| Description          | Yes                                                                       |
| Approval settings    | Yes                                                                       |

The on-disk `.pub` filename is derived from a hash of the key material, so it is stable for the life of the key. The file is the contract ssh config references, and the name is only a label. Deleting a key destroys it permanently, and there is nothing to export.

## Approval

This is OpenSSH's destination constraints (`ssh-add -h`) made visual and interactive. A key's usage is described in the same vocabulary OpenSSH uses: a **host** is identified by its **host key** (shown as a fingerprint), a connection is tied to a **session identifier**, and each agent connection is **bound** to its session with a `session-bind@openssh.com` record. The ordered list of those bindings is the **binding chain**, the same thing OpenSSH writes as `vm1>github.com`.

The `session-bind` record carries the host key, the session identifier, a signature, and an `is_forwarding` byte. That byte marks whether the connection forwards the agent onward: a **forwarding hop** has `is_forwarding = 1`, and the endpoint the key authenticates to (the **destination host**) has `is_forwarding = 0`. A request's binding chain is a run of forwarding hops ending in a destination host, and Sequester shows a chain as forwarded when any hop in it forwards.

Each key records the destination hosts it is asked to sign for, keyed by the exact binding chain: github reached directly, github reached through vm1, and github reached through vm2 are three separate records. Each record has a standing you set on the key's page:

- **Neutral** (default): ask before signing.
- **Approved**: sign without asking. Offered as a "don't ask again for this destination" checkbox in the approval dialog, for keys without the Touch ID requirement. Approval covers exactly the observed chain, so trusting github directly says nothing about forwarded use, and trusting it through vm1 says nothing about vm2. A standing set on a hop covers every chain through it, so a whole branch is governed at once.
- **Blocked**: deny without any prompt, including the Touch ID prompt. Useful for silencing noise and for defeating prompt-fatigue attacks from a compromised host.

Per-key settings shape the defaults for chains without an explicit standing. **Approve all requests without asking** signs everything except blocked destinations. **Approve local requests without asking** signs only non-forwarded chains. **Block forwarded requests** denies anything that arrives through a forwarding hop. **Lock to current destinations** signs only for destinations already approved and denies everything else, so a key can be finalized to exactly the hosts it is for. The approve settings are offered only for keys without Touch ID, since the Enclave prompt cannot be skipped, and blocks always win over approvals.

Each binding's signature is verified against its host key, and a silent signature additionally requires the request's own session identifier to match the destination binding. Unknown and unbound chains always ask, and a denied request for a host the key has never signed for is logged rather than added to the destinations, so a probe cannot grow the list.

Every signature posts a notification identifying the key and destination host, so unexpected use is visible.

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
- Approval dialogs are an app-level policy layer enforced for every signature the agent performs.
- The app runs in the App Sandbox with no network entitlement, so its file access is confined to the container and the agent process cannot phone home.
- Key handles and metadata are stored in the login keychain.

## Building

Requires macOS 26 or later, the Xcode 26 command line tools, and a Developer ID certificate.

```
make build      # signed bundle in .build/Sequester.app
make install    # copy to /Applications
make dev        # build and (re)launch
make test       # unit tests
```

`scripts/bundle.sh --identity adhoc` produces an unsigned local build. `scripts/build-icon.sh` regenerates `Resources/Sequester.icns` from `scripts/generate-icon.swift`. `scripts/agent-e2e.py` exercises the running agent end to end over the socket, and the app binary accepts a hidden `--selftest` flag that checks Enclave and keychain access headlessly.

## Debugging

The app logs to the unified logging system under the subsystem `cz.szypowi.sequester`, with categories `agent` (protocol events, sign decisions), `server` (socket lifecycle, connection provenance), `store` (key CRUD and Enclave operations), and `app` (launch, approval dialogs, login item).

Some shells ship a `log` builtin that shadows the system tool, so call it by its absolute path. Stream it live with

```
/usr/bin/log stream --predicate 'subsystem == "cz.szypowi.sequester"' --level debug --style compact
```

For past events use `/usr/bin/log show --last 1h --predicate 'subsystem == "cz.szypowi.sequester"'`, or filter for the subsystem in Console.app. Key names, fingerprints, and requesting process names are logged with public privacy so the log stays readable, and no secret material passes through any log line.

## Acknowledgements

The idea and several implementation patterns come from [Secretive](https://github.com/maxgoedjen/secretive) (MIT).

## License

MIT. See LICENSE.
