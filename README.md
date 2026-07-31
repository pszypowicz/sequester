# Sequester

A macOS menu bar app that keeps SSH keys in the Secure Enclave and serves them to ssh through the standard agent protocol. Private keys are generated inside the Enclave and cannot be exported, so there is no key file on disk to steal or leak. Each key's public half is written to `~/.sequester/<name>.pub`, which means per-host `IdentityFile` entries in ssh config keep working exactly as they do with plain key files.

The idea and several implementation patterns come from [Secretive](https://github.com/maxgoedjen/secretive) (MIT). Sequester exists to add per-key signing behavior aimed at agent forwarding abuse. When you forward your agent to a remote host, a compromised host can request signatures with any of your keys and hop onward to other servers. Sequester lets each key declare how it behaves when that happens.

## Status

Early proof of concept. Working today:

- ECDSA P-256 key generation in the Secure Enclave, with an optional Touch ID requirement enforced by the Enclave itself.
- SSH agent on `~/.sequester/agent.sock` (identity listing and signing).
- Public key files on disk, one per key.
- Per-key behavior with two modes, editable at any time.
- Start at login via the system login items mechanism, with no separate daemon.

## Keys

A key is created with four settings:

| Setting              | Changeable later                                                                        |
| -------------------- | --------------------------------------------------------------------------------------- |
| Name                 | No. It becomes the `.pub` filename and the on-disk contract your ssh config references. |
| Touch ID requirement | No. It is baked into the key's access control by the Enclave at creation.               |
| Description          | Yes                                                                                     |
| Behavior             | Yes                                                                                     |

Deleting a key destroys it permanently. There is no export, because there is nothing exportable.

## Behavior modes

- **Ask every time.** Every signature request shows an approval dialog naming the requesting process and the session it is bound to.
- **Allow local, ask when forwarded.** Requests from sessions that OpenSSH bound as local are allowed silently. Requests arriving through a forwarded agent connection, and requests on connections with no session binding at all, show the dialog.

Forwarding detection uses the `session-bind@openssh.com` extension that OpenSSH 8.9 and later sends on every agent connection. The current version records what the client reports and fails safe, so anything unbound or forwarded has to ask. Cryptographic verification of the binding signature and a pinned-destinations mode are planned (see the issue tracker).

## Setup

Point ssh at the agent socket and reference keys by their public files:

```
Host *
    IdentityAgent ~/.sequester/agent.sock

Host myserver
    HostName myserver.example.com
    IdentityFile ~/.sequester/<name>.pub
    IdentitiesOnly yes
```

## Security model

- Private keys live in the Secure Enclave. The app and the agent only ever hold an encrypted key handle that is useless on any other machine, and signing happens inside the Enclave.
- The Touch ID requirement is enforced by the Enclave's access control, independently of any app-level dialog.
- Approval dialogs are an app-level policy layer on top. They are enforced for every signature the agent performs, but a local process running as your user could talk to the Enclave-backed keychain items with its own code if it were signed appropriately, so the dialogs are a usability and forwarding defense rather than a hardware boundary.
- Key handles and metadata are stored in the login keychain.

## Building

Requires Xcode command line tools and a Developer ID certificate.

```
make build      # signed bundle in .build/Sequester.app
make install    # copy to /Applications
make dev        # build and (re)launch
make test       # unit tests
```

`scripts/bundle.sh --identity adhoc` produces an unsigned local build. `scripts/agent-e2e.py` exercises the running agent end to end over the socket, and the app binary accepts a hidden `--selftest` flag that checks Enclave and keychain access headlessly.

## License

MIT. See LICENSE.
