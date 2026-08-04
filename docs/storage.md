# Storage

Sequester keeps its state in two places: credentials live in the login keychain, and the files ssh needs live in a flat directory inside the app container. Both are inspectable with standard command line tools. This page describes the exact layout, so anything the app does can also be inspected or done by hand.

## Keychain layout

Every credential is one generic-password item in the login keychain. The account attribute holds the user-visible name, the service attribute identifies the kind, the label is what Keychain Access displays, the value holds the secret material, and the generic attribute holds the metadata JSON that the UI presents.

| Kind               | Service                         | Account                          |
| ------------------ | ------------------------------- | -------------------------------- |
| SSH keys           | `cz.szypowi.sequester.keys`     | key name                         |
| Secrets profiles   | `cz.szypowi.sequester.profiles` | profile name                     |
| App authorizations | `cz.szypowi.sequester.apps`     | `authorizations` (a single item) |

What the value of each kind holds:

- A key item's value is the Secure Enclave key's `dataRepresentation`, an encrypted handle that only the Enclave of the Mac that created it can use. The private key never leaves the Enclave, and this handle is the only reference to it, so deleting the item discards the key permanently.
- A profile item's value is a JSON envelope carrying the profile's own Enclave key handle and the sealed values blob, versioned together so the ciphertext and its key can only change as a pair.
- The app authorizations value is a JSON array with every app's standing, kept in one item.

Credentials are keychain items rather than files in the container because the keychain restricts writes to the app's code signature. A co-resident process could edit a user-owned file, but it cannot swap a sealed blob or add itself to the app allowlist stored this way.

## Inspecting items

List every item of one kind by name (substitute the service string for the other kinds):

```sh
security dump-keychain ~/Library/Keychains/login.keychain-db \
  | grep -B 20 '"svce"<blob>="cz.szypowi.sequester.keys"' \
  | grep '"acct"<blob>'
```

Show the attributes of a single item:

```sh
security find-generic-password -s cz.szypowi.sequester.keys -a <name>
```

Attributes and metadata are readable without any prompt. Reading an item's value with `-w` asks for authorization, because the items belong to the app's code signature. A key handle read that way is of little use anyway, since it only works inside the Enclave that created it.

## Removing items

```sh
security delete-generic-password -s cz.szypowi.sequester.keys -a <name>
```

Each invocation removes one matching item and prints its attributes as it goes. Deleting a key item permanently discards the Enclave private key behind it. The app notices changes made this way when it next comes forward.

## Files on disk

Everything outside the keychain lives in one flat directory:

```
~/Library/Containers/cz.szypowi.sequester/Data/.sequester/
├── agent.sock     # the SSH agent socket (SSH_AUTH_SOCK points here)
├── secrets.sock   # the secrets protocol socket, never forwarded with the agent
└── <stem>.pub     # one public key file per key
```

The path sits inside the app container because the sandboxed app resolves its home directory there; ssh and other unsandboxed processes can follow it freely. Each `.pub` filename stem is the first 16 hex characters of the SHA-256 of the public key blob, so the file that ssh config references never moves when a key is renamed. The files carry mode 0600 because ssh refuses a group- or world-readable `IdentityFile`.

On every launch the app rewrites any `.pub` file whose content drifted and deletes any `.pub` file no key claims. Pruning is skipped while any unreadable key item exists, because such an item's filename lives in the metadata that did not decode, and its file must not be mistaken for a stale one.

## Items from other versions

Sequester is pre-1.0 and reads only the current storage format, with no migrations. An item written by a different version may stop decoding; it still reserves its name, and a key item may still hold an Enclave key, so it appears in the sidebar as a greyed-out unreadable entry rather than disappearing. Right-clicking the entry deletes it after the usual typed-name confirmation, and removing the last unreadable key item lets the file sync prune the `.pub` files left behind.

The CLI commands above reach the same items, so the UI is a convenience rather than a requirement. A recreated key is a new key pair, and its public half must replace the old one on every host and service that used it.
