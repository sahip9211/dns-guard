# Encryption, keys and installation boundaries

The product requires encryption of private persisted data and distinct instance
identities. This is separate from authenticating the application's publisher.
The first implementation target is encrypted configuration and its rollback
journal. Private indexes, history, backups, credential-vault integration and
installed service isolation must be qualified separately; see SEC tasks in
[the checklist](../task.md).

## Three different secrets

| Key | Purpose | Custody |
| --- | --- | --- |
| Per-instance data key | Encrypt and authenticate that instance's private stored data | Independent OS-generated 256-bit key, protected by service identity/OS vault; never built into the program |
| API credential | Authorize a user/client to specified operations | Separate lifecycle, expiry/revocation and least privilege; never reuse the data key |
| Release signing key | Authenticate releases and detect changed signed code | Publisher-controlled signing system; only verification material belongs in distributed software |

All copies can share the publisher's verification key. They must not share a data
key. An install UUID or filesystem path is an identifier, not a secret key.

The service owns the data key. Browser and desktop clients authenticate to its
API and must not receive the database key or open private storage directly.

## What isolates app1 from app2

Each new instance needs its own key, data directory, service identity, endpoint
and authorization state. A fresh installation must not discover and adopt another
instance's state merely because a filename or product name matches. Upgrading
an existing instance preserves its identity/key. Restoring or moving one requires
an explicit recovery operation and access to its key.

Different data keys make instance B fail to decrypt or create accepted changes
to instance A's database. OS ownership/ACLs prevent B from reading A's keys or
overwriting/deleting A's files. These are complementary controls: authenticated
encryption detects changes but cannot prevent file deletion or ciphertext replay.
Revision checks coordinate legitimate edits; they are not a trusted rollback
counter outside the database.

| Threat | Intended boundary / limitation |
| --- | --- |
| Accidental second installation | Separate instance directory/key; explicit restore, no implicit adoption |
| Process under a different unprivileged account | Service account ownership, private directory and credential access controls; needs installation tests |
| Hostile process running as the same user/service identity | Ordinary private files are insufficient; needs a stronger OS confinement/identity boundary |
| Root/administrator or compromised running service | No universal confidentiality or integrity guarantee; decrypted data must exist while in use |
| Copied encrypted database without its key | Database encryption protects contents; keep keys out of the same backup |
| Modification without key | Page authentication rejects modified content; denial of service and replay remain possible |

## Platform key custody

- Linux/Arch services: distinct service users and private state directories,
  with systemd credentials or a qualified key provider for unattended unlock.
  Desktop keyrings are not a substitute for separating hostile processes with
  the same Unix identity. Headless deployments cannot assume a logged-in keyring.
- Windows: protect data keys in the service/user security scope and use file ACLs.
  DPAPI normally protects data for a logon identity on a machine, not one executable
  copy. Machine-wide DPAPI scope is not per-instance isolation.
  [Microsoft DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).
- macOS: Keychain access controls can incorporate code-signing requirements.
  Two copies satisfying the same designated requirement are not automatically
  different application identities. Separate instance authorization still matters.
  [Apple code signing and keychain requirements](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/AboutCS/AboutCS.html).

These integrations are requirements, not currently installed protections.

## Database encryption and performance

Use SQLCipher's maintained encrypted pager and integrity checks instead of a
custom database encryption format. It encrypts database and journal page contents;
temporary data must remain in memory. A random raw key avoids password-guessing
exposure associated with weak user-selected keys and avoids a password KDF at
each startup. Human passphrases need a separate supported KDF/unlock design.
[SQLCipher design](https://www.zetetic.net/sqlcipher/design/).

Configuration is opened, validated and closed before DNS begins serving. The
decrypted typed settings and policy index remain in memory; encryption must not
put database reads or key derivation on every DNS query. Measure bundled crypto
size, startup memory and latency, not just the old unencrypted binary.

The development key-file interface uses a freshly generated 32-byte key, refuses
to overwrite an existing key and restricts Unix file permissions. It is not a
vault: an actor able to read both the database and its key can decrypt the data.
Use a trusted private directory; metadata checks do not defeat hostile directory
replacement by a process with equal filesystem privileges. Windows directory
ACLs must be provisioned by the installer. Do not pass raw keys on command lines,
log them, include them in reports or commit them to Git.

Rust-owned key buffers should be zeroed on drop, and database memory wiping should
be enabled. This does not prove every compiler/runtime/OS copy is erased or protect
against privileged memory inspection, swap, crash dumps or a compromised process.
New encryption does not securely erase historical plaintext files or backups.
