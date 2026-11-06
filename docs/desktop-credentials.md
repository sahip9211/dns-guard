# Native credential libraries

The default build uses maintained credential-store libraries for Linux, Windows
and macOS. SQLCipher remains responsible for database encryption. Application
code selects the backend, names an instance entry, validates the returned key and
reports failure; it does not implement an OS vault or an encryption algorithm.

| Platform | Selected library | Native facility |
| --- | --- | --- |
| Linux desktop | `dbus-secret-service-keyring-store` 1.0.1 | Secret Service, such as GNOME Keyring or KDE Wallet |
| Windows | `windows-native-keyring-store` 1.1.0 | Windows Credential Manager, local persistence |
| macOS | `apple-native-keyring-store` 1.0.2 | User Keychain |

All use `keyring-core` 1.0.1. Only the current platform's backend is compiled.
Linux uses the OpenSSL provider already bundled for SQLCipher, with bundled
libdbus. Secret Service itself is supplied by the desktop; any required runtime
beyond the defined OS baseline counts even if shared or already installed. No plaintext/file/mock
fallback is selected when the native store is unavailable. The library's mock
store is used only in unit tests.

Sources: [keyring-core](https://docs.rs/keyring-core/1.0.1/keyring_core/),
[Linux backend](https://docs.rs/dbus-secret-service-keyring-store/1.0.1/dbus_secret_service_keyring_store/),
[Windows backend](https://docs.rs/windows-native-keyring-store/1.1.0/windows_native_keyring_store/),
[macOS backend](https://docs.rs/apple-native-keyring-store/1.0.2/apple_native_keyring_store/).

## Commands and lifecycle

```sh
dns-guard config keygen --keyring
# Prints a new public identifier; substitute it for ID below.
dns-guard config init settings.sqlite rules.dngi --keyring ID --upstream 192.0.2.53:53
dns-guard config show settings.sqlite --keyring ID
dns-guard serve --config settings.sqlite --keyring ID
```

Use a reachable upstream instead of the example address. The store may require
unlock/authorization through the OS. On headless Linux prefer
[systemd credentials](service-credentials.md); a logged-in desktop keyring is not
an unattended service prerequisite.

Key generation creates an independent OS-random 256-bit key and a separate random
128-bit public identifier. The CLI does not accept an existing identifier for
generation. Keys are stored under service `dns-guard.instance-key.v1`, with the
identifier as the entry username. The key is encoded as 64 hexadecimal characters
for compatibility with KDE Wallet; encoding is not encryption. The native store
protects this value. Neither the identifier nor the service label is a secret or
an authorization boundary.

The adapter checks that an entry is absent before writing and reads it back to
verify storage. This is not a cross-process atomic create operation: the native
libraries provide upsert semantics. Random, non-user-selected identifiers avoid
accidental concurrent replacement; they do not defend against a malicious actor
already authorized to write the same credential store.

Keep the identifier and credential across upgrades. Missing, denied, ambiguous
or malformed credentials cause failure, never automatic key replacement.
Read-back failure preserves any stored entry for inspection. The key source is
explicit: `--keyring ID` and `--key-file PATH` are mutually exclusive. Raw-file
and systemd-delivered keys remain supported independently. There is no automatic
file-to-keyring migration, credential deletion or portable recovery export yet.
Do not delete the store entry while its encrypted database is needed.

## Security and performance scope

Native stores enforce their platform's access rules. Windows local persistence
does not mean per-executable isolation; Linux Secret Service is not a general
boundary against hostile processes under the same user. macOS code signing and
Keychain authorization need release/upgrade qualification. Separate instances
still need OS identities/private directories where cross-account isolation is
required. Windows service-account and macOS launch-daemon provisioning remain
unfinished. This integration targets the three desktop OSes, not browser WASM,
Android or iOS.

The key and store connection are used during startup/administration and dropped
before DNS starts. No request accesses a keyring or performs SQL. The raw and
encoded key buffers owned by our adapter are zeroed on drop; this is not a claim
about every copy inside the OS or library. Backend errors are not formatted into
logs because some carry secret buffers.

`cargo build --release --no-default-features` omits desktop credential libraries
for a minimal service using file/systemd key delivery. That build rejects
`--keyring` rather than falling back. Complete installed size still includes any
additional credential-store runtime, assets and data; neither variant establishes
the complete 10 MB target.

## Validation

Portable tests cover missing/locked stores, existing-entry preservation, malformed
keys, redacted errors and mutually exclusive CLI sources. Native tests create
independent random entries, verify cross-instance SQLCipher rejection and separate
CLI-process access, then delete only their own test entries. No personal entries
are enumerated. Linux tests use a disposable D-Bus session and keyring:

```sh
python3 tests/systemd/run_keyring_linux.py
```

CI runs the native test with Windows Credential Manager and a disposable macOS
Keychain as well as Linux Secret Service. These are functional store tests, not
cross-OS-user confinement or signed-package upgrade qualification. Platform CI
must pass before that platform is considered validated.

Recorded on 2026-11-06: the Linux native test passed in
[implementation CI](https://github.com/sahip9211/dns-guard/actions/runs/42258826959/job/128033083136),
and Windows Credential Manager passed its native test in the
[same implementation run](https://github.com/sahip9211/dns-guard/actions/runs/42258826959/job/128033082991).
The original macOS test timed out; after separating the CLI and library test
identities and configuring the disposable keychain search list, both revised
native tests passed in the
[macOS rerun](https://github.com/sahip9211/dns-guard/actions/runs/42260119119/job/128037527322).
The production Rust code is identical between those two commits; the latter
changes the test harness and CI setup. Full release-job completion is separate
from the native-test results. Local validation also passed 92 ordinary Rust
tests, two revised Linux native tests, four systemd integration tests, formatting,
Clippy and the minimal-feature build check.

The native suite tests library-created credentials within the test executable and
CLI-created credentials across CLI invocations separately. A different executable
may require Keychain authorization on macOS; silent access by arbitrary programs
is not a test requirement. CI runs these checks serially in an isolated store.

The Linux release build is 7,397,376 bytes with native desktop libraries, versus
6,621,600 bytes for the headless variant. Both bundle SQLCipher/OpenSSL; desktop
also bundles libdbus and has no external libdbus/OpenSSL runtime link. This does
not include a Secret Service daemon or prove the full application fits 10 MB.
See [build measurements](benchmarks/keyring-build.json). No new DNS latency or
CPU/RAM benchmark is claimed for this change.
