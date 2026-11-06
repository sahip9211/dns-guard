# Native key custody for Linux services

Use systemd's credential API for unattended Linux/Arch services. SQLCipher already
handles database cryptography. The application accepts a key path, so systemd can
deliver a protected runtime key through that existing interface without another
Rust library, key daemon, polling task or per-query operation.

`LoadCredentialEncrypted=` decrypts/authenticates the credential at service
activation. The application reads the resulting 32-byte file; no raw key belongs
in command-line arguments, environment values, unit text or logs. `%d` in a unit
resolves to the credential directory. Systemd removes that directory when the
service stops. See [systemd credentials](https://systemd.io/CREDENTIALS/).

## System service template

[dns-guard@.service](../packaging/systemd/dns-guard@.service) is a deployment
template, not a completed installer. A system administrator must provision:

| Item | Example for instance `office` |
| --- | --- |
| Dedicated non-login user/group | `dns-guard-office` |
| Private state directory | `/var/lib/dns-guard/office`, mode 0700, owned by that account |
| Encrypted settings | `settings.sqlite` in that directory, owned by the service account |
| Policy index | `rules.dngi` in that directory; settings must reference this absolute path |
| Credential directory | `/etc/dns-guard/office`, root-owned, mode 0700 |
| Encrypted key | `data-key.cred` in the credential directory, root-owned, mode 0600 |
| Root-owned executable | `/usr/bin/dns-guard` |

Use short lowercase alphanumeric instance names and a different account/key for
every independent instance. Keep parent directories administrator-owned and
non-writable by service users. Do not reuse existing unrelated accounts.
Creating another client must not grant it membership of the service account.

Generate an independent key with `config keygen`, then initialize the encrypted
settings with that key and the final index path. On the target machine, an
administrator can wrap the bootstrap key using:

```sh
systemd-creds encrypt --name=data-key /secure/bootstrap/instance.key /etc/dns-guard/office/data-key.cred
```

The source is a placeholder for a private bootstrap location. Never overwrite an
existing instance key or credential during reinstall. Arrange protected key
recovery before removing bootstrap material: host/TPM-bound credentials may not
survive migration or OS replacement. Backing up the encrypted credential is not
necessarily a portable key backup. Secure removal of historical plaintext is a
separate storage/backup problem.

Install the template into the platform's system unit directory only after
provisioning and reviewing the saved listener, upstream and client ACL. Each
instance needs a distinct listening address/port. Startup fails if its identity,
credential or valid configuration is missing; it does not create defaults or keys.
The template grants only the capability needed for a privileged DNS port and
constrains filesystem, device and namespace access. It is not a defense against
root or a compromised process running as the service's own identity. The policy
index remains plaintext on disk behind filesystem permissions (SEC-02 remains open).

## Verified integration and its limits

On Arch/systemd 262, four opt-in integration tests passed against the existing
release binary on 2026-11-06:

1. Load user-scoped encrypted credentials after removing the raw fixture keys;
   verify read-only 32-byte runtime delivery and cleanup on service exit.
2. Reject another instance's key and preserve the database bytes.
3. Reject an invalid encrypted credential before successful application startup.
4. Answer a real blocked UDP query after native credential unlock.

```sh
DNS_GUARD_SYSTEMD_TEST_BINARY=./target/release/dns-guard \
  python3 -m unittest discover -s tests/systemd -v
```

These tests use temporary synthetic data and transient **user** services. They
require systemd's user credential encryption support and an active user manager;
they are intentionally separate from portable CI. They fail if those facilities
are unavailable rather than substituting unencrypted or null-key credentials.
Normal discovery without the explicit binary skips them.

The system service template is syntax-checked, but its full confinement and
cross-account isolation still require privileged installation tests. The test
runner's ordinary account cannot install those services here. User-service tests
do not establish a boundary against other processes under that same user.

The systemd-only integration at commit `a296f16` added no Rust production code or
dependency; its executable was 6,621,088 bytes. The subsequent desktop integration
has [separately measured build variants](size-budget.md). Unit files and encrypted credential blobs still count toward the
complete installed-size budget. Cold-start memory, credential-manager overhead,
and system-instance resource limits have not been newly qualified.

## Desktop library choice

The current Rust keyring ecosystem offers `keyring-core` plus explicitly selected
OS credential-store backends. The umbrella `keyring` documentation recommends
that approach for applications controlling which stores they use, avoiding
unneeded dependencies. Core's mock/sample stores are not secure production stores.
[keyring guidance](https://docs.rs/keyring/latest/keyring/),
[keyring-core](https://docs.rs/keyring-core/latest/keyring_core/).

The [desktop library integration](desktop-credentials.md) now uses those native
backends and fails when its secure store is unavailable. A credential
library does not establish OS account isolation or API authorization. Browser and
desktop clients should ultimately hold their own API credentials, not the DNS
service's database key. See [security boundaries](security-model.md).
