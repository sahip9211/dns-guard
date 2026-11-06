# Persistent startup configuration

Configuration is stored in SQLite through rusqlite, with the SQLite library
compiled into the executable. Repository builds omit unused FTS3/FTS5 and
R-tree modules and SQL extension loading. SQLite is compiled with `-Os`; Rust
DNS processing retains `-O3`. Thread safety, constraints, integrity checks and
transaction recovery remain enabled. These build options follow the
[SQLite compile-time interface](https://sqlite.org/compile.html). No external database server, installed SQLite
runtime, connection pool or database worker is required. The minimum supported
Rust version is now 1.89, matching the pinned rusqlite dependency.

## CLI workflow

Compile or fetch/compile an index first, then run:

```sh
dns-guard config init settings.sqlite rules.dngi --upstream 192.0.2.53:53
dns-guard config show settings.sqlite
dns-guard config set settings.sqlite --revision 1 --cache-bytes 65536
dns-guard serve --config settings.sqlite
```

Replace the documentation upstream address with a reachable resolver. The
default listener and ACL permit loopback clients only. `init` accepts the same
DNS options as `serve`, requires an explicit upstream and refuses to replace
an existing file. Index paths are validated and stored as absolute paths, so a
different startup working directory does not change which index is used.

`set` requires the revision from `show` and at least one setting. The entire
settings row and client ACL commit in one transaction. A stale revision fails
without overwriting a concurrent edit. Repeat `--allow-client` to replace the
complete ACL; omitting it preserves the current ACL. `--index PATH` selects a
different validated snapshot. `--categories none` disables category decisions
but does not remove the index or downloaded data.

Changes take effect on restart. `serve --config` rejects command-line overrides
to avoid ambiguity. The direct `serve INDEX --upstream ...` mode remains usable.
No network management endpoint, credentials or live configuration activation is
introduced by this milestone.

## DNS path and resource budgets

Configuration is loaded and validated synchronously before the Tokio runtime is
created. The connection is dropped before listeners start. The service holds only
its typed settings and immutable index; no DNS request performs SQL, waits for a
database mutex or enqueues database work. An integration test holds an exclusive
database transaction while the configured service answers a real UDP query.

The database contains one settings row and at most 32 ordered network entries.
There is no growing revision history. The fixed limits are:

| Resource | Limit / behavior |
| --- | --- |
| Database | 16 pages × 4,096 bytes = 65,536 bytes |
| Page cache | 32 KiB suggested cache target; not an RSS limit |
| Memory mapping | Disabled |
| Auxiliary SQLite workers | Zero |
| SQL text / row length | 8 KiB / 4 KiB |
| Lock wait | At most 250 ms per SQLite lock wait |
| Durability | `synchronous=EXTRA`, transactional rollback journal |
| WAL | Disabled; an existing WAL-mode database is rejected |
| Journal after successful commit | Deleted |

Configuration edits are rare and DNS has no persistent database reader. DELETE
journaling therefore avoids a WAL and its shared-memory file. `journal_size_limit`
is not a hard active-file cap; the database page limit, fixed schema and disabled
cache spilling bound this application's writes. Reserve **200 KiB** for the
configuration database plus temporary rollback journal when budgeting an update;
this includes a conservative journal-sector allowance up to 64 KiB. This is a
reservation for this schema and local storage behavior, not an application-wide
disk quota or permission to ignore other files. SQLite's page cache is also a
target: dirty transaction pages, schema allocations and allocator overhead cost
additional memory. See [SQLite pragmas](https://www.sqlite.org/pragma.html) and
[atomic commits](https://www.sqlite.org/atomiccommit.html).

Future analytics needs its own bounded writer and storage budget. It must not
reuse this connection on the DNS executor or append an event per query here.

## Versioning, recovery and file ownership

Initialization migrates an empty newly created file to schema version 1 and the
first complete revision atomically. The database has an application identifier;
unknown/future versions, foreign schemas, invalid settings, oversized files and
failed integrity checks are rejected. Later schema migrations must be explicit
transactions; no future schema is silently downgraded.

SQLite automatically recovers an interrupted transaction from its hot rollback
journal. A subprocess test flushes uncommitted changes and exits without running
destructors; reopening restores both the old settings and complete ACL. This is
process-interruption coverage, not a simulated hardware power-loss qualification.

Other corruption is preserved for inspection. Stop configuration writers, retain
the database and any journal together, and restore a known compatible backup or
create a fresh database at a different path. Automatic salvage, backup/export and
restore commands remain unfinished; never delete a hot journal to force startup.

Keep the database in an administrator-owned directory on local storage. New
files use mode 0600 on Unix; existing permissions are not silently changed.
Windows access follows the parent directory ACL. Database symlinks are rejected;
the parent directory is canonicalized so system aliases such as macOS `/var`
remain usable without following a symlink at the database filename.
These checks do not defend a directory another user can rewrite concurrently.
No SQL extension loading API is enabled, and trusted-schema execution, triggers,
views and double-quoted SQL string literals are disabled on application connections.

Tests also cover concurrent editors, unchanged state after invalid/conflicting
edits, invalid/future/foreign files, 200 repeated edits without growth in history
or WAL, CLI validation and startup from another directory.
