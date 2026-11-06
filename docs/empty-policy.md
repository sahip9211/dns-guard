# Explicit all-filters-disabled snapshots

An instance can run with no filtering rules, using a 71-byte snapshot. No dummy
hostname is inserted. DNS validation, client ACLs, upstream forwarding, cache
semantics and transport errors remain active. This does not guarantee that every
DNS request succeeds or bypass restrictions outside the policy matcher.

```sh
dns-guard compile empty.dngi --other-bytes 1000000 --empty
dns-guard serve empty.dngi --upstream 127.0.0.1:53
```

The storage reservation is illustrative; provide a complete inventory/reserve in
real deployments. Publication still counts old/new snapshot overlap and refuses
over-budget updates. `--empty` and `--feed` are mutually exclusive. Omitting both
is an error. Normal empty feed imports still fail and preserve the old snapshot.
Activation still requires service restart; the browser reports status and tests
hostnames but does not change selected sources yet.

Library callers use `Index::empty(limits)` or `compile_sources` with no enabled
sources. `compile(&[], limits)` and an enabled source selection containing no rules
are rejected. Thus a failed/empty import cannot silently become all-filters-off.
Disabling one source still preserves other sources' overlapping contributions.

The representation uses the existing v1 envelope with zero logical rules and the
FST library's canonical empty map. The reader requires that exact empty payload,
validates the checksum and continues to reject count changes, truncation or
malformed records. Earlier versions reject zero-rule snapshots rather than
silently loading them; upgrading the reader is required before using this option.
No new dependency or per-query allocation is introduced, and no jump tables are
allocated for an empty snapshot. Hostname/category validation still runs.

Tests cover every single-byte corruption of the empty snapshot, limits, atomic
replacement, explicit CLI intent, selection semantics, allocation-free matching,
and an actual upstream DNS exchange with filtering empty. The dashboard test
runs against both populated and empty snapshots.
