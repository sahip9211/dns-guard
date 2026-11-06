# Bounded DNS response cache

The service now has an in-memory response cache. Its default budget is 262,144
bytes. `serve --cache-bytes 0` disables it; explicit enabled budgets range from
4 KiB to 16 MiB. The larger limit supports experiments, not a promise that those
settings fit the 8 MiB service profile. No cache database or persistent cache file
is created, and no new dependency was added.

## Lookup, collision handling and memory accounting

A process-randomized hash selects a set with four slots. A hit requires comparison
of the complete request key, not just its hash. Each set has a fixed share of the
payload budget and evicts its least recently used entry when necessary. Lookup
and eviction inspect at most four slots; there is no growing queue or linked list.
Set-local quotas can leave unused space in other sets, favoring bounded work over
perfect capacity utilization.

The budget counts the cache structure, slot table, stored request/response bytes
and TTL-offset arrays. It excludes allocator bookkeeping/rounding, transient
parsing/key/response buffers, the mutex and the rest of the service. It is not an
RSS cap; whole-process/cgroup measurements are still required. Cached packets
are at most 4,096 bytes and 128 records, and a set's byte quota may reject a packet
below those caps. Oversized responses still forward normally.

The cache mutex covers only bounded memory operations, never DNS I/O or an await.
The CLI uses one runtime thread; the mutex also keeps library use safe if a caller
uses a multithreaded runtime. Policy matching remains independent of this lock.

## Eligibility and isolation

Keys preserve the question, case, record type/class, flags and empty-EDNS variant.
Only the transaction ID is omitted. Case variants may miss intentionally, so a
response never borrows another request's question capitalization. The cache belongs
to one server instance with immutable policy/upstream configuration. Question
filtering runs before cache lookup; CNAME target filtering runs before admission.
Blocked replies are not inserted.

Supported entries are positive replies containing the requested record type and
plain NXDOMAIN/NODATA replies with an applicable SOA. Negative replies containing
CNAME answers, referrals without SOA, SERVFAIL/REFUSED, truncated packets, zero-TTL
records, transaction signatures and signed answers are not admitted. DO requests
and requests/responses containing EDNS options bypass caching, including contextual
options such as ECS and cookies. These variants still use the forwarding path.

Empty EDNS OPT records are removed from stored packets and regenerated for the
current request, rather than treating transaction metadata as cached records.
Only a final empty OPT can be stripped safely while retaining opaque record data
and compression offsets; other layouts bypass admission.

Future live policy/upstream/profile changes must invalidate or partition dependent
cache generations before activation. That management feature is not implemented;
restarting the current service creates a fresh cache. Query coalescing, adaptive
cache admission, DNSSEC-aware caching and stale serving also remain unfinished.

## Expiry and packet correctness

A complete cached packet expires at the shortest real-record TTL, with a local
maximum of one day. Negative lifetime also respects the minimum of the applicable
SOA record's TTL and MINIMUM field. TTLs with the high bit set are not cached.
This follows the bounds in [RFC 2181](https://www.rfc-editor.org/rfc/rfc2181#section-8)
and the negative lifetime rule in
[RFC 2308](https://www.rfc-editor.org/rfc/rfc2308#section-5).

Every cached real-record TTL is reduced to the remaining whole-packet lifetime,
rounded down. This conservatively shortens longer TTLs rather than extending any
record's lifetime. Hits do not renew expiry. Both monotonic and wall-clock deadlines
are checked: a clock rollback cannot extend monotonic lifetime, and wall-clock
expiry catches suspend periods on platforms whose monotonic clock pauses.

Response records retain their original bytes and compression offsets. A cache hit
changes the transaction ID, clears AA/AD and updates recorded TTL fields; it does not
re-encode unknown RDATA. OPT handling is separate, consistent with
[RFC 6891](https://www.rfc-editor.org/rfc/rfc6891#section-6.1.1). UDP size limits still
apply on hits; a full cached answer can be returned to a subsequent TCP request.

## Metrics and tests

`cache_hits` and `cache_misses` count eligible lookups. Bypassed and locally blocked
requests are outside that denominator. `cache_entries` and `cache_bytes` report
resident cache storage, including expired entries not yet revisited; they are not
counts of currently valid records. `cache_evictions` counts capacity evictions,
not ordinary expiry. Shutdown output retains the last occupancy measurement.

Tests use injected monotonic timestamps and controlled wall-clock expiry for
aging/expiry without sleeps, forced collisions, repeated admission under a byte
limit, invalid/truncated packets, EDNS regeneration, negative answers and key
isolation. Socket tests close the mock upstream after the first reply and verify
subsequent UDP/TCP cache hits, correct IDs, negative caching, CNAME exclusions and
UDP truncation with a full cached TCP answer.
