# Packed policy traversal and alternatives — 2026-11-06

The filtering engine now has an adaptive compiler: a single scope/action kind
keeps format v1; multiple kinds compile to format v2. Existing v1 snapshots still
load unchanged. V2 merges all rules for a hostname into one 63-bit policy value
and walks the reversed hostname once, emitting matching rules at DNS label
boundaries. The query path has no database access, allocation, mutex, hash-only
membership decision, or handwritten assembly.

## Format and tradeoffs

Both formats use the existing 32-byte header and checksummed FST v3 payload.
V1 magic is `DNGIDX01`, with payload length at byte 8, logical policy count at
byte 16, and zero reserved bytes at 24. Keys are scope/action tag plus reversed
hostname. Values contain seven category bits.

V2 magic is `DNGIDX02`. Byte 24 now holds distinct hostname count, verified
against the FST footer. Keys contain only the reversed hostname. The value holds
three 21-bit groups: Domain at bits 0–20, Exact at 21–41, Subdomains at 42–62.
Within each group, Block/Allow/Enforce each occupy seven bits. Bit 63 must be zero.
Logical count remains the number of distinct hostname/scope/action tuples, not
input rows or hostname count. The loader validates every name and recomputes
logical count from nonzero fields. Duplicate rules OR category bits exactly.

A full-name match combines Domain with Exact; an ancestor match combines Domain
with Subdomains. Actions accumulate across ancestors, followed by unchanged
allow/enforce precedence and enabled-category masking. Short suffix rules and
prefix-table terminal nodes remain eligible. One/two-character names, highest
category bits and shared FST outputs have oracle coverage.

V2 derives one two-byte table: 1,332 entries with an address and full u64 output,
21,312 bytes on this 64-bit machine. V1 uses 10,656 bytes per present kind (up to
95,904). Thus v2 costs more table memory for a single kind, but less for three or
more kinds. Compiler selection uses kind count, not a claim that every two-kind
corpus is faster or smaller. Two-kind and unusual distributions need further
qualification. No per-device copy is created. Adding categories beyond seven
would require a new format or metadata design.

Snapshots remain trusted local compiler artifacts. The checksum detects ordinary
corruption; it does not make third-party FST decoding safe against malicious
payloads with recomputed checksums. Old executables cannot read v2. Use the new
reader before publishing a mixed-policy snapshot, and retain rollback artifacts
within the same installed-size budget.

## Research decisions

| Alternative / primary evidence | Decision |
| --- | --- |
| [AdGuard urlfilter DNS engine](https://github.com/AdguardTeam/urlfilter/blob/master/dnsengine.go) indexes hosts to rule IDs and reuses request/rule buffers | Preserve exact metadata and avoid per-request allocation. Its broader rule language is not directly comparable to our prototype. No third-party code was copied. |
| [Unbound tuning](https://unbound.docs.nlnetlabs.nl/en/latest/topics/core/performance.html) covers workers, UDP reuseport and sharded cache locks | Share immutable policy data. Qualify reuseport when actual DNS transport exists; more workers cannot create CPU beyond a cgroup quota. |
| [Pi-hole history database](https://docs.pi-hole.net/database/query-database/) is updated periodically, once per minute by default | Keep event persistence off the lookup path, with explicit bounded buffering and loss accounting. |
| [Blocky configuration](https://github.com/0xERR0R/blocky/blob/main/docs/configuration.md) exposes cache/prefetch settings | Cache upstream responses only once TTL, policy revisions and cache capacity are implemented correctly. Prefetch consumes resources; it is not a free optimization. |
| [Rust inline assembly](https://doc.rust-lang.org/reference/inline-assembly.html) requires target-specific contracts | Keep safe portable Rust. Removing repeated traversal addresses algorithmic work; no hardware profile currently identifies an instruction sequence justifying handwritten assembly. |
| [rustc PGO](https://doc.rust-lang.org/rustc/profile-guided-optimization.html) uses representative execution profiles for branch/layout/inlining decisions | A compiler experiment is preferable to unmeasured assembly; profiles must cover realistic hits/misses and both formats before any release default changes. |
| [SQLite WAL](https://www.sqlite.org/wal.html), [durability](https://sqlite.org/pragma.html#pragma_synchronous), [covering indexes](https://www.sqlite.org/queryplanner.html) | One batched writer, short readers, bounded WAL and explicit storage accounting. Indexes improve selected reads at a measured space/write cost. No SQL query per DNS match. |

`target-cpu=native`, unchecked indexing, extra worker queues, a different allocator,
and an architecture-specific SIMD parser are not enabled as blanket optimizations.
The default binary must remain portable; production continues to forbid unsafe
Rust. Existing exact-hash measurements exceed the small RAM budget. Probabilistic
filters may only reject definite misses ahead of an exact check; they cannot
supply a final allow/block decision or eliminate exact-key storage by themselves.

## Reproduction and qualification

`examples/repack.rs` recompiles validated v1 artifacts without overwriting an
existing output. Its `--mixed NEW_DIRECTORY` mode emits matched v1/v2 fixtures
and 12,000 independently expected queries for 180,000 policies on 20,000 names.
That corpus deliberately exercises every kind and is **synthetic**, not company
traffic. `tools/bench/compare_matchers.py` alternates six before/after pairs, verifies
decisions before timing, and records hashes, sizes, and run-level percentiles.
CPU 7 pinning is not isolation from desktop or sibling-core activity.

The initial all-v2 candidate regressed on the real one-kind corpus: median run
p50 2.750 → 2.904 µs, p99 9.289 → 10.735 µs. Its file grew by 21 bytes. Those results
are retained in [candidate measurements](benchmarks/packed-real-comparison.json). Therefore
single-kind compilation now preserves byte-identical v1 output. The initial mixed
screen is [here](benchmarks/packed-mixed-comparison.json); a brief formatting/Python-check
command overlapped that screen, so use the clean selected-build rerun below for
reported comparisons.

New tests were observed failing before both the packed format and adaptive
single-kind selection were implemented. Coverage includes independent policy
oracles for all 128 enabled masks, exact collision behavior in the hash experiment,
legacy loading, count/output corruption, deterministic snapshots, concurrency,
limits, atomic publication, and allocation instrumentation of both formats.

## Source selection

`RuleSource { enabled, rules }` and `compile_sources` now rebuild from enabled
inputs only. This is an offline compiler API, not a UI toggle or downloader.
Disabled inputs do not consume the active-rule budget or enter the index. No
extra copy of all source strings is made: the compiler traverses borrowed active
rules, then builds its existing sorted entries. Source identities and fetching
remain the caller's responsibility; no full provenance table was added to the
lookup path.

Tests first failed because the API was absent. Passing cases show that disabling
one source removes its exclusive domain, preserves another source's category on
a shared domain, and leaves the previous immutable snapshot usable. Disabling an
allow source restores an active block. An all-disabled selection still fails the
existing nonempty compiler contract; the future service must explicitly activate
an allow-all policy instead of treating a failed rebuild as a successful toggle.

Removing entries does not guarantee every compressed FST gets smaller: structural
sharing and output factoring affect compression. Whole-list deletion usually
reduces data, but byte size must be measured and checked before publication.
Deleting a disabled source's retained input file is an updater operation still
to implement. The strict footprint plan retains only small source catalog records
and redownloads disabled payloads when re-enabled.

## SQLite experiment

[Probe](../tools/bench/sqlite_probe.py), [raw results](benchmarks/sqlite-batch-results.json).
This is a standalone experiment on the test filesystem (**Btrfs**) filesystem using
Python's SQLite **3.54.0**, not a production DB integration or a Rust DB benchmark.
Each run writes the same 8,192 synthetic events, WAL + `synchronous=FULL`, a 256 KiB
page-cache target, and automatic checkpoint threshold 64 pages. Write time includes
commit/checkpoint operations and after-commit file-size sampling. The four-run
order is single-row, 256-row batch, 256-row batch, single-row.

- Single-row commits: **183–230 rows/sec**.
- 256-row commits: **26,541–44,814 rows/sec**. This is achieved with fewer durable
  commits, not weakened SQLite sync settings. Application queue contents remain
  vulnerable until committed; batches add a waiting interval in a live service.
- A covering `(client, ts, id, blocked)` index changed the measured read plan from
  a full scan plus temporary sort to a covering range search. Median read latency
  dropped in every run, but DB file size rose from **155,648 to 307,200 bytes**.
- The sampled main/WAL/SHM file total during ingestion peaked at **456,248–464,488
  bytes**. Sampling is not an enforced maximum and does not include temporary
  peaks during later index creation. No claim that the eventual history service
  fits this size is implied.

All row counts, block counts, read results and integrity checks matched. Covering
index creation occurred after ingestion, so these runs do **not** measure its
ongoing insert-maintenance cost. No concurrent-reader/checkpointer test was run.
Retain batching and a small set of measured UI indexes as the design; do not add
SQLite access to the filtering path. PGO, SIMD and allocator replacement remain
unselected experiments, not claimed speedups.


## Assembly assessment

The current release already uses optimization level 3, LTO and one codegen unit.
Those settings produce optimized machine code from Rust. The inspected `fst`
0.4.7 node decoder has direct indexing for sufficiently wide nodes and a short
linear scan for smaller ones (`src/raw/node.rs`, `AnyTrans::find_input`). Our
prefix tables already bypass the upper two transitions. A SIMD scan could be
an experiment for remaining multi-transition nodes, but its dispatch/setup cost,
very short inputs, dependent node loads, and supported CPU targets need measurement.
Handwritten assembly does not remove those data dependencies or HTTP scheduling.

No assembly, SIMD, PGO or alternative allocator speedup is claimed in this pass.
The kept improvement removes repeated exact traversal and duplicates in mixed
policy data. Any assembly candidate should remain a separate benchmark variant,
pass the same independent policy oracle and boundary tests, beat portable Rust
on held-out workloads, and retain a portable fallback before entering a release.


## Fixed-budget HTTP verification

Final build, one worker, 200 VUs and 2,000 device labels. The runner verified
8 MiB charged memory, zero swap, and CPUQuota 50% (5 ms per 10 ms). k6 runs on
the same active desktop outside those limits. All 12,000 expected cases are
checked before each timed workload. The mixed screen uses the synthetic v2
index; the sustained run uses the real v1 index, byte-identical to the baseline.

| Corpus / duration | Target/s | Correct responses | Correct/configured second¹ | HTTP p99 ms | Matcher p99 ms | Server mean CPU² | Peak RSS MiB | Peak charged MiB | Drops |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| mixed / 30s | 2,500 | 64,935 | 2,164.50 | 171.293 | 0.025854 | 16.62% | 5.109 | 5.684 | 10,060 |
| real / 5m | 25,000 | 950,042 | 3,166.81 | 86.232 | 0.020463 | 22.32% | 6.711 | 7.438 | 6,549,698 |

Both runs have **0% HTTP response errors, 0% wrong-policy responses and zero OOM
kills**, but **both failed acceptance** due to dropped arrivals and HTTP p99.
The configured rate is not achieved capacity. Matcher optimization alone has
not met the end-to-end goal, and these are HTTP harness measurements, not real
DNS forwarding or complete-product tests.

¹ Correct responses divided by the configured arrival duration; late drained
responses may be included. The sustained k6 overall rate, including setup, is
3,029.59/sec. Resource sampling includes setup/drain/summary and spans 318.49 s
for the five-minute run. ² CPU 100% means one logical core. Sustained sampled
server CPU peaked at 31.77%; k6 averaged 308.94% CPU and peaked at 329.41 MiB RSS.
The generator and desktop contention prevent an isolated server-capacity claim.

[Reports/configuration/hashes](benchmarks/packed-load-results.json),
[per-second resource samples](benchmarks/packed-load-samples.csv),
[build/source manifest](benchmarks/packed-build-manifest.json). Transient benchmark units
are stopped by the runner. Compiles, tests and other benchmarks did not overlap
these HTTP workloads.


## Final direct comparison and validation

Six alternating pairs per corpus, both binaries pinned to logical CPU 7,
12,000 queries and 120,000 timed lookups per run. All expected blocked masks
passed before timing. These are medians of run percentiles, not a pooled
distribution or confidence interval. The host remains shared and unisolated.

| Corpus | Before p50 µs | After p50 µs | Before p99 µs | After p99 µs | Index before → after, bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| real | 3.950 | 3.650 | 13.032 | 12.819 | 1,889,139 → 1,889,139 |
| mixed | 27.230 | 3.245 | 88.100 | 8.598 | 2,088,839 → 428,680 |

The synthetic mixed case reduces p99 by **90.24%** (about 10.25× lower latency),
median latency by 88.08%, and snapshot size by 79.48%. This is the deliberately
mixed 20,000-host/180,000-policy corpus. It is not a tenfold service-throughput
claim. The real one-kind corpus retains its algorithm and byte-identical index;
its small p99 difference (1.63%) should not be interpreted as a robust new speed
gain. Earlier pairs had different absolute timings, demonstrating host drift.

[Final real pairs](benchmarks/packed-final-real.json), [final mixed pairs](benchmarks/packed-final-mixed.json).
Earlier adaptive-build measurements, before the source-selection API changed
executable hashes: [real](benchmarks/packed-selected-real.json),
[mixed](benchmarks/packed-selected-mixed.json). No compilation, tests, HTTP load or other
project benchmarks ran during the final direct comparisons.

**36 Rust tests, 11 Python tests, formatting and Clippy with warnings denied
passed.** No new production dependency or unsafe code was added. The final Linux
CLI is **418,008 bytes** (previously 406,928); the async test adapter is **746,032
bytes** (previously 736,752). CLI plus the real active index totals 2,307,147 bytes,
but this excludes future UI, DNS transport, analytics and update reservations.
The complete product's under-10-MB goal remains unproven.
