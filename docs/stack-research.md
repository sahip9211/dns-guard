# Stack selection and performance research

Research date: 2026-11-06. Product requirements: [goal.md](../goal.md).

## 1. Decision

Use a Rust service with Tokio, Hickory DNS, Axum, and SQLite through rusqlite. Match block rules against a compiled in-memory FST index, not SQL. Store history asynchronously through bounded queues. Under the all-in **under 10 MB** constraint, the first UI feasibility candidate is **egui/eframe compiled natively and to WebAssembly**, avoiding an additional desktop WebView framework. Tauri/Svelte remains a researched alternative, not a size-qualified selection.

The service stack is selected for a feasibility prototype. Resource numbers below are targets and sizing calculations; the policy engine and development benchmarks are implemented, while the DNS service, database and UI remain planned. The [all-in size budget](size-budget.md) takes precedence over larger storage examples below. Millions of exact rules and rich durable history may not fit alongside a desktop application in 10 MB. Primary documentation and challenge code were reviewed; no challenge benchmark was reproduced on the target hardware.

## 2. What the Twelve Dollar Server Challenge actually shows

The original repository is [arjaythedev/twelve-dollar-server-challenge](https://github.com/arjaythedev/twelve-dollar-server-challenge). Research inspected revision `3f9e34ac6bc16d9fe5bad378664a3265e22eda5e`, including the load script, batch report, and two Rust submission descriptions. An initially discovered repository was a copy; conclusions below use the original.

The challenge implements a small HTTP feed API backed by SQLite. Its rules constrain schema changes and application caching, allow transaction batching, and require correctness checks before scoring. It measures a five-minute hold with p95 below 500 ms, p99 below 1 second, and fewer than 1% failed requests. Those latency thresholds are much looser than our local cached-DNS target. [Challenge rules](https://github.com/arjaythedev/twelve-dollar-server-challenge/blob/3f9e34ac6bc16d9fe5bad378664a3265e22eda5e/README.md).

The public leaderboard snapshot dated October 25 reports `rust-iouring-kensac` at 310,000 users, 29,284 requests/second, p95 62 ms, p99 190 ms, zero reported errors, and 1,114 MB in its RAM column. It identifies a Synteq 1-vCPU/2-GB VPS, rather than the original DigitalOcean machine. These are maintainer-published measurements, not our measurements. [Published leaderboard](https://benchmarks.arjaythedev.com/12-dollar-server).

The load script deliberately includes think time: two reads, waits averaging 5 + 5.5 + 10 seconds, a 15% chance of a like, and a 2% chance of a post. Ignoring request time, that is about `2.17 / 20.5 = 0.106` HTTP requests/second per simulated user. Writes represent roughly `0.17 / 2.17 = 7.8%` of requests. Consequently, 310,000 users does not mean 310,000 requests/second or that many simultaneous database writers. A full DNS query log can be a much more write-heavy workload. [Load script](https://github.com/arjaythedev/twelve-dollar-server-challenge/blob/3f9e34ac6bc16d9fe5bad378664a3265e22eda5e/bench/load.js).

The leading submission uses Linux-specific io_uring, custom HTTP handling, SQLite B-tree internals for reads, SQL writes, group commits, and a separate checkpoint thread. Its documentation explicitly requires Linux kernel features and has no epoll fallback. Those constraints do not fit a portable desktop/network product directly. We will use SQLite's public API and maintained protocol parsers. [Implementation description](https://github.com/arjaythedev/twelve-dollar-server-challenge/blob/3f9e34ac6bc16d9fe5bad378664a3265e22eda5e/submissions/rust-iouring-kensac/README.md).

The batch report also explains that changing VM providers changed CPU-bound results substantially, and some apparent capacity ceilings were descriptor limits. This makes hardware, socket memory, failure thresholds, and workload definition essential to any comparison. [Batch 2 report](https://github.com/arjaythedev/twelve-dollar-server-challenge/blob/3f9e34ac6bc16d9fe5bad378664a3265e22eda5e/benchmarks/batch-2.md).

One Axum-labelled submission uses patched Hyper/Tokio and explicitly distinguishes exploratory short runs from repeatable five-minute contest results. We must not treat it as an out-of-the-box Axum benchmark. [Submission notes](https://github.com/arjaythedev/twelve-dollar-server-challenge/blob/3f9e34ac6bc16d9fe5bad378664a3265e22eda5e/submissions/rust-axum-mjc/README.md).

**Lessons adopted:** batch storage work, bound connection memory, isolate checkpoints and expensive queries, test the full system, and publish tail latency and loss. **Inference:** the challenge supports evaluating an embedded database seriously; it does not establish SQLite's capacity for our schema, encrypted DNS, or logging rate. It also does not establish Rust as universally faster than Go or other languages.

## 3. Entire selected stack

| Layer | Selection | Reason and constraint |
| --- | --- | --- |
| Core language | Stable Rust, Cargo workspace | Explicit ownership and memory control, no tracing garbage collector, shared language with native/WASM UI. Minimize unsafe application code; dependencies still require review. |
| Async networking | Tokio | Portable async I/O and bounded channels. Start with worker counts derived from the CPU quota; tune only from measurements. |
| DNS | Hickory protocol/server/resolver libraries | Reuse message handling, encrypted transports, and validation. Verify the pinned release's exact APIs and forwarding behavior in the first spike. |
| TLS | rustls, one supported crypto provider | Share configuration between DNS and management transports where practical. Start with the maintained default provider; compare footprint before selecting an alternative. |
| HTTP/API | Axum + Hyper + Tower | Versioned REST, input limits, deadlines, authentication, static asset serving, and streaming. No external reverse proxy required for a basic installation. |
| Serialization/API schema | Serde/serde_json; OpenAPI generated during development/build | One versioned contract for desktop, browser, CLI, and integration clients. Keep schema generators out of the shipped runtime when possible. |
| Desktop | egui/eframe native, minimal renderer/features; feasibility candidate | Share Rust view code with the browser build and avoid shipping a WebView framework. Must pass size, appearance, graphics, and accessibility gates. |
| Web UI | Same egui UI compiled to WebAssembly, wasm-bindgen/Trunk tooling | Count WASM/glue/assets in the service footprint. Shared source does not eliminate duplicate compiled native/web code. |
| UI styling/components | egui theme/layouts, compact icon/font assets | Own a polished visual system with measured asset sizes; avoid bundling complete icon/font collections. |
| Charts/tables | Small egui plotting layer, bounded rows and server pagination | Downsample time series; no millions of browser-side records. Compare chart-crate contribution before accepting it. |
| Durable storage | SQLite + rusqlite | Local embedded SQL, explicit transaction control, small fixed worker counts, no database service to administer. |
| Database migrations | Versioned SQL migrations executed by service startup/upgrade code | Transactional changes, schema-version checks, backup-before-upgrade, and explicit downgrade policy. No heavyweight ORM. |
| Rule index | `fst` maps plus compact metadata arrays | Immutable exact/suffix-rule index, shared by profiles; compare against radix trie and hash-set baselines. |
| Small mutable policy overrides | Rust maps with randomized hashing | Fast edits without rebuilding every feed; bounded size and periodic merge into a snapshot. |
| Snapshot activation | `arc-swap` | Publish one consistent policy/index revision without a global read lock on every query. |
| DNS cache | Byte-budgeted sharded LRU/TTL layer using the `lru` crate and short locks | Entry and byte caps, policy/upstream isolation, explicit expiry and admission. Avoid a second hidden unbounded resolver cache. |
| Feed fetching | reqwest using rustls, streaming to staging files | Conditional HTTPS requests, deadlines, bounded downloads, limited parallelism, digest/provenance recording. |
| Feed compression | Zstandard for published downloads; FST for searchable domain keys | Transfer compression is decoded once into the staged index. Compact keys/metadata remain directly searchable; no archive decompression per query. |
| Authentication | Argon2id password hashes, random opaque sessions, hashed scoped API tokens | Bound concurrent password checks; session validation must not run a memory-hard password hash on every API call. |
| Observability | tracing + bounded metrics/Prometheus export | DNS counters/histograms, sampled diagnostics, no per-query text formatting by default. No mandatory telemetry collector. |
| UI build tooling | Cargo, wasm-bindgen, Trunk, wasm-opt; Node.js LTS/pnpm for browser tests only | Lock tool versions; no Node.js runtime is shipped. Measure WASM optimization effects and compatibility. |
| Tests | cargo-nextest, proptest, cargo-fuzz, Criterion; Rust UI tests/egui_kittest; Playwright; native OS smoke tests | Cover libraries, protocols, browser UI, and actual native behavior independently. |
| Load/profiling | DNS-OARC dnsperf/resperf; k6 for API; perf/flamegraphs and heaptrack on Linux | Separate load generator, whole-system measurements, deterministic upstream fixtures, long soak tests. |
| Release/CI | GitHub Actions with native OS runners; Cargo and native distro/OS packaging | Locked builds, checksums/signatures, SBOM, dependency/license checks, all-in byte gate, installer/service-lifecycle tests. |

Hickory documents reusable Tokio-based libraries and optional transport features. Axum supplies HTTP routing on the Tower ecosystem. These support the architecture; they are not performance measurements for our application. [Hickory](https://hickory-dns.org/), [Axum](https://docs.rs/axum/latest/axum/).

egui/eframe supports native and browser targets; its documentation describes native entry points and a WebAssembly browser runner. This establishes portability as a candidate, not a guarantee of a sub-10-MB full application. [egui](https://github.com/emilk/egui), [eframe](https://docs.rs/eframe/latest/eframe/).

### Alternatives considered

| Alternative | Decision |
| --- | --- |
| Go + miekg/dns + Svelte, with a Tauri shell | Credible fallback with strong DNS precedent. Rust better matches the requested memory/tail-latency priority and avoids maintaining both Go and Rust in the core product. GC cost is workload-dependent, not an automatic disqualification. [Go GC guide](https://go.dev/doc/gc-guide), [miekg/dns](https://github.com/miekg/dns). |
| C/C++ or Zig DNS core | Potentially compact, but increased protocol/memory-safety or ecosystem burden. No demonstrated need to accept it. |
| Linux-only io_uring/custom HTTP stack | Reserve for a future measured bottleneck; it adds portability and maintenance costs before proving benefit for this workload. |
| Tauri + Svelte + uPlot | Strong shared desktop/web option when system WebViews are outside the package budget. The user explicitly includes extra runtimes, so it is not certified under the current cap. [Tauri size guidance](https://tauri.app/concept/size/). |
| React | Reasonable web alternative but does not solve the desktop runtime/data size constraint. |
| Electron | Its bundled browser/runtime does not fit this all-in footprint objective. |
| Slint or other native widgets | Additional feasibility candidates if egui misses size, accessibility, or product-UI targets; verify browser build and licensing before adoption. |
| Server-rendered HTML/HTMX | Very small client possible, but the shared desktop UI, live explorer, and policy editors favor a static application with a common API. |
| Redis, Kafka, separate API microservices | Add deployment and operational overhead to a single-appliance product. Revisit only for optional centralized services with demonstrated demand. |

## 4. Concurrency and capacity model

Use `QPS = active_devices × average_queries_per_device_per_second` as a sizing input, then test correlated bursts independently. The rates below are explicit assumptions, not measured typical device behavior.

| Devices | Assumed mean DNS rate/device | Sustained QPS | 4× burst |
| ---: | ---: | ---: | ---: |
| 1,000 | 0.2/s | 200 | 800 |
| 5,000 | 0.5/s | 2,500 | 10,000 |
| 10,000 | 0.5/s | 5,000 | 20,000 |

For upstream concurrency, Little's law gives `in_flight ≈ arrival_rate × response_time` in steady state. At 2,500 QPS, an assumed 80% local-answer rate, and 40 ms upstream latency, mean forwarded concurrency is `2,500 × 0.2 × 0.04 = 20`. A cold cache or slow upstream can increase this sharply; explicit in-flight limits and deadlines are still required. This calculation does not size TLS connection pools or burst queues by itself.

Execution model:

1. Receive DNS messages into bounded buffers; apply admission and protocol limits before expensive work.
2. Read one consistent policy snapshot; identify the applicable profile and forwarding route.
3. Check explicit rules, category membership, and the bounded DNS cache.
4. Forward misses using reusable upstream connections and bounded outstanding work. Coalesce only requests with compatible route, validation, and policy context.
5. Send the DNS response; update cheap counters and attempt a nonblocking analytics enqueue.
6. Storage workers batch events. UI requests and feed compilation have their own limits and cannot execute blocking work on DNS runtime threads.

There is no thread, database connection, or independent policy-index copy per device. Tokio tasks are not OS threads, but tasks and their queues still need bounds. SQLite and other blocking work belong on a small fixed set of worker threads, not an unbounded `spawn_blocking` call per request. [Tokio blocking-task behavior](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html).

Memory is budgeted as:

`service = runtime + policy/index + DNS cache + active requests/connections + analytics queue + DB caches + query workspace + update overlap`.

An initial office allocation to test is roughly 32 MiB baseline/runtime, 48 MiB rules/metadata, 32 MiB DNS cache, 24 MiB active-request/connection allowance, 8 MiB event queue, 24 MiB total DB page caches, and 16 MiB UI/query/aggregation workspace. That is 184 MiB before allocator/stack overhead; the 256 MiB steady target leaves margin. These are allocation proposals, not measured library footprints. Ten thousand encrypted connections require a separate measured profile and may exceed this budget.

List compilation must account for the old index, staged input, new index, sorting buffers, metadata, and active readers retaining an old snapshot. Limit concurrent builds and use external sorting where needed. Reject or defer a new snapshot if it cannot fit the update budget; keep the working one.

## 5. Database choice

### SQLite is the primary store

SQLite matches an appliance's local, low-administration storage needs. WAL permits concurrent readers with a writer, but there is still one writer at a time per database file. Increasing the connection pool does not create parallel writers. Keep databases on local storage, with bounded read duration so readers do not hold checkpoints back indefinitely. [SQLite use cases](https://www.sqlite.org/whentouse.html), [WAL concurrency](https://www.sqlite.org/wal.html).

Choose **rusqlite with explicit workers and prepared SQL**. Its synchronous API makes ownership, batching, cancellation boundaries, and memory budgets visible. SQLx is a valid alternative, but its SQLite async interface also uses background threads; it does not turn SQLite into a nonblocking database engine or remove the single-writer constraint. This is an architecture preference, not a measured claim that SQLx is slow. [rusqlite](https://docs.rs/rusqlite/latest/rusqlite/), [SQLx SQLite implementation](https://docs.rs/sqlx/latest/sqlx/sqlite/struct.SqliteConnection.html).

| Candidate | Fit | Decision |
| --- | --- | --- |
| SQLite | Embedded configuration, indexed history, bounded summaries | Selected. Validate sustained ingestion and query cost with our schema. |
| PostgreSQL | Concurrent write-heavy central services and multi-node administration | Optional future central service. Local deployment does not need its separate server/process/maintenance model. |
| DuckDB | Broad analytical scans, offline exploration and columnar workloads | Consider as an external/offline analysis tool later, not the mandatory local configuration/logging engine. Its analytic concurrency design does not automatically solve our latency isolation needs. [DuckDB concurrency](https://duckdb.org/docs/2.0/connect/concurrency). |
| redb | Embedded Rust key/value storage and transactions | Attractive for simple key/value state, but relational filtering/reporting would require us to build more indexing/query machinery. Avoid a second engine without evidence. [redb](https://github.com/cberner/redb). |
| RocksDB/LMDB | Specialized embedded key/value workloads | Not selected: added operational/indexing tradeoffs without a demonstrated benefit over SQLite for our data access patterns. |
| ClickHouse | Central long-retention analytical ingestion | A possible later export destination, not a dependency on every desktop or small server. |

### Data ownership and files

| Store | Data | Write policy |
| --- | --- | --- |
| `config.sqlite` | Profiles, rules, devices, schedules, source registry, administrators, schema versions, configuration audit | Low-volume dedicated writer, WAL + `synchronous=FULL`; save success only after commit and snapshot activation status is known. |
| `queries/<segment>.sqlite` | Time-ordered DNS event metadata | One active ingestion writer; WAL + `synchronous=NORMAL`; rotate by time or size. |
| `summary.sqlite` | Explicit rollup dimensions, ingestion watermarks, retention metadata | Batched updates by the analytics worker; rebuildable where retained raw data exists. |
| Versioned compiled index files | Domain keys, compact category/rule metadata, source digests | Build in staging, validate, then atomically activate an immutable revision. |

Use one configuration writer and one analytics writer initially; the latter owns writes to active log and summary files. Start with one read worker in the small profile and two in the office profile, plus a separately capped maintenance task. Open historical segments only as needed through a bounded handle cache. Do not allocate connections proportional to client count or segment count.

Transactions across separate WAL databases are not assumed to be atomic together. For metadata mode, commit raw events first and advance the summary's segment/event watermark in the same transaction as its rollup updates. Resume idempotently from that watermark after a crash. Delete a raw segment only after required summaries are complete. Live in-memory counters are separately labeled and may be ahead of durable history; do not promise a zero-loss crash history.

### Durability, batches, and limits

- Begin with `256 events or 100 ms`, whichever occurs first, for metadata batches; benchmark 64/256/1,024 events and 25/100/250 ms intervals. Fixed caps on batch bytes and queue bytes override event count.
- `WAL + NORMAL` preserves database consistency but may lose recent commits after power/OS failure. `FULL` adds commit synchronization. Use the latter for configuration and clearly disclose the former's history loss window. Neither setting makes unflushed application-queue events durable. [SQLite synchronous modes](https://sqlite.org/pragma.html#pragma_synchronous).
- Use a maintained bundled SQLite release that includes the WAL-reset correction. Official SQLite documentation identifies the fix in 3.51.3 and later, with certain backports. Check the actual bundled engine, not only the rusqlite version. [SQLite WAL-reset fix](https://www.sqlite.org/wal.html#walreset).
- Prepared statements and a single batch transaction amortize overhead. Keep foreign-key validation and migration checks appropriate to each schema; do not disable correctness globally for a benchmark.
- Give every connection a modest page-cache budget; total cache allowance includes all open databases. Start with memory mapping disabled, then measure it separately with OS page-cache memory included.
- Use background/passive checkpoints, WAL size monitoring, bounded read transactions, query interruption, and explicit recovery from `BUSY`/disk-full errors. A size-limit pragma alone cannot guarantee a live WAL stays bounded while readers pin it.
- Under pressure, cancel expensive reports and stop admitting additional raw history before exhausting disk or blocking DNS. Keep policy serving and global counters alive; mark missing detail explicitly. Never silently claim complete history after dropping records.
- Strict lossless durable recording of every DNS reply would require a different availability/latency contract, such as waiting for a durable append before responding. It is outside the low-latency default.
- Back up live SQLite through the supported backup API or an equivalent consistent snapshot; copying only the main database file while a WAL is active is not the backup design. [SQLite backup API](https://www.sqlite.org/backup.html).

### Storage grows faster than the executable

For planning, assume **200 bytes per event including indexes**. This is a sizing assumption; measure the actual schema with realistic domain lengths, client distribution, answers, and indexes. WAL, backups, temporary query space, and free-space reserve add to these figures.

| Sustained QPS | Events/day | Approximate metadata/day at 200 bytes/event |
| ---: | ---: | ---: |
| 100 | 8.64 million | 1.73 GB |
| 1,000 | 86.4 million | 17.28 GB |
| 2,500 | 216 million | 43.2 GB |
| 10,000 | 864 million | 172.8 GB |

At 2,500 QPS a 4-GiB raw-history allowance would hold only about 2.4 hours at that assumed size, before overhead. A 30-day full event history cannot share the small-machine promise at these rates. Compression and deduplication can improve this but do not eliminate the retention decision.

Under the latest all-in 10 MB requirement, the earlier idea of a separate hundreds-of-MiB/GiB analytics allowance is rejected. Analytics must share the remaining bytes after executables and indexes, with strict database/WAL/temp caps. Live in-memory views can still show detail, but durable retention must state its measured window. The larger numbers above explain the unresolved conflict; they are not permitted defaults. External storage is not a hidden workaround for the cap.

Bound rollup cardinality too. Ten thousand clients times 1,440 minute buckets already means 14.4 million possible rows/day before domain dimensions. Keep global minute totals, short-lived per-client minutes, longer per-client hours, and bounded top-domain summaries. Do not materialize a client × domain × minute cube. Approximate rankings must be labeled; retained raw-history searches can compute exact counts within a bounded range.

## 6. Efficient matching and history search are different problems

### Blacklist matching: compiled index, no SQL

The serving representation is an immutable `fst` map with compact side tables for rule IDs, category bitsets, match semantics, and source references. The library compresses common key structure and supports efficient byte-string sets/maps. `arc-swap` publishes a consistent read-mostly snapshot. [FST documentation](https://docs.rs/fst/latest/fst/), [ArcSwap](https://docs.rs/arc-swap/latest/arc_swap/).

Preserve exact-domain and domain-plus-subdomain rules as separate semantics. Canonicalize source domains once: lowercase ASCII/IDNA form, normalized trailing dot, valid DNS label boundaries and lengths. DNS wire names are not always ordinary hostnames; malformed or non-hostname queries need protocol-correct handling, not indiscriminate IDNA conversion.

For `video.ads.example.com`, suffix candidates are label-boundary names such as `ads.example.com` and `example.com`. A suffix rule for `example.com` must never match `notexample.com`. Wildcard-only-subdomain rules must retain their distinction from rules that include the apex.

Use reversed-label keys when useful (`com.example.ads`) to exploit common structure and enable a reverse-label radix-trie alternative. With safe high-level FST lookups for each suffix, worst-case work is bounded by label count times key length, not magically O(1). A dedicated radix traversal can walk labels once. Benchmark before deciding whether its implementation complexity earns its place.

| Candidate | Properties | Planned use |
| --- | --- | --- |
| `HashSet<String>` | Expected constant probe count, but hashes/comparisons still read key bytes; per-entry allocation/table overhead | Simple correctness and performance baseline, plus small override sets. |
| Sorted packed keys + binary search | Predictable storage; logarithmic comparisons | Low-complexity memory baseline. |
| FST map | Compressed immutable keys; build cost and suffix-query strategy matter | Selected first implementation for bulk feeds. |
| Reverse-label radix trie | One traversal along domain labels; node layout determines memory | Benchmark challenger if FST suffix lookups dominate. |
| Bloom filter + exact index | Fast rejection possible; false positives require exact verification | Optional only if measurements show an overall win. |
| Minimal perfect hash | Compact indexing for a fixed key set, but arbitrary nonmember keys still require verification | Later candidate; preserve exact keys or collision-safe verification. |

Bloom-filter sizing for `n` entries and desired false-positive probability `p` is approximately `m = -n ln(p)/(ln 2)^2` bits and `k = (m/n) ln 2` hash probes. At one million entries and 1%, this is roughly 9.6 million bits (1.2 MB) and seven probes. That filter is additional storage, not a replacement for the exact index. It may hurt a small already-cached index; membership of every relevant suffix also needs correct handling. False positives must never directly cause a block. [Broder and Mitzenmacher's Bloom-filter survey](https://www.eecs.harvard.edu/~michaelm/postscripts/im2005b.pdf).

Category matching uses compact bitsets: intersect a domain's category flags with the profile's enabled-category flags, then apply rule priority and exceptions. Share the global index between clients; keep only profile configuration and overrides per group. Preserve all relevant source/reason references in side tables, rather than duplicating strings for each profile.

Do not store only a short domain hash and assume collisions are impossible. Do not use fuzzy similarity to decide exact blocking. Apply regex only in a separately bounded stage using Rust's finite-automata regex ecosystem, with compile/input limits; avoid pathological backtracking engines.

A cached result must not bypass policy changes. Cache keys/snapshots account for forwarding route, validation context, record type/class, and policy revision where answers depend on policy. Re-evaluate response CNAME rules under the active profile. If caching raw upstream data across profiles, apply profile-specific rules again before responding. Schedule changes invalidate relevant derived answers; client-side caches remain outside our control.

### Compression and tens of millions of entries

Use two layers: **Zstandard for distribution**, and **FST keys plus packed metadata for serving**. Compressing a text file alone does not provide fast random membership lookup. Verify/decompress a downloaded index once into a staging file, validate its format, and activate it atomically. [Zstandard](https://github.com/facebook/zstd).

Share common key structure and intern repeated metadata strings once per snapshot. Keep category membership as bitsets and source/rule IDs as packed integers or shared posting lists. Preserve exactness; compression must not create hash-collision blocks or erase exceptions. A parent-domain suffix rule can replace child rules only when their action, scope, priority, category behavior, and exception semantics are equivalent; retain explanation provenance separately.

At ten million entries, even a hypothetical 16-byte metadata record per rule is 160 MB before keys. At thirty million it is 480 MB. These are arithmetic examples, not proposed unavoidable allocations: sharing category/source combinations can reduce them. Measure keys, metadata, override maps, mapped resident pages, and build buffers independently so index savings are not hidden by large side tables.

Small devices should normally download precompiled snapshots. For local custom compilation, stream parsing into sorted bounded runs, merge/deduplicate on disk, and build the immutable index from the ordered stream. Do not build one giant `HashSet<String>` or clone all data when activating a new version. Keep snapshot versions in separate files and close readers before retiring an old file, including on Windows.

Memory mapping is an option for large immutable indexes, not free RAM: resident pages count toward physical memory, and page faults can hurt p99. Measure a fully warm index, cold start, random-domain traffic, and memory pressure. A large dataset may require more RAM to meet the same latency target even if it is stored compactly.

Acceptance candidates: 100k, 1m, 5m, 10m, and 30m unique-rule fixtures, with observed and adversarial domain distributions. Compare FST, radix-trie, sorted-packed-key, and hash-set implementations against a simple exact oracle. Record bytes/rule, build seconds, update peak, lookup p50/p95/p99, CPU, cache misses, and effective policy correctness. An initial warm-index matcher target is p99 below 100 microseconds at ten million rules on the declared office-class test CPU; validate or revise it before making claims. End-to-end DNS latency remains a separate gate.

First measured evidence: a [historical Rust probe](benchmarks/index-probe-results.json) compiled 178,507 unique HaGeZi Light/NSFW rules into a 1,841,357-byte reversed-label FST with two category flags. The recorded warm local p99 was 4,783 ns; stored-key and sampled suffix comparisons passed. Full provenance/policies, cold-cache behavior, concurrency, and larger datasets remain unmeasured. This supports continuing the FST investigation but does not meet the provisional 1 MB index budget. [Machine and measurements](benchmarks/index-probe-results.json).

### History search: B-tree indexes and bounded result sets

Use numeric event/client/profile/rule IDs and typed columns rather than a large JSON document per query. Initially store canonical domain text inline, with optional response detail in a separate short-retention table. Prototype dictionary-encoding domains only if measured size savings outweigh extra lookups and maintenance. Never keep an unbounded domain-interning map in RAM.

Candidate indexes for each log segment:

```sql
CREATE INDEX event_time ON events(ts_ms DESC, id DESC);
CREATE INDEX event_client_time ON events(client_id, ts_ms DESC, id DESC);
CREATE INDEX event_domain_time ON events(qname, ts_ms DESC, id DESC);
```

Example client-history page:

```sql
SELECT id, ts_ms, qname, qtype, decision, latency_us
FROM events
WHERE client_id = ?1
  AND ts_ms >= ?2
  AND (ts_ms, id) < (?3, ?4)
ORDER BY ts_ms DESC, id DESC
LIMIT ?5;
```

This is keyset/cursor pagination; it avoids increasingly expensive `OFFSET` scans. Index seek cost is generally logarithmic in indexed rows, followed by output work. Check `EXPLAIN QUERY PLAN`, tie ordering, and realistic selectivity. Merge results across only the segments intersecting the requested time range, with a cursor including segment identity.

For exact domain search, use canonical equality. For suffix search, evaluate a reversed-label auxiliary key with a bytewise prefix range and correct boundaries; add that index only if real usage justifies its write/storage cost. Leading-wildcard `LIKE '%text%'` is not a fast indexed lookup. Arbitrary substring search should be explicitly bounded or deferred to an optional search index, not silently scan months of data.

Use rollup tables for overview charts, time filters for logs, and query deadlines for broad reports. Add profile/decision partial or composite indexes only after query-plan benchmarks. Every index costs insert work, disk space, and cache; indexing every field is incompatible with the resource objective.

## 7. Desktop/web integration and security boundaries

The desktop uses trusted native UI code. A narrow platform adapter handles server connections, credential storage, tray actions, and service-management requests. The browser hosts the WASM UI and uses the same API over same-origin HTTPS. Keep the transport adapter small so business logic and screens remain shared.

The service supplies data through authenticated APIs, never arbitrary executable UI updates. Validate TLS, restrict native service-management commands, and keep web CSP/origin protections. If a WebView-based alternative is later qualified, restrict its capabilities and never give remote content native privileges. [Tauri security model for that alternative](https://tauri.app/security/).

Use loopback-only bootstrap, one-time setup credentials, secure cookies for browser sessions, CSRF/origin/Host protections, request limits, and rate-limited login. The service enforces authorization for every state change, including requests from the desktop. Restrict expensive Argon2 operations to a small semaphore to protect the memory budget.

The service owns port 53 and persists independently of the UI. Linux service capabilities should be limited to what is needed, such as binding a privileged port. Windows/macOS need their own service installation and DNS configuration adapters. Remote management does not grant local OS privilege. [systemd execution controls](https://man.archlinux.org/man/systemd.exec.5.en).

## 8. Testing and release stack

| Layer | Tools | Required evidence |
| --- | --- | --- |
| Rust correctness | cargo-nextest, proptest | Rule precedence, suffix boundaries, Unicode handling, cache isolation, schedule/DST transitions, queue bounds, migrations. |
| Protocol integration | Rust integration harness, deterministic upstream server, `dig`/`kdig` | UDP/TCP/IPv6, truncation, EDNS, CNAME loops, DNSSEC fixtures, DoH/DoT trust failures, cancellation and outage behavior. |
| Fuzzing | cargo-fuzz/libFuzzer | DNS parsing integration, list parsers, rule compilation, import formats, malformed compressed names. |
| Storage | Real temporary on-disk SQLite databases | Batch ingestion plus dashboard readers, checkpoint progress, crashes, power-failure simulation where available, full disk, restore, idempotent summaries. |
| Component UI | Rust view-model tests + egui_kittest | Forms, keyboard behavior, errors, policy explanations, controlled timers and snapshots. |
| Browser end-to-end | Playwright Chromium/Firefox/WebKit | WASM startup, setup, logs, schedules, keyboard interaction, layout, and API behavior. Canvas accessibility requires explicit verification; a DOM scanner alone is insufficient. |
| Native desktop | Native platform smoke/input tests plus Rust UI harness | Actual windows, graphics, local/remote connections, service-independent lifecycle, accessibility and packaged assets. |
| Microbenchmarks | Criterion | Exact/suffix matching, 100k/1m/5m rules, cache lookup, policy evaluation, normalization, batch encoding. |
| DNS capacity | DNS-OARC dnsperf/resperf plus a distinct-client harness | Open-loop offered load, throughput, p50/p95/p99, drops, TCP/encrypted connections, realistic mixed queries. |
| API capacity | k6 | Concurrent charts/history queries/exports while DNS remains loaded. |
| Profiling | Linux perf/flamegraphs, heaptrack; platform memory tools on Windows/macOS | CPU hot spots, allocations, resident and whole-system memory, package/asset sizes. |
| CI hygiene | rustfmt, Clippy, cargo-audit/cargo-deny, dependency audit, SBOM and installed-footprint audit | Locked dependencies, compatibility/size/supply-chain checks; automated scans do not prove security. |

Playwright browser testing is not a substitute for testing native windows and graphics. The Rust UI harness tests shared behavior; separate packaged-app checks cover platform integration. For the researched Tauri alternative, its documentation recommends WebdriverIO's Tauri service. [Playwright browsers](https://playwright.dev/docs/browsers), [Tauri alternative testing](https://tauri.app/develop/tests/webdriver/).

Use nextest for execution/isolation, cargo-fuzz for fuzz workloads, and DNS-OARC's tools for DNS load rather than treating an HTTP benchmark as a DNS test. [nextest](https://nexte.st/), [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html), [dnsperf/resperf](https://www.dns-oarc.net/tools/dnsperf).

### Acceptance matrix

Run on an actual one-vCPU/2-GiB VM with local SSD and no swap, and separately on a small ARM64 machine. Record CPU model, storage, kernel, CPU quota, library versions, and network RTT. A process cgroup limit on a larger desktop is useful but is not the same experiment as a whole constrained VM.

- Local-answer mix: explicitly 80% cached/blocked and 20% forwarded, plus separate all-cache-miss runs; use a controlled upstream delay before testing public resolvers.
- Sustained office workload: 5,000 distinct client identities, 2,500 QPS for 30 minutes, 1 million rules, complete metadata logging and two active dashboards; require no metadata drops.
- Burst workload: 10,000 QPS for 60 seconds; record latency, queue recovery, and any lost history. Report whether the lossless requirement passed rather than hiding drops.
- Connection workload: 10,000 idle and then active TCP/DoT/DoH clients, with TLS reconnect bursts tested independently from steady query throughput.
- Update workload: replace lists and change schedules during load; record peak memory and check that blocked domains do not leak across policy versions.
- Analytics workload: search realistically sized retained history while ingesting, checkpointing, deleting old segments, exporting, and viewing charts.
- Overload workload: rates beyond capacity, slow clients, bogus domains/random subdomains, upstream outage and timeout storms; verify bounded memory and fair admission.
- Endurance: 24-hour soak, service restarts, failed migration/restore, disk exhaustion, corrupted feed, and rollback to the last valid policy.

Generating many requests from one source address is not a test of 5,000 per-device profiles. Use isolated source addresses/network namespaces or the actual supported authenticated client-identity mechanism. Do not add a production identity header solely to make the benchmark easy.

Compare AdGuard Home and Blocky on the same machine, rule semantics, cache capacity, protocol mix, and logging settings; publish configurations. Include both equal-functionality and default-config tests. Do not compare our no-log build against a competitor retaining full history.

## 9. Packaging, dependencies, and rollout

- Build native x86_64/ARM64 artifacts separately; report compressed download, executable/assets, added dependencies, active data, and staging independently, and enforce their combined installed-footprint cap.
- Arch: separate service and desktop packages, `PKGBUILD`/`.SRCINFO`, systemd unit, configuration backup entries, service account, and clean-chroot package checks. Package-managed installs update through the package manager, not an application updater overwriting managed files.
- Other Linux: `.deb`/`.rpm` for service integration; AppImage as an additional desktop distribution. A GUI AppImage alone is not a privileged service installer.
- Windows: signed native installer, Windows Service registration, native graphics compatibility, and reversible local DNS setup.
- macOS: signed/notarized desktop build, launchd service installation, native credential storage, and explicit Intel/Apple Silicon testing.
- Server/container: daemon plus web assets only, non-root operation where possible, persistent volume, health checks, and no mandatory display stack.
- Pin a supported Rust toolchain and all dependency graphs. Produce release hashes, SBOM and signed artifacts; publish build configuration and supported OS minima.
- Start with release optimization and dead-code elimination, then measure LTO/codegen-unit changes and optional-feature pruning. Do not use machine-specific CPU instructions in generic release binaries. Keep debug symbols separately.

Packaging tools do not automatically solve privilege management, service lifecycle, signing identities, or every target architecture. Validate these through native packages and clean-system tests. [Arch PKGBUILD](https://man.archlinux.org/man/PKGBUILD.5.en).

## 10. First implementation gate

Implement a narrow benchmarkable vertical slice before the complete dashboard:

1. Hickory forwarding + exact/suffix rule index + isolated bounded cache.
2. A real disk-backed SQLite writer with the proposed indexes and simultaneous reader queries.
3. One Axum API and the shared native/WASM screen, with all added dependencies measured.
4. Repeatable source-list snapshot and compile pipeline, including provenance, update failures, and memory peaks.
5. Automated correctness tests and the small/office acceptance workloads.

The service stack stays selected unless this gate reveals a specific problem. The GUI choice is explicitly provisional until the all-in size test passes. Replacement decisions should cite measurements: binary/index size, memory, cache contention, upstream handling, ingestion, graphics compatibility, or packaging. Do not silently drop the requested corpus/history to claim success under 10 MB.
