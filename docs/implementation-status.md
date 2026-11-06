# Implementation status

DNS Guard is a DNS filtering prototype with UDP/TCP forwarding. It does not yet
provide mutable web administration, a desktop shell, persistent analytics or a
background updater. A read-only browser dashboard is implemented.

## Implemented

- Optional embedded dashboard, versioned aggregate status and active hostname-policy APIs, using Hyper,
  Serde and a separate bounded runtime thread. Independent management tokens use
  native credential libraries or explicit private credential files. See
  [management API](management-api.md) for the exact security and resource scope.

Private policy index encryption and installed per-instance service
identities are still unfinished. Encryption currently covers configuration and
its rollback journal; see [security scope](security-model.md).

- Native credential libraries for Linux Secret Service, Windows Credential Manager
  and macOS Keychain, with explicit key identifiers and no fallback/regeneration.
  See [credential scope and testing](desktop-credentials.md).

- Encrypted SQLCipher startup configuration with revision conflict checks, a
  64 KiB database ceiling, explicit key files, wrong-key/tamper rejection and interrupted-write recovery and CLI initialization/edits.
  The connection closes before DNS starts; changes require restart. See
  [configuration](configuration.md) for budgets, recovery and remaining management work.

- Four-way bounded DNS response cache with exact request keys, positive/SOA-bounded
  negative responses, TTL aging, dual-clock expiry and cache counters. See
  [cache scope](dns-cache.md) for bypassed protocol variants and resource accounting.

- Bounded UDP/TCP DNS service with client CIDR allowlists, category filtering,
  CNAME target checks, upstream reply correlation, deadlines and TCP fallback.
- One-thread DNS runtime (optional management adds a separate thread) with explicit upstream configuration, signal shutdown
  and aggregate counters; no query names are logged.

- Strict hostname validation and normalization; explicit category masks.
- Exact, domain-and-descendant, and descendant-only matching.
- Category-scoped allows, ordinary blocks and enforced blocks.
- Immutable FST snapshots: v1 for one policy kind, packed v2 for mixed kinds.
- Compatibility reading v1 snapshots; version, count, record and checksum checks.
- `compile_sources` rebuilds the enabled-source union without deleting other
  sources' overlapping contributions. No enabled sources produces a 71-byte empty
  snapshot; an empty enabled selection still fails. The CLI requires explicit
  `compile --empty` to disable all rules. See [empty policy semantics](empty-policy.md).
- Budget-aware staged publication and a command-line compiler/checker.
- On-demand HTTPS source fetching into a bounded, ignored development cache.
- Direct matcher measurements, k6 orchestration, cgroup resource sampling and
  separately labeled native-client/transport experiments.

See the [management validation](management-validation.md) for the latest constrained
DNS/API comparison. Full capacity gates remain unmet.

## Validation

The Rust suite includes policy, protocol, forwarding, overload and shutdown tests. The Python suite covers report validity,
resource accounting, runner configuration and feed-download failure handling.
The native diagnostic client has Go unit tests. Rust formatting and Clippy are
required. CI runs Rust checks on Linux, Windows and macOS; local results alone do
not establish qualification on all three systems.

Policy matching and the fixed-buffer benchmark response formatter do not
allocate. DNS parsing, cached response copies, HTTP connections, compilation and
feed downloads have separate memory costs. A short cache mutex protects bounded
memory operations and is never held across DNS I/O. Development generators are outside the server resource cap.

## Performance limits

The real measured corpus contains 178,507 logical policies and occupies 1,889,139
bytes. Mixed-policy packing produced substantially lower direct lookup latency
and a smaller index on a synthetic corpus; it is not evidence of a similar gain
for every list or for end-to-end DNS traffic.

The five-minute 25,000/sec k6 test failed: 950,042 correct responses, HTTP p99
86.23 ms and 6,549,698 dropped arrivals. The same-host generator and desktop
contention limit interpretation. The optional polling adapter remains experimental;
the Hyper/Tokio adapter is still the default.

See [DNS service](dns-service.md), [packed-policy measurements](packed-policy-optimization.md),
[transport diagnostics](transport-diagnostics.md) and the
[benchmark guide](../tests/load/README.md).

The [configuration checkpoint](configuration-performance.md) adds a current
60-second DNS regression and a passing 2,500/sec k6 HTTP run. The DNS generator
was near one-core saturation; neither measurement satisfies the 25,000/sec full-service gate.

## Remaining work

Encrypted DNS, upstream pooling/failover, cache coalescing and generation
invalidation, profile identity
and authorization, source refresh scheduling, live snapshot activation, disabled
payload cleanup, analytics persistence, desktop/web UI, and release packaging.
The complete installed footprint below 10 MB is a design target, not a validated
full-product result. [Task checklist](../task.md), [roadmap](../goal.md), [size budget](size-budget.md).
