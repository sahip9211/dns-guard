# DNS Guard application tasks

Status: prototype in active development. `[x]` means implemented and verified for
the stated scope; `[ ]` means unfinished, including partially implemented work.
The full application is not release-ready. Update this checklist with each milestone.

Latest implementation: encrypted configuration with explicit instance keys.
OS credential custody, installed instance isolation, authenticated API and the
first dashboard remain unfinished.
Requirements and design rationale: [goal.md](goal.md). Measurements and limitations:
[implementation status](docs/implementation-status.md).

## Delivery order

1. DNS correctness, bounded caching and repeat-query performance — cache functionality implemented; capacity gates remain open.
2. Persistent configuration, authenticated management API and a working dashboard.
3. Native desktop shell and browser UI using the same service API; measure both bundles.
4. Native feed refresh, selected-source activation and per-device policies.
5. Parental controls, bounded analytics/history, and complete setup workflows.
6. Arch packaging first, other platforms, security review and sustained acceptance tests.

No completed component substitutes for the whole-product size/performance gates.

## Product constraints and architecture

- [x] ARCH-01 — Document complete installed/distributed footprint below 10,000,000 bytes, including downloaded data and update staging.
- [x] ARCH-02 — Select Rust service, exact FST policy index and a SQLite-based configuration/analytics design; document alternatives.
- [x] ARCH-03 — Define DNS visibility limits: domains and DNS metadata versus URLs, traffic bytes, applications and screen time.
- [ ] ARCH-04 — Qualify the shared UI technology with actual native and browser builds, accessibility tests and complete dependency accounting.
- [ ] ARCH-05 — Build an end-to-end slice: service + desktop + browser + persistent settings + one inspectable query.
- [ ] ARCH-06 — Validate the entire application/data/update footprint below 10 MB; do not exclude runtimes, raw lists, WAL or notices.
- [ ] ARCH-07 — Finalize product name, project license and redistribution policy for third-party sources.

## DNS service and cache

- [x] DNS-01 — Implement UDP/TCP listeners, explicit upstream selection and one-thread CLI runtime.
- [x] DNS-02 — Correlate upstream source, transaction ID, opcode and question; randomize forwarded IDs and use ephemeral UDP sockets.
- [x] DNS-03 — Implement upstream deadlines, UDP truncation/TCP fallback, client UDP size handling and TCP frame limits.
- [x] DNS-04 — Bound active requests and TCP clients; shed overload with counters; stop and drain tasks on shutdown.
- [x] DNS-05 — Support explicit client CIDR allowlists with loopback defaults and IPv4-mapped IPv6 normalization.
- [x] DNS-06 — Reject malformed/unsupported requests; preserve DNS label boundaries and clear unvalidated AD flags.
- [x] DNS-07 — Apply category policy to questions and CNAME destinations; expose aggregate service counters.
- [x] DNS-08 — Add bounded positive-response caching with TTL expiry/aging, collision-safe keys, byte accounting and eviction.
- [x] DNS-09 — Add SOA-bounded negative caching for plain NXDOMAIN/NODATA without caching referrals or transient failures; CNAME-bearing negatives bypass the cache.
- [ ] DNS-10 — Isolate cache variants by flags, EDNS context and policy/upstream generation; flush on live policy changes.
- [ ] DNS-11 — Coalesce identical outstanding queries with bounded waiters and cancellation.
- [ ] DNS-12 — Pool upstream connections; support multiple upstreams, health checks, failover and bounded retries.
- [ ] DNS-13 — Add DoT/DoH upstreams with verified TLS, bootstrap addresses and loop prevention.
- [ ] DNS-14 — Add DNSSEC validation and correctly bounded caching of signed answers.
- [ ] DNS-15 — Add conditional forwarding, local A/AAAA/CNAME/PTR overrides and configurable block responses.
- [ ] DNS-16 — Qualify modern record types, EDNS extensions, DNAME/HTTPS alias policy and IPv6 transport interoperability.
- [ ] DNS-17 — Add per-client rate limits, DNS rebinding protections and configured internal-network exceptions.
- [ ] DNS-18 — Add authenticated downstream DoH/DoT and certificate lifecycle management (P1).
- [ ] DNS-19 — Evaluate stale serving/prefetch, optional recursion, DoQ and DNSCrypt with separate resource budgets (P2).

## Exact filtering and large rule sets

- [x] FILTER-01 — Validate/canonicalize hostnames; implement exact, domain and subdomain-only scopes.
- [x] FILTER-02 — Implement category-scoped block, allow and enforced-block precedence.
- [x] FILTER-03 — Compile compact immutable v1/v2 FST snapshots; validate versions, checksums, counts and limits.
- [x] FILTER-04 — Keep successful policy matching allocation-free; verify against an independent oracle and collision tests.
- [x] FILTER-05 — Rebuild selected-source unions without deleting other sources' overlapping contributions.
- [x] FILTER-06 — Budget and atomically publish local snapshots, counting old/staged index overlap.
- [ ] FILTER-07 — Activate snapshots without stopping DNS; retain the last valid generation on failure and invalidate dependent cache data.
- [ ] FILTER-08 — Support all-sources-disabled operation without inventing a blocking rule or requiring a nonempty compiler input.
- [ ] FILTER-09 — Explain matches with source, category, rule, revision, profile, schedule and overrides.
- [ ] FILTER-10 — Add custom rules, expiring exceptions, previews and undo with audit records.
- [ ] FILTER-11 — Add memory-bounded external sorting/merging for large source compilation.
- [ ] FILTER-12 — Qualify 1M/10M-rule data sets and a 30M stress tier; measure semantics, bytes, peak build memory and latency separately.
- [ ] FILTER-13 — Add signed, reproducible snapshot distribution and measured Zstandard transfer support (P1).
- [ ] FILTER-14 — Evaluate bounded regex/service bundles and evidence-based threat heuristics without probabilistic final blocks (P1/P2).

## Source registry and automatic updates

- [x] FEED-01 — Keep source URLs/formats/coverage/license links in a public catalog; exclude real hosts lists and generated indexes from Git.
- [x] FEED-02 — Parse domain, hosts and supported Adblock rules; reject unsupported syntax instead of silently widening it.
- [x] FEED-03 — Provide an on-demand development downloader with HTTPS, byte limits, hashes and interrupted-download preservation.
- [ ] FEED-04 — Implement the native runtime downloader; Python must not become an uncounted application dependency.
- [ ] FEED-05 — Add ETag/Last-Modified refresh, bounded retries, timeouts, redirect/destination checks and decompression limits.
- [ ] FEED-06 — Schedule automatic refresh with jitter and optional desktop battery/metered-network constraints.
- [ ] FEED-07 — Expose Ignore/Block/Allow modes and category assignment; preview broad exceptions from combined feeds.
- [ ] FEED-08 — Validate update completeness and suspicious count changes before atomic activation; provide rollback.
- [ ] FEED-09 — Remove disabled-source payloads while preserving shared rules; refetch when re-enabled.
- [ ] FEED-10 — Track source revision/digest, freshness, unique contribution, overlap, bytes, errors, provenance and license attribution.
- [ ] FEED-11 — Maintain reviewed product-owned additions/exceptions and a false-positive/emergency-removal workflow.
- [ ] FEED-12 — Qualify ads/tracking/adult/malware/phishing/gambling/social feeds for accuracy, coverage and redistribution rights.

## Persistent configuration, database and management API

- [x] CONFIG-01 — Add schema-v1 bootstrap migration, validation and defaults; recover interrupted transactions and preserve corrupt/unsupported files for explicit restoration.
- [x] CONFIG-02 — Implement SQLite configuration storage with bounded database pages, a small cache target, no WAL and durable transactional changes; close it before DNS starts.
- [ ] CONFIG-03 — Define versioned API schemas shared by desktop, web and CLI; validate all mutations before activation.
- [ ] CONFIG-04 — Implement administrator bootstrap, strong credential storage, session/token expiry and revocation; no default password.
- [ ] CONFIG-05 — Serve management on loopback by default; explicitly configure remote HTTPS and trust.
- [ ] CONFIG-06 — Enforce authorization, CSRF/origin protection, rate/body limits and redaction across management endpoints.
- [ ] CONFIG-07 — Add transactional configuration import/export, backup/restore, rollback and change audit records.
- [ ] CONFIG-08 — Expose health/readiness, version, resource budgets and policy-generation diagnostics.
- [ ] CONFIG-09 — Add admin/operator/read-only roles, scoped API tokens and MFA (P1).
- [ ] CONFIG-10 — Add OIDC/directory integration and multi-node configuration synchronization without shared SQLite files (P1).

## Encryption and instance isolation

- [x] SEC-01 — Encrypt configuration and journals with authenticated database encryption; test wrong keys, corruption and interruption without plaintext fallback.
- [ ] SEC-02 — Protect private policy indexes, query history, exports, backups and temporary artifacts; identify and eliminate remaining plaintext copies.
- [ ] SEC-03 — Give each instance an independent OS-generated data key; never share keys across installations or derive them from a public instance identifier.
- [ ] SEC-04 — Provision separate service identities and private data directories; qualify ownership, ACLs and confinement on Linux, Windows and macOS.
- [ ] SEC-05 — Integrate OS credential custody for unattended services and desktop unlock; document same-user and administrator limitations without claiming code signing creates instance isolation.
- [ ] SEC-06 — Add safe key rotation, recovery/export, intentional migration and reinstallation/restore workflows; never reset an unreadable instance automatically.
- [ ] SEC-07 — Keep data-encryption, API-authentication and release-signing keys separate; retain release private keys outside shipped binaries and repositories.
- [ ] SEC-08 — Test cross-instance access under actual OS identities, malicious replacement, replay/rollback limits, memory/crash dump exposure and encrypted-size/resource budgets.
- [x] SEC-09 — Verify native systemd encrypted-credential delivery, wrong-key rejection, credential cleanup and DNS startup without adding runtime dependencies; provide a system unit template pending privileged isolation qualification.

## Clients, profiles and parental controls

- [ ] PARENT-01 — Identify observed clients without conflating NAT/router proxies, MAC addresses, devices and authenticated users.
- [ ] PARENT-02 — Add device names, subnet/group assignment, child/family/guest profiles and deterministic policy precedence.
- [ ] PARENT-03 — Apply category/source selections per profile, with administrator-enforced rules above child exceptions.
- [ ] PARENT-04 — Implement timezone/DST-aware bedtime and school/work schedules, holidays, manual overrides and restart behavior.
- [ ] PARENT-05 — Add timed DNS pause/resume and explain cached-answer/established-connection limitations.
- [ ] PARENT-06 — Implement provider-specific SafeSearch and YouTube restriction modes with diagnostics.
- [ ] PARENT-07 — Add recreation windows, app/service bundles, approved temporary access and delegated parent permissions (P1).
- [ ] PARENT-08 — Provide router/managed-device guidance and enrollment checks for VPN/encrypted-DNS bypass (P1).
- [ ] PARENT-09 — Add traffic/screen-time quotas only with measured endpoint/gateway integration (P2).

## Analytics, history and privacy

- [x] STATS-01 — Expose aggregate DNS receive/block/forward/error/admission/in-flight counters without storing query names.
- [ ] STATS-02 — Add bounded nonblocking event queues; expose ingestion lag, dropped events and retention gaps.
- [ ] STATS-03 — Implement off/aggregate/detail/temporary-diagnostic logging modes and explicit retention controls.
- [ ] STATS-04 — Store bounded query metadata with profile, reason, cache/upstream status, transport, timestamps and latency.
- [ ] STATS-05 — Implement minute/hour/day aggregates and bounded top-client/domain/category views.
- [ ] STATS-06 — Add a dedicated batched storage writer, disk/WAL limits, compaction and crash recovery without DNS-path SQL.
- [ ] STATS-07 — Add cursor-paginated search, query details, CSV/JSON exports, deletion and secret-redacted support bundles.
- [ ] STATS-08 — Expose QPS, percentiles, cache usage, RSS/CPU, queue pressure, storage and update peaks.
- [ ] STATS-09 — Add bounded metrics labels, upstream/source/storage alerts and opt-in reporting integrations (P1).
- [ ] STATS-10 — Add separate flow/endpoint traffic views with visible collector coverage and sampling (P2).

## Browser application

- [ ] WEB-01 — Build embedded local assets with no CDN dependencies or runtime Node.js requirement; measure final asset sizes.
- [ ] WEB-02 — Implement first-run setup for service mode, occupied ports, upstreams, source selection, admin credentials and a real DNS check.
- [ ] WEB-03 — Build live overview cards/charts from real service data, including errors, cache and resource counters.
- [ ] WEB-04 — Build query explorer/detail view and domain-policy explanation/testing tools.
- [ ] WEB-05 — Build source manager with freshness, modes, categories, storage, manual refresh and update errors.
- [ ] WEB-06 — Build devices/groups/profiles, parental schedules, custom rules and exception/undo flows.
- [ ] WEB-07 — Build upstream, security, logging, backup/restore, service status and diagnostics settings.
- [ ] WEB-08 — Add accessible keyboard navigation, responsive layouts, light/dark themes, reduced motion and chart text equivalents.
- [ ] WEB-09 — Test loading/empty/error/disconnected states; bound live subscriptions and pause hidden-view polling.
- [ ] WEB-10 — Add localization, saved views and batch operations (P1).

## Desktop application

- [ ] DESKTOP-01 — Build and size-test a native shell with the shared management interface; qualify egui/eframe versus alternatives.
- [ ] DESKTOP-02 — Connect to local/remote services through the same authenticated API, with explicit TLS trust.
- [ ] DESKTOP-03 — Add tray/status, startup preferences, notifications and independent service lifecycle.
- [ ] DESKTOP-04 — Implement narrow privileged installation/DNS-setting helpers with deliberate apply/restore behavior.
- [ ] DESKTOP-05 — Qualify Wayland/X11, Windows and macOS input, accessibility, rendering and window lifecycle.
- [ ] DESKTOP-06 — Measure idle/chart CPU/RAM and total native/browser/runtime footprint; closing the UI must not stop DNS.

## Packaging, deployment and operations

- [ ] RELEASE-01 — Package Arch service/desktop components with PKGBUILD, .SRCINFO, systemd unit, service user and configuration preservation.
- [ ] RELEASE-02 — Verify Arch clean install, upgrade, rollback and uninstall; publish to AUR only as an explicit release action.
- [ ] RELEASE-03 — Add Debian/Ubuntu and Fedora packages, Linux ARM64 builds and optional AppImage.
- [ ] RELEASE-04 — Add Windows Service installation and signed desktop installer.
- [ ] RELEASE-05 — Add launchd service, Apple Silicon/Intel builds and macOS signing/notarization.
- [ ] RELEASE-06 — Build minimal amd64/arm64 containers with persistent state and no mandatory container runtime.
- [ ] RELEASE-07 — Add reproducible release artifacts, checksums/signatures, SBOM/notices and dependency/security-update policy.
- [ ] RELEASE-08 — Document router/DHCP/IPv6/VLAN/VPN/internal-DNS integration and two-filtered-resolver failover.
- [ ] RELEASE-09 — Test migrations, backups, disk-full behavior, interrupted updates, outage recovery and multi-node drift (P1).
- [ ] RELEASE-10 — Qualify Windows ARM64, FreeBSD, ARMv7/OpenWrt and optional mobile/endpoint integrations separately (P2).

## Testing, performance and release gates

- [x] TEST-01 — Maintain policy/oracle/corruption/allocation, mocked DNS transport, CLI and development-tool tests.
- [x] TEST-02 — Run formatting, Clippy and Rust CI on Linux/macOS/Windows; Python and Go tool tests on Linux.
- [x] TEST-03 — Provide k6 HTTP tests, UDP diagnostics, artifact hashes, CPU/RSS samples and verified cgroup limits.
- [x] TEST-04 — Add deterministic cache time/expiry/eviction tests and socket-level cache integration tests before enabling caching.
- [ ] TEST-05 — Add API/database migration, authorization, feed-update transaction and failure-injection tests.
- [ ] TEST-06 — Add browser/desktop end-to-end, accessibility and packaging tests with headless execution by default.
- [ ] TEST-07 — Fuzz DNS parsing boundaries, snapshot imports, configuration and feed parsers; add dependency audits.
- [ ] TEST-08 — Measure blocked/cached/forwarded/negative DNS separately, with a generator that has CPU headroom and independent client validation.
- [ ] TEST-09 — Meet 25,000 requests/sec under the experimental 8 MiB/half-core cap with p99 below 20 ms, zero wrong answers and zero dropped arrivals; current runs fail.
- [ ] TEST-10 — Qualify the documented 5,000-device office workload and 10,000-device stretch workload, with honest logging/corpus/transport limits.
- [ ] TEST-11 — Run sustained and 24-hour mixed-load soaks, update-under-load, upstream outage, crash/restart and disk-full scenarios.
- [ ] TEST-12 — Verify complete installed and distributed size under 10 MB, including data, runtimes, notices and peak update overlap, on each release platform.
- [ ] TEST-13 — Publish measured acceptance results and known limitations; separate DNS results from the unrelated $12-server HTTP/SQLite workload.
