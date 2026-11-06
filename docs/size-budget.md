# All-in 10 MB requirement and feasibility gate

The size target applies to the complete installed application and its runtime data.

## Requirement and accounting

Hard ceiling: **less than 10,000,000 bytes**, decimal MB, for the complete installed application and its retained operational data. Also keep the distributed bundle below that limit. Passing the compressed-download gate does not imply passing the installed gate.

Count desktop/service executables, browser assets, fonts/icons, bundled libraries, additional runtime/framework dependencies, compiled blocklists and their metadata, configuration, database/WAL, logs, retained downloads, and update staging. Count downloaded components even if omitted from the installer. A bootstrapper is not a size optimization if it installs a larger application later.

The platform operating system and stock display/network drivers are the baseline; additional app frameworks such as a desktop WebView are included. Do not present a dependency-heavy Arch package as tiny merely because pacman fetches those dependencies separately. Build tools and this research workspace are not part of the shipped runtime.

RAM is a separate constrained resource, measured through process and system memory. A memory map does not make index bytes disappear from either disk accounting or resident-page accounting. Moving the complete corpus to a cloud service or hiding it in an uncounted cache is not a compliant workaround.

## Current evidence and unresolved conflicts

No complete application currently meets this limit. The strict cap is a feasibility objective, not an achieved property.

The last measured plaintext-configuration Linux executable was
1,853,656 bytes. Removing unused SQLite search/spatial modules and extension
loading, and compiling SQLite for size while retaining Rust DNS optimization,
reduced it from 3,252,408 bytes. The previous DNS/cache-only binary was 1,032,472
bytes. These are separate feature/build comparisons, not compression ratios.

The encrypted-configuration Linux executable is **6,621,088 bytes**, including
SQLCipher and its bundled OpenSSL provider. It exceeds the initial 3 MB service
allocation below. The current 87,812-policy test index is 1,018,122 bytes, the
encrypted configuration fixture is 12,288 bytes, and its raw key is 32 bytes.
Those four components total **7,651,530 bytes**, excluding notices, UI, analytics,
retained feeds, other state and index update overlap. Reserve 200 KiB for the
database/journal update budget instead of counting only its resting file size.
The complete-product target remains unproven. See [encryption measurements](encryption-validation.md)
and [configuration limits](configuration.md).

The update publisher gates `other bytes + old index + staged index` against the
strict ceiling using a caller-supplied inventory. See the
[DNS checkpoint](benchmarks/dns-service-udp.json) and
[implementation status](implementation-status.md).

- We fetched three representative feeds and compressed their combined **6,173,417 bytes to 1,683,959 bytes** with Zstandard level 3. Integrity checks passed. These are compressed text inputs, not the final searchable indexes or a complete app. [Recorded experiment](benchmarks/feed-snapshot.json).
- A standalone Rust FST probe stored **178,507 unique rules with two category bits in 1,841,357 bytes**, passing stored-key and sampled suffix checks. Its warm local matcher p99 was approximately **4.8 microseconds**. This already exceeds the proposed 1 MB index allocation, before full provenance. More optimization or a different allocation is needed; no compliant full build has been demonstrated. [Probe results](benchmarks/index-probe-results.json).
- A published multi-million-domain candidate has a **165,454,078-byte raw artifact**. Its compression ratio and index size have not been measured here. [Source research](feed-sources.md).
- At the illustrative 200 bytes per stored event, even giving the entire 10 MB to history would store only 50,000 events: about 20 seconds at 2,500 QPS. The actual application and index consume some of those bytes, so the available window would be shorter. Aggregates/live views can help, but cannot retain every event indefinitely.
- Ten million rules with a hypothetical 16-byte metadata record already use 160 MB before key storage. Shared metadata and compact keys can reduce this; there is no guaranteed compression ratio for arbitrary exact domain sets.
- Tauri's small application payload relies on platform WebViews. Its framework guidance must not be read as proof that the additional runtime plus data fits this all-in limit. [Tauri app size](https://tauri.app/concept/size/), [prerequisites](https://tauri.app/start/prerequisites/).

These conflicts do not justify silently lowering the feature goals. They require an early measured prototype and a clear report of which combinations fit.

## Selected optimization direction

1. **Rust service:** retain the portable DNS/TLS/database architecture, prune unused crate features, strip symbols from release artifacts, and compare size-oriented versus speed-oriented optimization. Never remove protocol validation or TLS checks to meet the size target.
2. **Native UI candidate:** prototype egui/eframe with the smallest supported renderer/features, shared native and WASM UI code, minimal fonts/icons, and repaint-on-demand behavior. This avoids an added WebView framework but is not yet proven smaller than the total budget. Check usability and accessibility alongside size. [eframe's native/web support](https://docs.rs/eframe/latest/eframe/).
3. **Compact exact index:** FST keys, shared category/source metadata, no per-device copies, and a small override map. Compare a reverse-label radix trie and sorted packed keys using the same exact-match oracle.
4. **Distribution compression:** Zstandard-compress snapshots; keep only required decoded searchable files after activation. Measure decoder/bundle overhead as part of the app.
5. **Bounded storage:** enforce aggregate byte quotas covering database and WAL, not just row retention. Offer live detail and compact summaries, but label the actual history retained. Do not claim the original full-history goal has been satisfied if only summaries fit.
6. **Update headroom:** reserve bytes for old/new index overlap and rollback, or demonstrate another crash-safe update mechanism within the cap. Temporary files count while installed updates run.
7. **No probabilistic blocking errors:** Bloom filters may accelerate negative checks but must be verified against exact data. Do not trade correctness for a smaller blacklist.

## Allocation experiment, not measured component sizes

This is a starting envelope for a prototype. Any component exceeding its allowance triggers redesign or a documented feasibility failure; it is not permission to omit its bytes.

| Component | Initial allocation to test |
| --- | ---: |
| DNS/API/storage service and native dependencies it adds | 3.0 MB |
| Native desktop UI and added UI dependencies | 2.0 MB |
| Browser WASM/glue/assets | 1.0 MB |
| Active searchable index and provenance/category metadata | 1.0 MB |
| Configuration and bounded durable analytics, including WAL | 0.25 MB |
| Update staging/rollback allowance | 1.5 MB |
| Other assets/notices/package metadata | 0.25 MB |
| Unallocated margin | 1.0 MB |

The allocations total 10 MB; releases must remain strictly below the ceiling and should preserve margin. The 1 MB index and 0.25 MB database allocations are deliberately demanding hypotheses. The first actual FST prototype exceeded the index allocation even at 178,507 rules. These allocations have not been shown to support 10 million rules or 5,000 richly described devices. Keep this failure visible while optimizing or reallocating; do not silently ship a smaller corpus to claim success.

## Measurements required before committing to the full build

- Build a minimal service and usable native/browser screen on Arch first, then Windows/macOS; measure every installed file and additional dependency.
- Compile the real downloaded feeds to a searchable exact index. Report normalized rule counts, semantic reductions, bytes/rule, metadata overhead, and warm/cold p99 lookup latency.
- Test larger 1m/10m/30m fixtures and real source snapshots where available. Use both shared-prefix and poorly compressible domains.
- Measure configuration storage for 5,000 clients and the durable-history window possible within the remaining quota.
- Test updates, interrupted updates, SQLite checkpoints and recovery without exceeding the accounting limit or losing the known-good configuration.
- Publish the resulting Pareto comparison: total bytes, corpus coverage, retained detail, RAM, latency, and feature completeness. Do not report a best-case number without its configuration.

If no candidate meets the complete requested combination, the outcome is a measured incompatibility report with the closest exact/correct configuration—not a claim that optimization can necessarily fit any amount of data into 10 MB. No constraint is relaxed by this document.
