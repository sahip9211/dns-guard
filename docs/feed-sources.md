# Blacklist sources, compression, and update design

Researched: 2026-11-06. This document complements [goal.md](../goal.md) and the [matching/database design](stack-research.md). Completed research downloads, immutable URLs, hashes, sizes, and compression results are recorded in [feed-snapshot.json](benchmarks/feed-snapshot.json).

## 1. Product decision

Build our own **versioned, categorized corpus** from reviewed upstream feeds plus our own curated additions and exceptions. Own the source registry, normalization, provenance, quality checks, compact compiler, update process, and correction workflow. Keep each source's attribution and terms; aggregation does not make upstream data our original work.

Initial categories: base ads/tracking protection, adult content, malware/phishing, gambling, and optional social/game/service restrictions. Add more categories only when their data has a clear meaning and maintained source. A mixed adware/malware feed must remain labeled mixed protection unless individual entries have independent classification evidence.

Do not automatically enable every source. Overlap, stale records, false positives, inconsistent syntax, and broad domain rules affect usefulness more than the headline count. The product still needs an efficient large-corpus mode, tested at 10 million and 30 million unique rules.

## 2. Source discovery, including forums

The Pi-hole community has reported installations with approximately 12.8 million combined entries and discussed overlapping feeds. This is a useful discovery lead, not a verified count of distinct harmful domains or proof that every linked source is reliable. [Community discussion](https://www.reddit.com/r/pihole/comments/1vuzv68/help_me_clean_up_my_pihole_blocklists_128m/).

IPFire's developers describe building categorized lists with explicit source attribution and maintenance checks. Their mailing-list discussion also illustrates that stale-domain cleanup can radically change counts. Those are maintainers' observations for their corpus; our pipeline must measure its own data and must not delete domains merely because one lookup fails. [IPFire development discussion](https://lists.ipfire.org/development/DD6F0BB8-B24F-482D-BB66-5CA82DF5AA8C%40ipfire.org/T/).

Follow forum recommendations back to publisher repositories, source manifests, actual downloadable files, update metadata, and issue history. Forum popularity is not an automatic trust or freshness signal. Historic Shalla/columndeeply URLs and similar recommendations must be checked rather than copied into defaults.

## 3. Candidate sources and evidence

Counts in this table have different evidence levels. They are deliberately not added together: feeds overlap, URL entries are not necessarily domains, and suffix rules can represent many subdomains.

| Source | Suitable coverage | What was verified | Proposed role |
| --- | --- | --- | --- |
| [HaGeZi DNS blocklists](https://github.com/hagezi/dns-blocklists) | Mixed protection, separate adult/gambling/threat feeds | Downloaded Light and NSFW at a pinned November 6 revision; 87,225 and 91,332 simple domain-suffix rules respectively | Initial prototype corpus. Use one base tier, not all nested tiers. |
| [StevenBlack hosts](https://github.com/StevenBlack/hosts) | Mixed adware/malware base and optional categories | Downloaded November 1 snapshot; its header declares 77,758 unique domains. File also contains local hosts mappings, which are not block rules | Alternative base and parser compatibility fixture; do not blindly stack with other aggregates. |
| [Block List Project](https://github.com/blocklistproject/Lists) | Separate ads, adult, tracking, phishing, gambling and other lists | Repository revision queried was from July 20. Ads download was incomplete twice and was excluded | Candidate category input requiring freshness review; no accepted corpus generated from the truncated files. |
| [OISD](https://oisd.nl/faq) | Ads/threat protection and separate adult feeds | Publisher explains suffix coverage and update behavior; no full corpus downloaded in this pass | Alternative source pending exact feed terms and payload verification. |
| [UT1 / Université Toulouse Capitole](https://cri.univ-tlse1.fr/blacklists/) | Categorized domains and URLs, especially adult | Publisher's indexed category table lists about 4.6 million adult entries and says adult is its actively maintained focus; live fetch timed out | Large adult-corpus candidate. Separate domain and URL records before counting or importing. |
| [T145 Black Mirror](https://github.com/T145/black-mirror) | Large aggregate domain and IP lists | Viewed README lists 7,792,324 domain entries; API verified a 165,454,078-byte domain asset updated November 5. Payload not downloaded/recounted | Large-corpus qualification candidate, after category and data-term review. IP lists must not be treated as domain rules. |
| [nathan-d/pihole-hosts](https://github.com/nathan-d/pihole-hosts) | Preserved adult-list aggregation | README claims 12,576,671 domains; fork last pushed June 25. Referenced original `columndeeply/hosts` returned 404 | Historical stress fixture candidate, not a fresh production default. Claimed monthly updates are unverified. |
| [IPFire DNSBL](https://dnsbl.ipfire.org/lists/) | Categorized ads/adult/malware/gambling/service lists | Maintainer discussion reviewed; list host could not be resolved from this environment | Candidate to recheck, especially its per-category source attribution. No payload accepted in this pass. |

Black Mirror's `latest` release was originally created in 2023, but the individual domain asset was updated in November 2026. This is why the updater must record asset-level timestamps and hashes, not infer file freshness solely from release creation time. API-observed asset ID: `714788514`; advertised SHA-256: `88b8e27aa0b80f479fb06ab8851f50067520cee46680eed57ff22c67f58af69e`. [Release](https://github.com/T145/black-mirror/releases/tag/latest).

The 12.6-million claim shows why the architecture should allow very large corpora, but it is not evidence of a maintained, high-quality 12.6-million-domain feed today. Thirty million unique rules is a synthetic/combined stress target until verified by a normalized source manifest.

### Licensing and provenance

- HaGeZi publishes GPL-3.0 terms and discusses upstream inputs. Preserve its license and notices in any redistributed derived data; review direct upstream inputs separately. [Publisher disclaimer](https://github.com/hagezi/dns-blocklists#disclaimer), [license](https://github.com/hagezi/dns-blocklists/blob/main/LICENSE).
- StevenBlack's repository declares MIT, and its generated file combines multiple sources. Preserve the supplied source notices and inspect input terms when redistributing a derived corpus. [Repository license](https://github.com/StevenBlack/hosts/blob/master/license.txt).
- Block List Project declares the Unlicense. Record that declaration and its source provenance alongside the artifact. [License](https://github.com/blocklistproject/Lists/blob/main/LICENSE).
- UT1 identifies a Creative Commons license; resolve its exact linked terms before making a distribution decision. Black Mirror's repository declares AGPL-3.0; verify applicability to the selected data artifacts and included sources. Do not assume every artifact in a public repository has identical terms.
- Keep application-code licensing and dataset licensing explicit. Do not silently relicense a merged list or assume end-user fetching removes all obligations. Unresolved sources can remain research candidates without preventing implementation of the generic importer.

## 4. Completed download and compression experiment

These files were fetched at pinned revisions after checking current repository state. The original and compressed files are in `/tmp/dns-stack-research/feeds/`; paths and digests are recorded in the manifest. Temporary storage is not a durable release archive. No source was activated as a system DNS policy, and no production updater is running.

Zstandard level 3, one thread, produced:

| Snapshot | Raw bytes | Compressed bytes | Reduction |
| --- | ---: | ---: | ---: |
| HaGeZi Light | 2,123,553 | 648,461 | 69.5% |
| HaGeZi NSFW | 1,696,254 | 483,412 | 71.5% |
| StevenBlack base | 2,353,610 | 552,086 | 76.5% |

All three compressed files passed `zstd -t`. This is a real **download/storage compression** measurement on those snapshots. It is not a measurement of FST size, resident memory, or query latency, and should not be extrapolated as a guaranteed ratio for a 10-million-rule corpus.

A subsequent Rust FST probe combined the two HaGeZi inputs into **178,507 unique rules** with two category bits. The reversed-label layout occupied **1,841,357 bytes**; forward-domain layout occupied **1,908,735 bytes**. Every stored key and 42,004 sampled suffix queries passed reference checks in each layout. The final reversed-layout run measured warm matcher p99 of **4,783 ns** on an Intel i7-10510U. This excludes normalization, full policy/provenance metadata, cold faults, networking, and concurrent load. Samples differ between layouts, so timing is exploratory rather than a controlled performance ranking. [recorded measurements](benchmarks/index-probe-results.json).

This is useful evidence of compact, fast exact matching at this corpus size. It also shows that the provisional 1 MB index allocation is already exceeded. It does not establish that the complete application or a ten-million-rule corpus fits under 10 MB. The [all-in size gate](size-budget.md) still applies to all downloaded/index data.

For scale context, 7.8 million lines averaging 20 domain characters plus a newline occupy about 164 MB as plain text. This explains the large raw downloads. The serving representation should not be millions of independently allocated language strings.

Selected compression design:

1. Normalize and deduplicate while preserving rule semantics and category/source relationships.
2. Compile sorted domain keys into an FST and pack/intern repeated metadata.
3. Bundle a versioned manifest, compiled index, metadata, source digests, and notices.
4. Zstandard-compress the bundle for delivery.
5. Decompress once into staging, verify it, then activate the searchable files.

Query-time matching uses the compact index directly. It never scans compressed text or decompresses the full archive for each DNS request. Memory mapping and on-demand pages are evaluated with cold-cache latency, not assumed to be free memory. See [matching algorithms and large-corpus budgets](stack-research.md#compression-and-tens-of-millions-of-entries).

## 5. Source registry and ingestion contract

Each registered source needs: stable ID, publisher URL, fetch URL/mirrors, content format, rule semantics, category scope, license/attribution references, refresh interval, compressed/decompressed size limits, last attempted/successful fetch, ETag/Last-Modified, revision or asset ID, raw digest, parser version, accepted/rejected counts, and enabled profiles.

Prefer direct raw files or documented release assets over cloning full repository history. Support GitHub API metadata where necessary, conditional HTTP fetches, rate-limit backoff, and explicitly configured mirrors. A GitHub commit being recent does not prove a particular data file was updated. A mutable `latest` URL must be resolved to a recorded digest/revision for reproducibility.

Proposed update policy: check ordinary feeds every 24 hours with jitter, and offer shorter threat-feed intervals only when the publisher supports them. Limit simultaneous downloads/builds. There is no always-on cloud requirement: users can fetch sources directly, use our signed compiled snapshots, or import offline packages.

Pipeline:

1. **Fetch:** HTTPS with certificate checking, explicit deadlines, limited redirects, and streaming to a `.part` file. Honor publisher limits and validators.
2. **Validate transport:** require a successful complete response; reject truncated files, HTML/error responses, excessive decompression, and unexpected formats. A local SHA records identity but is not a publisher signature.
3. **Parse:** support hosts, plain-domain lists with explicit semantics, and a documented DNS-relevant Adblock subset. Keep unsupported rules visible. URL-path records cannot automatically become whole-domain blocks.
4. **Normalize:** canonical domain form and label validation, comments/local-host exclusions, explicit handling of IP literals, and exact-versus-suffix flags.
5. **Merge:** external sorted runs for large inputs; deduplicate equivalent rules and retain all source/category references. Do not union away exceptions or copy public allowlists into a global policy override.
6. **Quality gate:** check count changes, removals, category distribution, unexpected broad/TLD rules, sampled diffs, known-good regression fixtures, and rules with conflicting classifications. Quarantine anomalous updates for review.
7. **Compile:** construct compact index and metadata with schema/version checks, resource limits, and deterministic output from pinned inputs.
8. **Publish/activate:** verify signed manifests where supplied, keep a known-good previous version, atomically switch policy snapshots, and expose update status in both interfaces.
9. **Monitor:** record freshness, update latency, memory/disk peaks, parser errors, rejected rules, and false-positive corrections.

Restrict remote source URLs to intended destinations and reject private/link-local targets by default unless an administrator explicitly configures an internal feed. Apply those checks after redirects and resolution. Do not let list content become executable code, SQL, HTML, or a privileged filesystem path.

Client-side distribution of precompiled indexes is the normal path for very large datasets on small hardware. The build service can use larger resources without making every user compile tens of millions of entries. Offline/local compilation remains available with measured disk and peak-memory requirements.

## 6. Our curated additions and corrections

Store original records with domain, match scope, category, reason, evidence references, submission/review dates, reviewer, confidence, and expiry/review deadline. Keep additions, removals, and exceptions versioned and auditable. Product-owned corrections can override a problematic upstream rule without waiting for its next release, subject to administrator policy precedence.

Maintain regression fixtures for legitimate services, authentication/payment dependencies, software updates, educational/health information, and already-reviewed false positives. Mixed-content sites require deliberate policy choices; the presence of one adult page does not establish that blocking an entire platform is appropriate.

Source counts should include raw records, parsed rules, unique domains, exact/suffix rules, cross-source duplicates, rejected entries, and semantic reductions. Show incremental contribution per source so users can avoid redundant downloads and memory consumption.

Automatic web discovery and content classification would require a separate crawler, quality process, and operating budget. The first release builds and maintains an aggregated corpus with reviewed additions; it does not claim an independently crawled classification of the whole internet.

## 7. Acceptance checks

- Every block can be traced to a rule, category, active policy, and source revision.
- Failed, empty, truncated, oversized, or malformed downloads preserve the working corpus.
- Equivalence tests compare the compact index with a straightforward exact oracle, including IDNA, label boundaries, allow rules, category overlap, and schedules.
- Deterministic builds from the same inputs have reproducible hashes, excluding explicitly separated timestamps/signatures.
- 1m/10m/30m test corpora report actual unique rules and include long/random domains that compress poorly, not only favorable synthetic shared prefixes.
- Measure compressed download, decompressed index, metadata, steady resident pages, cold/warm lookup p99, and peak replacement memory separately.
- Querying 5,000 devices shares one immutable corpus; adding a device cannot duplicate the entire blacklist.
- Compression and semantic reduction must preserve every tested decision and explanation.

Next implementation work is the production importer/compiler and broader correctness/size/latency benchmark. This pass downloaded and compressed representative inputs and built a small research FST; it did not implement the production compiler, build a release-ready merged blacklist, or validate the largest publishers' full datasets.

## Source controls and downloads

See [source controls](filter-sources.md) for category-only variants, exceptions
and safe source removal. The [catalog](../config/sources.json) stores public URLs
and coverage metadata. `python3 -m tools.feeds.fetch --source SOURCE_ID` downloads
selected sources into `.cache/feeds/`; no real blocklists are versioned.
Background service scheduling and live activation remain planned.
