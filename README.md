# DNS Guard

A compact, exact DNS policy engine in Rust, designed as the foundation for a
self-hosted filtering service with desktop and browser administration.

**Early development:** the policy engine, compiler and bounded UDP/TCP DNS
forwarder work. The administration UI, cache, scheduled feed refresh and
production packages are not implemented. The complete application has not yet met its size
or throughput goals.

## What works

- UDP/TCP DNS filtering, upstream TCP fallback, client network allowlists and bounded concurrency.
- Exact hostname and subdomain matching with compressed immutable FST indexes.
- Category-scoped block, allow and enforced-block policies.
- Selected-source compilation that preserves overlapping contributions.
- Versioned, checked snapshots and budget-aware atomic publication.
- Allocation-free successful matching and fixed-buffer benchmark responses.
- Tests for policy semantics, independent oracles, corruption, limits and concurrency.

The runtime uses `fst`, Hickory protocol parsing, Tokio and `ipnet`. HTTP benchmark
adapters and load generators are development tools, excluded from the runtime.

## Build and test

Use stable Rust (1.88 or newer) with Cargo. Python 3.10+ is needed for the optional feed and
benchmark tools. Go 1.22+ is needed only for the native diagnostic client.

```sh
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
python3 -m unittest discover -s tests/python -p 'test_*.py'
```

Try the compiler with the **synthetic fixtures** included for tests:

```sh
mkdir -p .cache
./target/release/dns-guard compile .cache/example.dngi \
  --other-bytes 1000000 \
  --feed adblock ads tests/load/ads.txt \
  --feed adblock adult tests/load/adult.txt
./target/release/dns-guard check .cache/example.dngi all \
  ads.example safe.ads.example adult.example clean.example
./target/release/dns-guard inspect .cache/example.dngi
```

`--other-bytes` is the measured/reserved size of all other installed files. The
example reservation above is illustrative. Publication refuses an update when
`other + old index + staged index >= 10,000,000` bytes. This does not establish
that the eventual UI, resolver, history and update data fit together.

## Run DNS filtering

After compiling the example index above:

```sh
./target/release/dns-guard serve .cache/example.dngi --upstream 127.0.0.1:53
```

This listens on `127.0.0.1:5353` over UDP and TCP, using an explicitly configured
upstream. It does not alter system DNS. The default client access list permits
loopback only. A LAN deployment needs an explicit listening address and permitted
client networks. See [DNS service](docs/dns-service.md) for limits, options,
shutdown, counter definitions and current protocol limitations.

## Fetch blocklists

**Real blocklists are not stored in this repository.** The source catalog contains
URLs and metadata only. Fetch selected sources into the ignored cache:

```sh
python3 -m tools.feeds.fetch --list
python3 -m tools.feeds.fetch --source hagezi-light --source hagezi-nsfw
```

The utility downloads current source files over HTTPS, records hashes and byte
counts, and bounds staged cache growth. It preserves a previous feed if a download
fails. It is an on-demand development tool; automatic service scheduling and live
activation remain planned. Source licenses and coverage differ. See
[feed guidance](docs/feed-sources.md) before assigning categories or redistributing
source-derived data.

## Policy contract

`Exact` matches a hostname; `Domain` also matches descendants; `Subdomains` excludes
the hostname itself. Matching ignores ASCII case and one trailing root dot.
Unicode names must already be IDNA A-labels. Enabled category bits select policies
without copying the index:

```text
blocked = ((matching_blocks & ~matching_allows) | matching_enforced_blocks) & enabled
```

The importer supports plain domain lists, sinkhole hosts entries, `||hostname^`
and `@@||hostname^` Adblock rules. Unsupported wildcard, URL-path, cosmetic and
modifier syntax fails the import. Category assignment is explicit, not automatic
content classification. **Load only locally compiled, trusted snapshots**; the
checksum detects accidental corruption and is not an authentication mechanism.

## Repository layout

| Directory | Purpose |
| --- | --- |
| `src/` | Policy library, compiler, storage budget and CLI |
| `tests/` | Rust tests, Python tool tests and synthetic k6 fixtures |
| `examples/` | Direct benchmarks and loopback HTTP adapters |
| `tools/feeds/` | Source-catalog download utility |
| `tools/bench/` | k6 runner, metrics, fixture preparation and diagnostics |
| `config/` | Public source metadata; no downloaded feeds |
| `docs/` | Architecture, status, research and benchmark interpretation |
| `docs/benchmarks/` | Sanitized measurement records and samples |

Build outputs, downloaded feeds, generated queries, indexes and runtime databases
belong in ignored directories. See [development tools](tools/README.md) and
[benchmark instructions](tests/load/README.md).

## Status and measurements

The latest sustained k6 run under an 8 MiB / half-core server cap did **not** meet
25,000 requests/sec: about 3,167 correct responses per configured second,
86.23 ms HTTP p99, and 6.55 million dropped arrivals. Zero response errors alone
is not a passing capacity result. Native-client screens are separately labeled
and do not substitute for k6 acceptance.

Start with the [documentation index](docs/README.md), [implementation status](docs/implementation-status.md)
and [product roadmap](goal.md). Hardware, workload definitions, resource accounting
and failed tests are retained with the results.
