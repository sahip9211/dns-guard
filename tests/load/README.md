# k6 benchmarks

The loopback HTTP adapters exercise the real policy engine. They are development
harnesses, not DNS listeners or a production management API. `ads.txt`, `adult.txt`
and `cases.json` in this directory contain synthetic test domains only.

## Small fixture

Install k6 separately, then run from the repository root:

```sh
cargo build --release --bins --examples --locked
mkdir -p .cache
./target/release/dns-guard compile .cache/test.dngi \
  --other-bytes 1000000 \
  --feed adblock ads tests/load/ads.txt \
  --feed adblock adult tests/load/adult.txt
python3 -m tools.bench.run_k6 \
  --index .cache/test.dngi --cases tests/load/cases.json \
  --output results/smoke --duration 30s --rate 2500 --vus 200
```

The reservation is illustrative; supply a complete inventory for actual installed
size checks. A tiny fixture validates the harness, not large-list capacity.
Output directories must be new, preventing accidental overwrite of measurements.

## Real-list workload

Fetch and compile sources locally; generated lists and query corpora must remain
in ignored directories. The following assigns test category masks to entire feeds;
it does not classify every domain in a mixed-purpose source.

```sh
python3 -m tools.feeds.fetch --source hagezi-light --source hagezi-nsfw
./target/release/dns-guard compile .cache/real.dngi \
  --other-bytes 5000000 \
  --feed adblock ads .cache/feeds/hagezi-light.txt \
  --feed adblock adult .cache/feeds/hagezi-nsfw.txt
python3 -m tools.bench.prepare_cases .cache/queries \
  .cache/feeds/hagezi-light.txt .cache/feeds/hagezi-nsfw.txt
python3 -m tools.bench.run_k6 \
  --index .cache/real.dngi --cases .cache/queries/cases.json \
  --output results/real-5m --duration 5m --rate 25000 --vus 200 \
  --workers 1 --devices 2000 --cpu-percent 50 --memory-mib 8
```

Adjust the illustrative reservation to the actual downloaded files, application
and reserved growth. Source content changes over time; reports record hashes of
the index, query cases, server and k6 script.

## Limits and interpretation

The resource-capped mode requires Linux cgroup v2 and a systemd user manager with
CPU/memory controller delegation. It verifies 5 ms CPU per 10 ms at 50%, the
requested memory limit, and zero swap. Only its unique transient service is
stopped. The generator runs outside the server cap and is measured separately.

The async adapter is the default. One worker uses a current-thread runtime;
additional workers share the immutable index. Requested TCP backlog is 128 and
active connections are capped at 2,048. These bounds alone do not guarantee that
all admitted connections fit a selected memory ceiling. Kernel memory counts.

Use `--server target/release/examples/load_server_poll` for the experimental
single-worker polling adapter, or `load_server` for the blocking comparison.
The polling adapter has a restricted HTTP surface and is not a public server.

The k6 setup verifies every expected case before timing. Every measured response
checks policy correctness and matcher timing. Default gates require HTTP p99
below 20 ms, matcher p99 below 0.05 ms, no incorrect/failed responses, no dropped
arrivals and a nonempty workload. Failed runs remain in reports.

- Requested rate is not achieved throughput. Report issued, correct and dropped counts.
- The k6 counter rate includes setup. `requests_per_configured_load_second` divides
  correct responses by the configured arrival duration and can include late drains.
- HTTP latency includes transport; matcher latency excludes HTTP and scheduling.
- CPU 100% means one logical core. Sampling includes setup/drain/summary work.
- RSS and cgroup charged memory measure different things; OOM outcomes take priority
  over a stale last sample. No-response runs report missing metrics, not zero latency.
- Device headers are workload labels, not authenticated devices or DNS clients.
- A shared desktop can limit the load generator. Separate machines are needed for
  stronger capacity claims; do not silently substitute another test protocol.

The runner writes configuration, artifact hashes, logs, per-second samples, k6
metrics and a normalized `report.json`. Optional `--mode concurrency` is a closed
loop and must be labeled separately from constant-arrival tests.

See [results and limitations](../../docs/transport-diagnostics.md) and the
[measurement archive](../../docs/benchmarks/README.md). No benchmark executable,
Python environment, Go client or k6 installation belongs in the shipped app.
