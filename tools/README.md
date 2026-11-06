# Development tools

Run Python modules from the repository root. These tools are not application
runtime dependencies. Downloaded feeds and generated outputs belong in `.cache/`
and `results/`, both ignored by Git.

| Tool | Purpose |
| --- | --- |
| `python3 -m tools.feeds.fetch` | Download selected HTTPS sources from `config/sources.json` |
| `python3 -m tools.bench.prepare_cases` | Build independent expected queries from two Adblock feeds |
| `python3 -m tools.bench.run_k6` | Run k6 and capture correctness, latency, CPU/RSS and cgroup results |
| `python3 -m tools.bench.compare_matchers` | Alternate direct matcher binaries with artifact hashes |
| `python3 -m tools.bench.process_metrics` | Measure a standalone process on Linux |
| `python3 -m tools.bench.sqlite_probe` | Separate SQLite batching/index experiment on Linux |
| `python3 -m tools.bench.dns_probe` | Closed-loop blocked/synthetic-A UDP diagnostic with latency and process metrics |
| `python3 -m tools.bench.run_native` | Supplementary native HTTP diagnostic under the same server caps |

`load_report.py`, `process_metrics.py` and `resource_budget.py` share the tested
reporting/accounting logic. Tests live in `tests/python/`.

## Feed downloads

```sh
python3 -m tools.feeds.fetch --list
python3 -m tools.feeds.fetch --source hagezi-light --source hagezi-nsfw
```

Downloads use HTTPS with redirects restricted to HTTPS, bounded streaming,
SHA-256 records and staged replacement. Default limits are 4 MB per source and
8 MB for the development cache including old/staged files and metadata reserve.
These are cache limits, not a complete product-footprint audit. A failed transfer
keeps the previous source file. File and metadata renames are not a single
multi-file transaction; verify hashes before consuming a cache after a crash.
The service's automatic scheduler, conditional refresh and live activation are
not implemented. Nothing is fetched merely by cloning or building the project.

## Native diagnostic

Go 1.22+ is required only for this tool:

```sh
mkdir -p .cache/bin
(cd tools/bench/native && go test ./...)
(cd tools/bench/native && go build -o ../../../.cache/bin/http-probe .)
cargo build --release --example load_server_poll --locked
python3 -m tools.bench.run_native \
  --probe .cache/bin/http-probe --server target/release/examples/load_server_poll \
  --index .cache/real.dngi --cases .cache/queries/cases.json \
  --output results/native-diagnostic --duration 30s --rate 25000
```

This Linux wrapper needs a delegated systemd user cgroup. The client uses 1 ms
arrival batches, checks every response, and reports missed work. Its result is a
diagnostic, **not a k6 acceptance pass**. See the [benchmark guide](../tests/load/README.md)
and [transport notes](../docs/transport-diagnostics.md).

## DNS diagnostic

With a running DNS service whose index blocks `ads.example`:

```sh
python3 -m tools.bench.dns_probe --address 127.0.0.1:5353 \
  --duration 60 --clients 32 --output results/dns/report.json
```

Add `--pid PID` on Linux to sample server CPU/RSS. The generator is sampled
separately. Every successful reply must have the original ID/question and an
empty REFUSED response. The fixed histogram reports upper bounds in 1 µs bins;
percentiles above its 100 ms range are null, with overflow count and maximum
reported. This is a closed-loop blocked-query diagnostic, not an offered-arrival
capacity result or a substitute for k6. Forwarding correctness uses local mock
upstreams in `tests/dns_server.rs`; upstream network latency needs its own workload.

For a controlled cache experiment against a synthetic upstream returning one A
record with TTL at most 300 seconds:

```sh
python3 -m tools.bench.dns_probe --address 127.0.0.1:5353 \
  --hostname cache.example --answer-ip 192.0.2.7 --answer-ttl 300 \
  --duration 60 --clients 1 --output results/cache/report.json
```

This narrow validator checks the ID, flags, exact question, one A/IN record,
address, TTL ceiling and complete packet framing. It accepts the test owner's
uncompressed name or a compression pointer to the question. It is not a general
DNS response parser. Compare `serve --cache-bytes 0` with the default cache using
the same upstream, binary, index and resource limits; report upstream request
counts as well as client latency. The workload does not establish office capacity.
