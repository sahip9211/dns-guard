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
