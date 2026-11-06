# Configuration milestone: resource and performance checks

Measured on 2026-11-06. The implementation adds durable startup settings, not a
new DNS lookup algorithm. [Configuration behavior and limits](configuration.md)
and the [remaining checklist](../task.md) define the scope.

## Build size and storage

| Artifact | Bytes |
| --- | ---: |
| Previous DNS/cache-only executable | 1,032,472 |
| Initial settings executable, default bundled SQLite build | 3,252,408 |
| Compact settings executable, including portability fixes | 1,853,656 |
| Test index: 87,812 policies | 1,018,122 |
| Settings database | 12,288 |

Removing unused SQLite FTS/spatial modules and extension loading, and using size
optimization for SQLite's C implementation, reduced the new executable by about
43%. Rust DNS code retains speed optimization. The executable embeds SQLite;
`ldd` reports only the system C/compiler-support libraries and loader, not an
external SQLite runtime. Full UI, analytics, package metadata and update overlap
are still missing from the complete-product size qualification.

## Actual DNS service, fixed resource limits

Three sequential runs used 32 closed-loop Python clients for 60 seconds each,
querying the blocked synthetic name `ads.example` over UDP. Each server had a
verified 8 MiB cgroup limit, zero swap and 50% of one logical core with a 10 ms
quota period. The index and request semantics were unchanged. No upstream was
contacted. Generators ran outside the server cgroup on the same desktop.

| Measurement | Previous direct CLI | Current direct CLI | Current saved settings |
| --- | ---: | ---: | ---: |
| Correct replies | 348,227 | 394,151 | 338,212 |
| Correct replies/sec | 5,803.50 | 6,568.95 | 5,636.56 |
| p95 latency | 9.092 ms | 6.531 ms | 8.898 ms |
| p99 latency | 15.189 ms | 7.783 ms | 16.011 ms |
| Maximum latency | 245.487 ms | 22.584 ms | 336.384 ms |
| Errors / timeouts | 0 / 0 | 0 / 0 | 0 / 0 |
| Mean server CPU, one core | 27.88% | 28.43% | 28.48% |
| Peak sampled RSS | 3,997,696 | 4,333,568 | 4,861,952 |
| Peak cgroup charged bytes | 2,359,296 | 2,621,440 | 2,359,296 |
| Mean generator CPU, one core | 92.28% | 94.52% | 92.37% |

No OOM, overload or send errors occurred. Percentiles are histogram upper bounds
including reply validation. RSS and cgroup charged memory have different
accounting and should not be treated as interchangeable. Startup storage increases
observed resident memory; closing a database does not imply all code/allocator
pages immediately leave RSS.

The shared desktop had uncontrolled scheduling contention, and the Python
generator used over 90% of one core. These are regression observations, not a
capacity estimate or evidence that configuration improved DNS speed. The saved
settings run was slightly slower than the previous binary; this experiment does
not isolate a cause. The 25,000/sec acceptance gate remains open. Mixed names,
forwarding, cached replies, independent arrivals, UI and analytics need separate
tests. A repeat of the earlier measurement varied substantially on this machine.

The [DNS report](benchmarks/configuration-dns-comparison.json) records the exact
binary/index/source hashes, implementation commit, hardware, cgroup counters and
summary statistics. CPU peak summaries were recomputed from original samples
using minimum 100 ms windows to avoid a final 3.8 ms sample magnifying a single
CPU clock tick. Means and RSS values were unchanged; raw samples remain in the
ignored local results directory.

To repeat the workload, start the previous or current service with the same
index/listener/upstream and equivalent verified resource limits. For saved settings,
initialize with `config init` and start `serve --config` as described in the
[configuration guide](configuration.md). Once readiness is reported, run:

```sh
python3 -m tools.bench.dns_probe --address 127.0.0.1:5353 \
  --hostname ads.example --clients 32 --duration 60 \
  --pid SERVICE_PID --output results/dns-config-check.json
```

Use the actual bound address/PID. A direct shell launch alone does not enforce
the cgroup limits. The existing `tools.bench.resource_budget` helpers create and
verify the transient systemd limits used for these measurements.

## k6 policy HTTP regression

The existing HTTP policy adapter separately passed a 60-second arrival-rate run
at 2,500 requests/sec under the same 8 MiB/half-core server caps:

- 150,001 correct responses, zero errors and zero dropped arrivals.
- HTTP p95 0.554 ms and p99 2.257 ms; matcher p99 0.004281 ms.
- Mean server CPU 12.96% of one core; peak sampled RSS 6,148,096 bytes.
- The generator averaged 172.54% of one core and ran outside the server budget.

This tests policy HTTP handling, not DNS transport or saved configuration. Its
2,000 device labels are workload labels, not authenticated enrolled devices. It
does not erase earlier failed runs or establish 25,000/sec capacity. See the
[k6 report](benchmarks/configuration-k6-regression.json) and reproduce with:

```sh
python3 -m tools.bench.run_k6 --index .cache/dns-bench.dngi \
  --output results/config-k6-regression --duration 60s --rate 2500 \
  --vus 200 --devices 2000 --workers 1 --cpu-percent 50 --memory-mib 8
```

Build the documented HTTP adapter and put k6 on PATH, or supply `--server` and
`--k6`. Use a freshly compiled corpus with the synthetic policy fixtures.

## Correctness and portability

82 Rust tests pass locally, with 19 Python tests and two existing Go tests covered
by CI. Linux, macOS and Windows CI and the new Rust 1.89 compatibility job verified
the configuration implementation. Cross-platform checks exposed and fixed a
directory-alias issue in SQLite NOFOLLOW handling and an independent TCP/UDP
ephemeral-port collision. Explicit requested ports still fail on conflicts.

The database-full test has a fixed insertion limit; removing its page quota cannot
turn the test into an unbounded disk writer. Process-exit recovery and exclusive
database-lock tests exercise persistence and DNS isolation. Hardware power-loss,
complete packaging, live management and long mixed-load soaks remain unfinished.

[Validation CI](https://github.com/sahip9211/dns-guard/actions/runs/42243083951)
passed all platform, minimum-Rust and development-tool checks at commit `650d8e3`.
