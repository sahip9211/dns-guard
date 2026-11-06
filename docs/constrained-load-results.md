# Fixed-budget HTTP load measurements — 2026-11-06

The current prototype serves the real policy index under verified Linux CPU and
memory limits. The lowest passing short screen so far is **6 MiB of charged
memory and 25% of one logical CPU**, at 2,500 requests/sec. This is a measured
screening result, not a production minimum: memory reclaim occurred. A 4 MiB
budget caused an OOM kill; reducing CPU to 10% or 20% at 6 MiB missed arrivals and the
latency gate. CPU and memory are ceilings, not constant consumption.

The **15-minute stress run survived at 8 MiB / 50% CPU**, handling 8,671,093
requests with zero response errors. It **failed the 25,000/sec target**: about
9,635 correct responses per configured load second, HTTP p99 33.24 ms and
13,828,615 dropped arrivals. A requested arrival rate alone is not achieved
throughput. One memory-limit event occurred during connection cleanup; no OOM.

## Implementation and method

- Hyper/Tokio HTTP adapter, one worker for constrained runs, one shared immutable
  FST, at most 2,048 active connections, 8 KiB parser buffers, 32 headers and a
  10-second header-read timeout. Idle connections do not require OS threads.
- Core matching remains exact and allocation-free. The async adapter itself
  allocates connection/response state. The change reduced measured adapter RAM
  in exploratory screens; it did not establish a universal latency improvement.
- Actual systemd/cgroup-v2 ceilings, 10 ms CPU quota period, swap disabled and
  64-task ceiling. The runner reads the kernel settings back before loading.
- Real 178,507-rule index, 1,889,139 bytes; 12,000 independently expected queries
  checked before load. Each load response is checked for the expected blocked
  category mask. The workload rotates 2,000 device labels through 200 VUs for
  constrained tests. Labels do not prove 2,000 concurrent clients.
- i7-10510U, 8 logical CPUs, Arch-based Linux, Rust 1.99.1 and k6 2.3.0. Generator
  and target share the host. Builds were stopped for the long run; unrelated
  desktop processes were not controlled. CPU affinity/frequency were not pinned.
- CPU 100% means one logical CPU. Mean CPU and sampled RSS include preflight and
  k6 summary generation. RAM includes the adapter and index. Generator resources
  are separate. The process sampling interval can exceed the load duration.
- Tests-first implementation: adapter and budget tests failed before code was
  added, then passed. Checkpoint: 24 Rust tests, nine Python tests, formatting and
  Clippy with warnings denied.

## Budget screening

All rows below use the same async adapter and one worker, with a 30-second
configured arrival period except the 20% CPU row, which ran for 60 seconds.
Handled/sec is correct responses divided by that
period; k6's separate overall rate includes setup. A few in-flight requests may
finish during drain. HTTP p99 excludes connection setup; matcher p99 excludes
HTTP parsing, queueing and serialization.

| RAM cap | CPU cap | Target/sec | Handled/sec | HTTP p99 ms | Matcher p99 ms | Mean CPU | Dropped arrivals | Outcome |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 16 MiB | 100% | 25,000 | 7,560.67 | 54.390 | 0.009908 | 32.77% | 522,871 | Target and latency failed |
| 8 MiB | 50% | 25,000 | 4,556.40 | 82.218 | 0.014876 | 24.92% | 613,106 | Target and latency failed; build overlap |
| 6 MiB | 25% | 2,500 | 2,500.03 | 3.652 | 0.009537 | 14.00% | 0 | Passed; reclaim pressure |
| 4 MiB | 25% | 2,500 | — | — | — | — | — | OOM killed; aborted |
| 6 MiB | 10% | 2,500 | 2,377.50 | 92.432 | 0.009038 | 9.92% | 3,672 | Target and latency failed |
| 6 MiB | 20% | 2,500 | 2,362.02 | 124.208 | 0.024825 | 17.51% | 8,288 | Target and latency failed; 60 seconds |

Completed-duration rows had zero HTTP and policy response errors. Dropped
arrivals are additional failures; they are not included in the response-error
percentage. The aborted 4 MiB run produced connection errors after the kill and
is excluded from steady-state comparisons. Systemd recorded `Result=oom-kill`.

The 6 MiB / 25% passing screen handled 75,001 requests. Sampled RSS peaked at
6.88 MiB; cgroup peak was 6.156 MiB, with 279 memory-limit events but no OOM.
These metrics are deliberately not substituted for one another: RSS and cgroup
charged memory account shared mappings differently, and the kernel permits
temporary overshoot during reclaim.
[Linux memory controller semantics](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#memory-interface-files).

The 8 MiB / 50% short screen overlapped a brief incremental build/test run and
must not support a controlled before/after latency claim. More generally, these
screens differ in budgets, concurrency or generator settings and are exploratory.
The final 20% CPU screen had 5,969 memory-limit events and a 6.484 MiB charged
peak while reclaiming, with no OOM kill. This reinforces that 6 MiB has very
little headroom. A single passing 30-second screen at 25% CPU is insufficient to
recommend that budget for deployment, and the non-monotonic short-run latencies
must not be interpreted as a calibrated CPU-capacity curve.

## Earlier 10× exploration

A 60-second blocking-adapter run targeting 25,000/sec delivered about 6,071/sec,
with p99 102.60 ms, 1,135,321 dropped arrivals, mean server CPU 57.06% and peak
RSS 18.31 MiB. Restricting the generator to `GOMAXPROCS=2` made it slower. The
four-worker async screen used about 10.10 MiB peak RSS and 26.70% mean server CPU,
but delivered 4,307/sec with p99 129.69 ms and also failed the target. The lower
RAM/CPU observations do not prove an end-to-end latency win.

High generator CPU alongside low server CPU suggests generator/host contention;
it does not establish isolated server capacity. A separate load host is needed
to distinguish generator limits from target limits at 25,000/sec.

## Fifteen-minute result under enforced limits

Run: `results/k6-local-20261106T105803Z`. One async worker, 200 VUs, 2,000
rotating labels, 25,000 scheduled arrivals/sec for 900 seconds. The k6 exit code
was 99 (threshold failure); `completed` is false even though the full duration
finished. The HTTP p99 gate was 20 ms and dropped-arrival gate was zero.

| Measurement | Result |
| --- | ---: |
| Enforced charged-memory / CPU / swap ceilings | 8 MiB / 50% of one logical CPU / 0 bytes |
| Correct responses / issued requests | 8,671,093 / 8,671,093 |
| Correct responses / configured load second | 9,634.55/sec |
| k6 overall correct response rate, including setup | 9,597.10/sec |
| HTTP p99 | 33.237282 ms |
| Matcher p99 | 0.009975 ms |
| HTTP / policy response errors | 0% / 0% |
| Dropped arrivals | 13,828,615 |
| Server CPU mean / sampled peak | 37.37% / 48.78% of one logical CPU |
| Server RSS sampled peak | 7.824 MiB |
| Kernel charged-memory peak | 7.949 MiB |
| Memory-limit events / OOM kills | 1 / 0 |
| Throttled CPU periods after verified startup | 15,868 |
| CPU throttled time after verified startup | 18.628 seconds |
| Generator CPU mean / sampled peak | 539.63% / 673.03% |
| Generator RSS sampled peak | 2,158.41 MiB |

Process sampling covered 941.42 seconds, including setup and k6's final summary
calculation. This explains why CPU averages cover a longer interval than the
900-second arrival phase. RSS was flat at 6.949 MiB during sustained load and
increased during cleanup; the reported peak includes cleanup. No memory event
is discarded. Generator RAM includes k6's accumulated latency measurements and
is not application RAM or part of the shipped product.

This run's observed latency was lower than the earlier short 10× screens, but
duration, VUs, worker count, quotas and host activity differed. It is not a
controlled speedup claim. The result demonstrates survival under this budget,
not passing 25,000/sec capacity or a production latency SLO.

Full reports and hashes: [constrained-load-results.json](benchmarks/constrained-load-results.json).
The long-run resource series is preserved in
[constrained-load-samples.csv](benchmarks/constrained-load-samples.csv).

## Reproduce and interpret

Use the [fixed-budget test command](../tests/load/README.md). Each run preserves
configuration, executable/corpus/query/script hashes, raw k6 metrics, one-second
server/generator/cgroup samples and logs. The durable JSON companion retains
reports and provenance, including failures; raw local run directories are under
`results/` and excluded from source control.

The release CLI is 400,296 bytes; the async test executable is 725,264 bytes and
is not shipped as part of the CLI. Neither this memory budget nor those file
sizes establish the complete product's all-in <10,000,000-byte footprint. DNS
forwarding, cache, UI, analytics and feed updates are not implemented or measured
here. Resource enforcement is currently Linux-specific; Windows/macOS adapters
and real DNS transport tests remain future work.
