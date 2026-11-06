# Transport and generator diagnostics — 2026-11-06

The 25,000 requests/sec goal under 8 MiB charged server memory and 50% of one
logical CPU is **not met**. The default runner remains the Hyper/Tokio adapter.
The new polling adapter and native client are experiments, not a production DNS
transport, a public HTTP API, or replacements for k6 acceptance.

## Comparison with the $12 server challenge

The [leader's detail page](https://benchmarks.arjaythedev.com/12-dollar-server/leaderboard/rust-iouring-kensac)
reports 29,284 req/s, 190 ms HTTP p99, 82% CPU, 25 µs CPU/request and 1,114 MB peak
RAM, scored **November 2, 2026**. The leaderboard header's October 25 date is not
the individual score date. CPU time/request is not elapsed latency. The detail
page's reported CPU/request is retained as published rather than inferred from
rounded headline CPU/throughput numbers.

[Its implementation](https://github.com/arjaythedev/twelve-dollar-server-challenge/tree/main/submissions/rust-iouring-kensac)
uses a single io_uring driver, reusable buffers, direct HTTP handling, and separate
checkpoint work. It also reads SQLite B-tree internals and group-commits writes.
Its Linux-specific ring features have no epoll fallback. These are useful design
ideas, not a portable drop-in server or performance guarantee. No source code was
copied from the submission.

Our preceding five-minute HTTP test handled 950,042 correct responses, about
3,166.81 per configured second, p99 86.23 ms, peak RSS 6.71 MiB, average CPU 22.32%
of one core, and 6,549,698 dropped arrivals. Lower p99 and memory do not establish
superiority: the workloads, hardware, resource accounting and latency thresholds
differ. Our prototype has no request-path SQL, authentication or durable writes.
The [challenge](https://github.com/arjaythedev/twelve-dollar-server-challenge#scoring)
uses a separate k6 machine; ours competes on the same desktop. Device labels are
not equivalent to the challenge's long-lived simulated users with think time.

## Generator screen

With the same saved server binary, corpus, 200 VUs, 25,000 requested arrivals/sec
and fixed server limits, four 30-second k6 screens varied only GOMAXPROCS. They
ran in the order 2, 1, 4, 8. There was no simultaneous compilation or other project
benchmark. These are short unpaired screens on an active laptop, not a controlled
causal ranking or a passing capacity result.

| k6 GOMAXPROCS | Correct/configured second | HTTP p99 ms | Dropped arrivals |
| --- | ---: | ---: | ---: |
| 2 | 1,643.97 | 200.79 | 700,687 |
| 1 | 1,114.67 | 445.31 | 715,072 |
| 4 | 4,693.70 | 73.25 | 609,146 |
| 8 | 3,922.03 | 87.03 | 632,284 |

All had zero HTTP/policy response errors; **all failed** latency/arrival acceptance.
The substantial generator sensitivity motivates independent diagnostics; it does
not prove the server can handle the missing traffic. [Raw reports](benchmarks/generator-screen.json).
[Grafana's large-test guidance](https://grafana.com/docs/k6/latest/testing-guides/running-large-tests/)
also recommends watching generator CPU and preserving capacity headroom.

Read-only inspection found the laptop on AC with battery full, the `powersave`
governor and `power` energy preference, and an allowed 400 MHz–4.9 GHz range.
Sampled CPU frequencies in earlier runs were often near 800 MHz. No power settings,
system services, or user applications were changed to improve the result.

## Native client and polling adapter

`tools/bench/native/main.go` uses Go's standard HTTP/JSON libraries and validates all
12,000 fixture cases before scheduling traffic. It checks every issued response,
records HTTP and matcher percentiles, errors and unscheduled drops, and also
records scheduled-time-to-completion latency. It uses 1 ms arrival batches and
bounded workers, so it is **not identical to k6's arrival process**. A final
partial scheduling interval can contribute drops. It must never be presented as
a k6 acceptance pass. It does not add a Go dependency to the shipped application.

`tools/bench/run_native.py` starts a uniquely named transient service, verifies
8 MiB/no-swap/half-core caps, samples server and generator separately, preserves
binary hashes, and stops its own service. Provide the index, query-case and compiled probe paths explicitly; see the
[tool guide](../tools/README.md).

The poll adapter uses safe Rust, Mio readiness polling (not io_uring), and httparse.
One loop drives sockets; no async task or OS thread is created per connection.
Connection input storage starts at 1 KiB and grows only as needed to an 8 KiB
header ceiling. A 512-byte output buffer formats complete responses in place.
The ready queue deduplicates live connection entries; each pass handles at most
256 ready connections and each connection at most 16 replies before yielding.
Active connections are capped at 2,048, with excess accepted sockets closed.
That connection cap alone does not promise every connection fits in 8 MiB.

The HTTP surface is deliberately restricted: loopback binding, origin-form
requests, no request bodies or transfer encodings, and no TLS. Host/header framing,
partial reads/writes, pipelined replies, buffer overflow, and connection close
have tests. These do not amount to full HTTP conformance or adversarial internet
qualification. Timing and response policy semantics remain the same. Unlike the
Hyper adapter, this minimal experiment does not add a Date header.

The shared route formatter can now write into caller-owned fixed storage. The
existing String-returning route reserves space for a normal decision response,
so its compatibility path does not repeatedly grow the String. Allocation tests
cover full successful wire response formatting as well as both matcher formats.

## Preliminary native observations

These two 30-second, unpaired screens used GOMAXPROCS=2 for the diagnostic client,
200 in-flight workers, the real 178,507-rule corpus, and 25,000 requested/sec.
Their generator and server processes shared the same machine. Header/body sizes,
parsing paths, and scheduling differ from k6, so compare them only as diagnostics.

| Adapter | Correct/configured second | HTTP p99 ms | Mean server CPU | Peak server RSS MiB | Drops |
| --- | ---: | ---: | ---: | ---: | ---: |
| Saved Hyper | 9,442.53 | 42.35 | 41.80% | 6.36 | 466,724 |
| Poll candidate | 11,276.27 | 30.77 | 40.56% | 4.29 | 411,712 |

Both had zero response errors and no OOM event. Neither met the target. The
candidate shows a useful direction but requires paired repetitions and sustained
k6 qualification before changing the default. These observations precede the
compatibility String-capacity cleanup and final test-only additions; each report
records the exact tested binaries. [Full diagnostic reports](benchmarks/transport-diagnostics.json).

New tests were observed failing before implementation. Final local checks cover
41 Rust tests, Python reporting/download tests, and two Go tests, plus formatting and Clippy. CI
adds the native-client tests alongside the existing Rust OS matrix and Python
checks. Cross-platform CI results are separate from local Linux validation.
