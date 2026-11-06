# Management dashboard validation

The first dashboard milestone is a read-only browser interface and optional
loopback status API. It adds no DNS-path SQL or per-query HTTP work. The full
application's performance, total footprint and device-capacity goals remain open.

## Final executable sizes

The final default-port fix build (`da0bb58`) measures
**7,642,784 bytes** with native stores and **6,876,928 bytes** without them.
Both include the 8,421-byte embedded dashboard. The feature adds 245,408
bytes to the previous native-store-enabled executable. These are binary sizes,
not a complete installation audit; see [build hashes and accounting](benchmarks/management-build.json)
and [size budget](size-budget.md).

## Constrained comparison

Three sequential 60-second runs used the same 87,812-rule, 1,018,122-byte index
and encrypted startup configuration, with 32 closed-loop UDP clients requesting
`ads.example`. The answer was independently checked as blocked. Each server ran
under verified cgroup limits of **8 MiB memory, zero swap and 50% of one CPU core**
(5 ms CPU quota per 10 ms period). Generators ran outside that cgroup.

| Case | DNS replies/sec | DNS p99 ms | Errors | CPU mean, % one core | RSS peak, MiB | Cgroup peak, MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Previous native-keyring build | 7,365.98 | 7.297 | 0 | 26.65 | 8.19 | 2.92 |
| New build, management disabled | 7,075.62 | 8.726 | 0 | 25.95 | 8.51 | 2.96 |
| New build, management polled at 20/sec | 7,309.12 | 8.169 | 0 | 26.28 | 8.42 | 4.42 |

During the third run, k6 sent **1,200 real authenticated API requests**: 19.999/sec,
**0.597 ms p99**, zero HTTP/schema errors and zero dropped arrivals. All configured
k6 thresholds passed. This API rate represents roughly 40 tabs polling every two
seconds; it does not qualify 40 active browsers or 1,200 concurrent devices.

These are observations on a shared desktop, not statistically established
improvements or regressions. Closed-loop DNS traffic slows with the server/client
and cannot establish offered-arrival capacity. RSS includes shared file-backed
pages; it can exceed cgroup charges. Warm shared-page accounting is not proof of
operation on a cold machine with only 8 MiB total memory. There were no cgroup
OOM kills. The **25,000/sec capacity target is not met/qualified** by these runs.

The [aggregate JSON](benchmarks/management-dns-comparison.json) records complete
CPU/RAM/error/rate/percentile data, cgroup counters and binary/index hashes. It
identifies implementation commit `bd30509`; the later default-HTTP-port origin
normalization fix has separate regression tests. No raw keys, indexes or lists
are committed.

## Reproduction

Build the release executable and compile/fetch a local index as documented in the
README. Use an encrypted configuration with an explicit upstream, a loopback DNS
listener and a separate management token. Keep the same artifact/index/configuration
for management-off/on runs. For a live server PID:

```sh
python3 -m tools.bench.dns_probe --address 127.0.0.1:5353 \
  --hostname ads.example --duration 60 --clients 32 --pid SERVER_PID \
  --output results/dns-management.json
```

Supply `MANAGEMENT_TOKEN` via a protected process environment and run
`k6 run tests/load/management.js` concurrently for the management-on case.
Set `BASE_URL`, `RATE=20`, `DURATION=60s` and `SUMMARY_PATH` as needed.
Use the existing `tools.bench.resource_budget` helper to create and verify
transient systemd user-unit CPU/memory limits, and sample cgroup state before and
after each run. The development Python/k6 tools do not belong in the shipped app.
The preceding command alone does **not** apply resource limits.

## Functional scope

Local validation passed **104 Rust tests**, Clippy, three isolated Linux native-store
tests, four systemd credential tests, 11 minimal-feature management tests, and headless Chromium login, responsive layout, polling pause, outage,
reconnection, disconnect and reload. Native OS APIs remain delegated to maintained
libraries. The implementation and default-port fix runs are tracked in
[feature CI](https://github.com/sahip9211/dns-guard/actions/runs/42276517114) and
[fix CI](https://github.com/sahip9211/dns-guard/actions/runs/42277282364).
Local success does not establish Windows/macOS qualification for this change.
