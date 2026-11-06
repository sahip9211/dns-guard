# Encrypted configuration validation

Implementation: `3bc53524dce5c6ed0446aef47c3648a99a08a2a3`, measured 2026-11-06
on Linux x86-64. SQLCipher 4.19.0 embeds SQLite 3.53.4; the selected crypto provider
is bundled OpenSSL 3.6.3. Configuration and rollback journal page contents are
encrypted and authenticated. Private policy indexes, OS credential custody and
installer-enforced instance isolation remain unfinished; see the
[security model](security-model.md).

## Correctness

The 88 Rust tests cover wrong-instance keys, unkeyed reads, modified ciphertext,
key generation and permissions, explicit plaintext import, interrupted encrypted
transactions, database limits, revision conflicts, and configured DNS serving
while an independent database connection holds an exclusive lock. There is no
automatic plaintext fallback. The source plaintext database remains unchanged
after migration and must be handled separately.

Local Rust tests, formatting and Clippy passed. Linux and minimum-Rust CI passed;
Windows was still running and macOS was queued when this report was written.
Python (19 tests) and Go (2 tests) CI passed. See the
[implementation CI run](https://github.com/sahip9211/dns-guard/actions/runs/42251748905).

## Footprint and constrained DNS diagnostic

The stripped release executable grew from 1,853,656 to **6,621,088 bytes**.
SQLCipher/OpenSSL are bundled; `ldd` shows libc, libgcc and the system loader,
with no external SQLCipher or OpenSSL runtime. The 87,812-rule index occupies
1,018,122 bytes and either configuration fixture occupies 12,288 bytes. Build
tools are not shipped runtime dependencies.

Both builds served the same blocked synthetic `ads.example` A request over UDP
for 60 seconds with 32 closed-loop clients. Each service had an enforced 8 MiB
cgroup limit, no swap and a 50% single-core CPU quota with a 10 ms period.
The generator ran outside that cgroup. Configuration is closed before serving;
the DNS request path performs no SQL or database encryption.

| Measurement | Plaintext baseline | Encrypted configuration |
| --- | ---: | ---: |
| Correct responses | 143,376 | 159,127 |
| Correct responses/s | 2,389.32 | 2,651.90 |
| Errors / timeouts | 0 / 0 | 0 / 0 |
| p95 | 58.674 ms | 47.276 ms |
| p99 | >100 ms | >100 ms |
| Maximum observed latency | 549.443 ms | 534.866 ms |
| Mean service CPU, one core | 22.92% | 23.63% |
| Sampled peak service RSS | 4,603,904 bytes | 8,323,072 bytes |
| Cgroup charged-memory peak | 3,874,816 bytes | 3,166,208 bytes |
| Cgroup OOM kills | 0 | 0 |

The histogram retains exact microsecond bins only through 100 ms. Above that
limit it retains an overflow count, not individual latency values. More than 1%
of each run overflowed, so p99 is **greater than 100 ms**, not zero or an exact
number recoverable from this report. RSS and cgroup charged memory differ:
shared executable/index pages can be charged outside the test cgroup. These
warm-cache runs do not qualify cold-start memory under an isolated 8 MiB budget.

The desktop was contended: an observation during the run showed load averages
11.52/12.54/11.23 on eight logical CPUs. The generator itself averaged 73–75% of
one core. These sequential runs do not establish a speed improvement from
encryption or measure sustainable open-loop capacity. The 25,000 requests/s and
p99 <20 ms target remains unmet. This is a DNS diagnostic, not a k6 HTTP test or
a comparable $12 Server Challenge workload.

The [sanitized measurement record](benchmarks/encryption-dns-comparison.json)
includes binary/source hashes, aggregate generator/service resources and cgroup
counters. Per-sample process traces remain local; no key, database or downloaded
filter corpus is published.
