# Numeric hostname hashes and alphabet partitions

Hashing can accelerate matching. The measured exact hash-table alternative is
faster than the compressed FST on this fixture, but uses more RAM than the
current 8 MiB server budget. Alphabet-partitioning the hash tables did not improve
these measurements. The alternatives remain development experiments; the small
production index is unchanged.

## What the number means

A hash maps a variable-length hostname to a fixed-size value. A hash table uses
that value to find candidate entries, then compares the actual key. Distinct
hostnames can share a hash; the number alone is not a unique hostname ID.
Rust's standard hash map combines hashing with key equality and a SwissTable
implementation. Its default seeded hasher is intended to resist hash-flooding
attacks. [Rust HashMap documentation](https://doc.rust-lang.org/std/collections/struct.HashMap.html).

The exact path is:

```text
validate + lowercase → hash hostname/suffix → candidate bucket
                    → compare full stored hostname → apply category policy
```

A rule for `example.com` may apply to `ads.example.com`, so hashing only the
full incoming name would miss valid suffix matches. This prototype checks the
full name and label-boundary ancestors with the applicable scope/action. It
preserves allow/enforce precedence and category masks. Empty maps are cheap,
but hashing multiple suffixes still repeats some work that an FST avoids with
one reversed-name walk per present rule kind.

Minimal perfect hashing, such as [PTHash](https://github.com/jermp/pthash), can
assign distinct slots to a fixed stored set. That mapping alone does not prove
that an arbitrary incoming name belongs to the set. Exact membership still
needs key verification; a short fingerprint instead makes membership
probabilistic. A different compact hash layout or compressed verifier remains
a future experiment, not something disproved by this standard-library test.

## Actual comparison

`examples/hash_compare.rs` implements flat and alphabet-partitioned exact hash
tables, alongside the current production FST. It reuses the production hostname
normalizer and keeps full keys in one contiguous byte pool, borrowed by the
tables. This avoids a separate `String` allocation for each map key. The
partitioned version has 36 possible terminal characters per scope/action and
routes by the first character of the reversed hostname.

Six runs per mode were executed in rotating order, in separate processes, with
the same 178,507-rule index and 12,000 query fixture. Each run warmed and checked
the fixture, then timed 120,000 lookups while checking every blocked result.
RandomState seeds vary across processes. The host was not isolated and clock
frequency was not fixed. These are direct matcher timings, not HTTP/DNS p99.

| Backend | Median run p50 | Median run p99 | Median process RSS before timing | Key-pool + map-slot lower bound |
| --- | ---: | ---: | ---: | ---: |
| Compressed FST + prefix table | 2.620 µs | 8.433 µs | 5.078 MiB | Snapshot 1,889,139 bytes, plus acceleration tables |
| Flat exact hash tables | 1.521 µs | 4.316 µs | 12.680 MiB | 8,608,555 bytes |
| Alphabet-partitioned exact hash tables | 1.603 µs | 4.658 µs | 12.932 MiB | 8,874,907 bytes |

One microsecond is 0.001 milliseconds. Flat hashing reduced median-of-run p50
by about 42% and p99 by about 49% in this experiment. Partitioning did not beat
flat hashing. These figures do not establish a universal result for all hash
functions, index formats or query distributions.

The hash key pool contains 3,103,531 bytes. Even the conservative flat-table
lower bound of 8,608,555 bytes exceeds an 8 MiB cap (8,388,608 bytes), before
the program, connections, queries or allocator overhead. The lower bound uses
map capacity times entry size and omits control bytes, unused allocated buckets
and padding outside the entry. It must not be described as exact allocation size.

RSS includes the query fixture, runtime and retained conversion allocations;
it is not a pure index-byte count. Hash conversion temporarily loads the FST
and builds records/keys before dropping it. Median whole-process high-water RSS
was about 17.84 MiB for flat hashing, versus 6.07 MiB for FST, including timing
samples. No serialized hash index or complete installed-size claim is provided.
This memory experiment was uncapped so all alternatives could finish; it is
separate from the capped server tests.

Raw results and hashes: [hash-comparison-results.json](benchmarks/hash-comparison-results.json).

```sh
cargo build --release --example hash_compare --locked
./target/release/examples/hash_compare fst /tmp/dns-guard-smoke/rules.dngi /tmp/dns-guard-smoke/queries.tsv
./target/release/examples/hash_compare hash /tmp/dns-guard-smoke/rules.dngi /tmp/dns-guard-smoke/queries.tsv
./target/release/examples/hash_compare sharded-hash /tmp/dns-guard-smoke/rules.dngi /tmp/dns-guard-smoke/queries.tsv
```

Tests first failed with an empty implementation. The completed tests force every
key to hash to the same number and verify that unknown names still do not match.
They also compare flat/sharded backends with the validated FST across all 128
enabled-category masks, all scopes/actions, mixed case, suffix boundaries and
invalid inputs. The benchmark is not a production backend switch.

## Alphabet queues versus shared workers

In this fixture, 39.08% of names end in `m`, and 38.60% use `.com`. Routing from
the original first character also has skew: `p` receives 29.10% and `n` 26.22%.
These are synthetic fixture counts: a quarter of the queries intentionally have
a `probe.` prefix and a quarter use `.invalid`. They are not production DNS
popularity measurements.

An illustrative full-name SHA-256 routing into four buckets produces counts
3,051 / 2,990 / 2,929 / 3,030. This measures distribution only, not hash cost or
queue throughput, and SHA-256 was not selected as a request-routing dependency.
Repeated requests for one hot hostname would still choose the same bucket.
[Distribution data](benchmarks/shard-distribution.json).

Dedicated alphabet queues are not enabled: request-count skew is established,
but a queue-performance benefit is not. We retain bounded admission and shared
workers over one immutable index. The existing two-byte prefix table already
selects a smaller exact FST subtree without a thread handoff, mutable cache or
duplicate index. Future expensive work such as feed compilation or batched
analytics should have bounded queues outside this short lookup path; those
components are not implemented here.
