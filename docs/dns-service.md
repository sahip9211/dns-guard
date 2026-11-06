# DNS filtering service

The prototype now serves DNS over UDP and TCP. One immutable policy index is
shared by all requests. It is a forwarding resolver: upstream recursive resolution
must be configured explicitly. The service does not change OS DNS configuration.

## Local use

```sh
cargo build --release --locked
mkdir -p .cache
./target/release/dns-guard compile .cache/example.dngi --other-bytes 1000000 \
  --feed adblock ads tests/load/ads.txt --feed adblock adult tests/load/adult.txt
./target/release/dns-guard serve .cache/example.dngi --upstream 127.0.0.1:53
```

The upstream must actually provide independent DNS resolution. Do not configure
it to forward back to DNS Guard. Direct self-address and wildcard/loopback loops
are rejected; indirect routing loops and every local interface alias cannot be
detected from a socket address alone. The size reservation above is illustrative;
use a complete installed-file inventory for a real compiler budget.

The default listener is `127.0.0.1:5353`, avoiding privileges and existing port-53
services. With `dig` installed, `dig @127.0.0.1 -p 5353 ads.example` should report
REFUSED; `+tcp` tests the TCP listener. Unblocked names use the configured upstream.

For a LAN, explicitly choose the service interface and client networks, for example:

```sh
./target/release/dns-guard serve .cache/example.dngi \
  --listen 192.168.10.2:5353 --allow-client 192.168.10.0/24 \
  --upstream 192.168.10.1:53 --max-inflight 64 --max-tcp-connections 32
```

Use the actual interface/upstream addresses on the deployment. Standard clients
usually need a listener on port 53, which requires the appropriate OS service
privileges. No installer, privilege helper or systemd service package is supplied
yet. `--allow-client` replaces the default loopback networks; repeat it to allow
additional networks. IPv4-mapped IPv6 clients are checked as IPv4 addresses.
There is one global category mask (`--categories`), not per-device profiles yet.

## Processing and resource bounds

- The CLI runs one Tokio event-loop thread. Idle sockets do not occupy OS threads.
- Default limits: 64 in-flight queries, 32 TCP clients, 4,096-byte query messages,
  1,232-byte advertised UDP payload, and a two-second upstream deadline.
- UDP overload drops the new datagram and increments `overloaded`. TCP overload
  closes the connection. There is no unbounded application request queue.
- TCP clients can reuse connections and pipeline frames; each connection processes
  one request at a time. A five-second deadline covers reading a complete frame
  and another covers writing its reply. Slow clients consume bounded slots.
- Each upstream UDP exchange uses a fresh ephemeral socket and independently
  randomized ID. A connected socket constrains the source address/port; the parser
  also verifies ID, opcode and the full question. Wrong replies are ignored until
  the original deadline. A validated truncated response triggers TCP fallback.
- TCP responses are bounded by DNS's 65,535-byte frame size. TCP clients use TCP
  upstream directly. Responses larger than the client's UDP allowance become a
  small TC response, allowing a client retry over TCP.
- Policy matching remains allocation-free. DNS parsing, buffers and tasks allocate;
  limits on counts and wire sizes are not proof of a fixed process RSS ceiling.
  External cgroups can enforce CPU/RAM caps for measurement.

Hickory handles DNS parsing and serialization. Reply correlation follows the
requirements in [RFC 5452](https://www.rfc-editor.org/rfc/rfc5452#section-9.1);
TCP support, reuse and framing are covered by
[RFC 7766](https://www.rfc-editor.org/rfc/rfc7766). This prototype is not a claim of
complete conformance with every DNS extension.

## Policy and protocol behavior

Blocked questions and blocked CNAME destinations return REFUSED with the original
question and transaction ID. Each CNAME target is checked independently against
the enabled categories; an allow for one name does not exempt an unrelated target.
Raw DNS labels retain boundaries, so embedded dots cannot become extra labels;
SRV-style non-hostname labels can still match a blocked hostname ancestor.

One standard IN-class recursive question is supported, with at most one OPT record.
Malformed requests receive FORMERR when a usable query header exists. Short packets,
response packets sent to the listener and oversized UDP queries are dropped.
Non-query opcodes receive NOTIMP. Transfers, non-recursive queries, signed requests
and additional request records other than OPT are refused. Unsupported EDNS
versions receive extended RCODE 16 (BADVERS). Generated replies preserve RD/CD,
clear AD/AA, advertise recursion, and include a fresh OPT when appropriate.

Forwarded replies retain original record bytes and TTLs, including unknown RDATA.
Only the client ID is restored and AD is cleared. Plain upstream DNS is not
independently authenticated. DNSSEC validation, encrypted transports, caching,
DNAME/HTTPS alias-target policy, upstream connection pooling, retries/failover,
rebinding protection and per-client rate limits remain planned.

## Counters and shutdown

Ctrl-C, or SIGTERM on Unix, stops listeners and cancels/drains outstanding tasks.
The CLI then prints aggregate counters. The library exposes a shared `Stats` handle
with approximate concurrent snapshots; it stores no query names or client history.

`received` counts UDP datagrams and complete TCP requests. `blocked` counts local
policy refusals (including CNAME targets), `forwarded` counts allowed upstream
replies prepared for clients, and `upstream_errors` counts failed/timed-out upstream exchanges.
`invalid`, `overloaded`, `denied` and `send_errors` describe separate transport
outcomes; they are not a partition of `received` because denied TCP connections
and connection-limit events occur before a query is read. `inflight` and
`peak_inflight` track the bounded active-query slots.

Tests use local mock upstreams; they do not rely on public DNS or downloaded feeds.
The [UDP diagnostic](../tools/README.md#dns-diagnostic) measures blocked-query latency
and resources separately from the existing HTTP/k6 results. None of those earlier
HTTP results establish capacity for this new DNS service.

## First resource measurement

A 60-second blocked-UDP diagnostic used 32 closed-loop clients and an 87,812-rule
index, with a verified 8 MiB cgroup memory ceiling, no swap, and 50% of one logical
CPU. It completed 165,467 correct replies with zero errors, timeouts or overload
counts: **2,757.49 replies/sec, p99 51.903 ms**. This does not meet the 20 ms latency
target and does not test offered-arrival capacity or upstream forwarding speed.

Server mean CPU was 26.98% of one logical core, peak sampled RSS 4,034,560 bytes,
and peak cgroup-charged memory 2,621,440 bytes; no OOM events occurred. RSS and
cgroup charges have different shared-page accounting and must not be interchanged.
The same-host Python generator averaged 87.11% of one core, so its scheduling and
measurement overhead limit interpretation. No claim of 25,000 DNS queries/sec is
made. [Raw measurement and artifact hashes](benchmarks/dns-service-udp.json).

The separate 60-second k6 HTTP regression screen targeted 2,500 requests/sec with
200 VUs, one server worker and the same 8 MiB / half-core caps. It handled 147,947
requests with zero HTTP/policy errors, but **failed** its gates: HTTP p99 was
78.34 ms and 2,054 arrivals were dropped. Matcher p99 was 0.00843 ms. Server mean
CPU was 17.52% of one core and peak sampled RSS was 6,148,096 bytes; generator CPU
averaged 215.01%. This is an HTTP adapter measurement, not DNS throughput, and it
is not directly comparable with older runs using a larger corpus.
[Full k6 result, configuration and samples](benchmarks/dns-service-k6-regression.json).
