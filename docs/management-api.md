# Read-only local management

The optional embedded browser dashboard shows actual aggregate DNS/cache counters.
It does not retain hostnames or expose database paths, keys or client identities.
There are no configuration mutations, sessions, roles or remote HTTPS endpoints yet.

## Start and credentials

Desktop credential custody uses the existing maintained Secret Service, Keychain
and Windows Credential Manager libraries, under `dns-guard.management-token.v1`.
Database keys retain the separate `dns-guard.instance-key.v1` namespace.

```sh
dns-guard management token-create --keyring
# stdout: secret 64-character token; stderr: independent public credential ID
dns-guard serve INDEX --upstream 127.0.0.1:53 \
  --management-listen 127.0.0.1:8788 --management-token-keyring PUBLIC_ID
```

Visit exactly the numeric URL printed at startup. `localhost` and alternate
Host headers are deliberately rejected. For port 80, the browser-normalized Host
without `:80` is also accepted and Origin uses the normalized URL. IPv6 `[::1]:8788` is also supported.
Nothing opens a browser automatically or changes the machine's DNS settings.
Management options also work with `serve --config DATABASE --keyring DATA_KEY_ID`.
The active database key cannot be reused as the management token.

Headless/development alternative:

```sh
dns-guard management token-create management.key
dns-guard serve INDEX --upstream 127.0.0.1:53 \
  --management-listen 127.0.0.1:8788 --management-token-file management.key
```

Files contain exactly 32 random bytes; Unix creation uses mode 0600. Existing
files are never overwritten. Use a trusted private parent directory and the
native store or OS credential delivery for production custody. Plain key files
are not encrypted vaults and inherit platform directory/ACL limitations.
A service can use a second systemd encrypted credential and pass its runtime path
through `--management-token-file`; the supplied service template does not enable
management or provision this second credential automatically.

`management token-show --token-file PATH` or `--token-keyring ID` explicitly
exports the existing bearer value to stdout. Protect terminal history/scrollback
and redirected output. Ordinary server logs and status responses never print it.
Missing/locked/corrupt entries fail without generating replacement credentials.
To revoke a token, generate a different credential and restart with it. Deleting
its backing entry does **not** revoke the in-memory credential of a running service.
Automatic expiry, live rotation and multi-user access remain unfinished.

## API v1

`GET /api/v1/status` requires exactly one `Authorization: Bearer TOKEN` header.
It returns `schema_version: 1`, application `version`, `uptime_seconds` since the
management runtime started, `policy: {rules, bytes, enabled_categories}`, and a `dns` object:

| Fields | Meaning |
| --- | --- |
| received, blocked, forwarded | Cumulative DNS requests and filtering/forwarding counters |
| upstream_errors, invalid, overloaded, denied, send_errors | Distinct DNS failure/admission counters; not a single additive error rate |
| inflight, peak_inflight | Current and peak admitted work |
| cache_hits, cache_misses, cache_evictions | Cumulative cache activity |
| cache_entries, cache_bytes | Current cache accounting, not total RSS or installed data |

See [DNS counter semantics](dns-service.md). Counters are approximate concurrent
atomic snapshots, not transactions. They reset on restart. JSON integers are
unsigned; JavaScript display loses integer precision above 2^53−1. No percentile,
CPU utilization, traffic-byte or per-device metrics are invented from these totals.

`POST /api/v1/policy/check` uses the same independent read-only bearer token and
origin checks. Send `Content-Type: application/json` and a body such as
`{"domain":"ads.example"}`. This evaluates the shared active index and the service's
configured categories, without upstream requests, SQL, index copies or DNS-counter
increments. It is a read-only operation; POST keeps the hostname out of URLs and
browser navigation history. No domain history is retained by the service.

The JSON response contains `schema_version: 1`, normalized `domain`, `blocked`
(boolean), `blocked_categories`, `allowed_categories`, `enforced_categories` and
`enabled_categories` (category bitmasks: ads=1, adult=2, malware=4, tracking=8,
phishing=16, gambling=32, social=64).
This checks the question hostname only: upstream answers/CNAME targets, client
ACLs and transport errors are not evaluated. Full source/rule explanations are
still pending. Unicode input requires an IDNA A-label.

Bodies are limited to **512 bytes**, including chunked transfer, using
`http-body-util::Limited`. Authentication occurs before reading the body. Unknown
or duplicate JSON fields, invalid hostnames and malformed JSON return 400;
unsupported content type returns 415 and oversized bodies return 413. Stalled
body reads are covered by the existing whole-connection deadline. No other route
accepts request bodies. Method mismatches return 405 with an appropriate Allow
header. The dashboard cancels checks on hide/disconnect and clears input/results
on disconnect; results are rendered as text rather than HTML.

`GET /`, `/app.js` and `/app.css` serve the public login shell with no embedded
credentials. All responses from the application handler use `Cache-Control:
no-store`, a restrictive CSP, frame denial and MIME sniffing protection. Hyper's
parser-level rejection responses may be generated before that handler.

Numeric Host must match the actual bound address and port. An Origin, if supplied,
must match that origin exactly; Fetch Metadata permits only same-origin or direct
navigation (`none`). Duplicate authorization/origin headers, cross-origin requests,
query parameters and unsupported methods are rejected. Only the bounded policy
check endpoint accepts a JSON request body; other routes reject bodies and transfer encoding.
No CORS or forwarded-host trust is enabled. Unsupported paths return 404.
A secret in a URL is never accepted. These controls protect browser access; they
are not isolation from an administrator or another process with the same OS identity.
Loopback HTTP has no TLS; this milestone does not support remote proxy exposure.

The assets are compiled into the executable and must not be counted again as
separately installed files. See [current measurements](policy-validation.md) for
asset/build sizes. Full installed size accounting still includes indexes,
credential runtimes and update overlap.

## Bounded work and libraries

HTTP parsing is delegated to [Hyper 1.12](https://docs.rs/hyper/1.12.0/hyper/server/conn/http1/struct.Builder.html),
JSON to Serde, and fixed-length bearer comparison to
[subtle](https://docs.rs/subtle/2.6.1/subtle/trait.ConstantTimeEq.html).
No HTTP parser, encryption primitive or native vault implementation is hand-written.

Management runs on a separate single-thread Tokio runtime, sharing atomic
counters and the same immutable index with DNS. It opens no database, duplicates
no index and uses exact FST lookups rather than scanning rules. Limits:

- 8 accepted active HTTP connections, including slow clients.
- 8 KiB parser buffer/header limit and 32 headers per request.
- 3-second whole-connection deadline, including response writes.
- One request per connection; no keepalive/pipelined sessions.
- At most 64 admitted connections per one-second fixed window. Adjacent windows
  can admit a boundary burst. Excess connections close immediately, without a 429
  response or an unbounded pending queue in application memory.
- Shutdown cancels and drains active HTTP tasks. Unexpected management thread exit
  stops the DNS supervisor rather than leaving a partially failed combined process.

The browser polls every two seconds, permits one status request and one explicit
policy check at a time, times them out,
pauses when hidden and labels stale values on disconnection. Tokens stay in tab
memory; no cookies, localStorage or sessionStorage. JavaScript/HTTP buffer copies
are not guaranteed to be wiped from memory. Native/desktop process isolation,
crash dumps and privileged access remain separate security work.

## Verification

Rust tests cover wrong/missing/duplicate tokens, key reuse, native namespaces,
origin/Host checks, unsupported bodies/methods, oversized headers, slow clients,
IPv4/IPv6, shutdown and a real DNS-to-status counter update. Browser tests are
headless and cover authentication, empty counters, paused polling, outages,
reconnection, mobile overflow, disconnect and reload without retained tokens.

```sh
cargo test --all-targets --locked
npm ci --prefix tests/web --ignore-scripts
npx --prefix tests/web playwright install chromium
npm test --prefix tests/web
```

`DNS_GUARD_CHROMIUM` optionally selects an installed Chromium executable;
`DNS_GUARD_TEST_BINARY` selects an absolute server binary path. Browser tooling is
development-only and adds no shipped Node.js dependency. The CI Linux job runs
headless browser tests; all three OS jobs run the HTTP/CLI and native-store tests.

`tests/load/management.js` exercises the **real API** with k6. Supply
`MANAGEMENT_TOKEN` through the process environment, `BASE_URL`, and optionally
`RATE` (default 20/sec), `DURATION` and `SUMMARY_PATH`. Do not enable HTTP debug
logging with real credentials. The test includes p99, rate, errors and dropped
arrivals. This small management workload is not a DNS capacity benchmark.

For k6 policy checks, also set `POLICY_DOMAIN` and an explicit
`EXPECTED_BLOCKED=true` or `false`. Without these, the workload remains status-only.
