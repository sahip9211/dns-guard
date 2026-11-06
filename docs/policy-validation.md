# Hostname checks and empty-policy validation

The dashboard now checks hostnames against the shared active policy index. Checks
are authenticated, read-only, bounded to 512-byte JSON bodies and do not perform
upstream DNS or database work. Explicit all-filters-off snapshots occupy 71 bytes;
ordinary empty enabled imports remain errors.

## Functional validation

- 110 Rust tests passed, including corruption of every byte of an empty snapshot,
  actual empty-policy upstream forwarding, source selection and zero-allocation
  policy lookups.
- API tests cover active category masks, allow/enforce precedence, canonicalization,
  authentication, wrong methods/types, unexpected/duplicate fields, malformed JSON
  and oversized fixed-length/chunked bodies.
- Two headless Chromium flows passed against populated and empty snapshots,
  including checks, validation/network errors, clearing inputs/results on disconnect
  and keeping hostnames/tokens out of request URLs and browser storage.
- Formatting, Clippy and 15 minimal-feature targeted tests passed.

The preceding port-normalization CI run failed on a macOS test that set a socket
read timeout after the peer had already closed. The test now sets options before
shutdown and accepts EOF/reset/aborted connections while rejecting timeout; the
production shutdown implementation is unchanged. Cross-platform CI must validate
this correction; local Linux tests alone are not macOS qualification.

## Footprint

The Linux native-store-enabled release executable is **7,725,600 bytes**, including
**12,213 bytes** of embedded assets: HTML 2,880,
JavaScript 6,595, CSS 2,738. No dependency was added.
The existing FST, Hyper, http-body-util and Serde libraries handle storage, HTTP,
body limits and JSON. The 71-byte empty snapshot allocates no jump tables and
adds no lookup allocation.

Binary size is not a complete installation audit. Browser/keyring runtimes,
indexes, configuration/journal growth, notices and update overlap still count
against the all-in 10 MB target. The 25,000 requests/sec performance gate remains
unqualified; prior [management measurements](management-validation.md) are retained
with their original artifact hashes and workload limits.
