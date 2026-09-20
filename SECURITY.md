# Security scanning

Run the installed gosec against all production Go packages:

```sh
make security
```

The target runs `gosec ./...` with all default rules and analyzers. It does not
exclude packages or rule IDs. Gosec does not include test files by default.

## Review on 2026-09-20

Using **gosec 2.29.0** and Go 1.27.1 on macOS arm64, the initial scan reported
**47 findings** across 27 source files. After changes, the same scan reports
**0 findings**, no Go loading errors, and **14 narrowly scoped annotations**.

Code changes address 33 findings:

- 19 integer-conversion findings: bind wire lengths to checked local values,
  encode certificate lengths with `binary.BigEndian`, preserve parsed 16-bit
  values in their types, parse signed consensus parameters directly at 32-bit
  width, and avoid narrowing CLI link values. Signed parameters now accept the
  full valid range, including -2147483648.
- 4 array-index findings: make both three-hop loop bounds explicit, including
  comparisons with earlier hops.
- 8 unchecked-error findings: propagate directory-session cleanup failures
  without publishing a snapshot or penalizing a guard. Channel/socket teardown
  intentionally discards close results where an earlier failure or cancellation
  is authoritative, or where `Channel.Close` always returns nil.
- 2 variable-path findings: use `os.Root` for state-file reads and directory
  synchronization. Reads reject symlinks, validate permissions and size, and
  verify that the opened inode still matches the checked entry. State writes
  also require a single filename component. These APIs are available in Go 1.24.

## Reviewed exceptions

Each exception names one rule at its exact import, expression, or field and
includes its rationale. No numeric/indexing rules are suppressed.

| Rules | Locations | Rationale |
| --- | --- | --- |
| G401 / G505 (13 annotations) | `directory/authority.go`, `directory/consensus.go`, `directory/fast.go`, `torcert/cert.go`, `relaycrypto/crypto.go` | Tor's legacy RSA fingerprints, authority certificate signatures, and original relay running digests use SHA-1. The directory verifier also retains verification-only support for legacy consensus signatures. The directory-only CREATE_FAST bootstrap also requires the SHA-1 KDF-TOR, inside a TLS channel authenticated against both pinned relay identities. Application circuits continue to use ntor. Replacing these with a different hash would change the authenticated wire data. SHA-256 remains in ntor, microdescriptor digests, cache consensus identity, and TLS certificate binding. |
| G407 (3 annotations) | `relaycrypto/crypto.go`, `onion/ntor.go` | Tor's original AES-CTR cipher starts each direction at zero with a fresh per-hop key derived by ntor. Cipher counters persist across cells; callers must never reuse hop key material. The v3 service hop likewise uses a zero counter with a fresh hs-ntor AES-256 key. INTRODUCE1 uses a zero counter with a fresh ephemeral-derived key; the handshake rejects a second encryption. Randomizing the initial counter would break the wire protocol. |
| G402 (1 annotation) | `channel/handshake.go` | Tor authenticates the exact TLS leaf through CERTS and both configured relay identity pins before exposing a channel. Ordinary Web PKI verification does not implement that authentication scheme. TLS session resumption is disabled. |
| G304 (1 annotation) | `cmd/veil/directory.go` | Local CLI flags intentionally select files to inspect or use as bootstrap configuration. These paths never originate in relay messages or downloaded directory documents, and reads are bounded. |

Protocol references: [relay message digests](https://spec.torproject.org/tor-spec/relay-cells.html),
[authority key certificates](https://spec.torproject.org/dir-spec/creating-key-certificates.html),
[consensus signatures](https://spec.torproject.org/dir-spec/consensus-formats.html),
and [Tor channel authentication](https://spec.torproject.org/tor-spec/negotiating-channels.html).
Existing interoperability vectors and provenance are in [UPSTREAM.md](UPSTREAM.md).

To audit the annotations themselves, rerun with suppression disabled:

```sh
gosec -nosec ./...
```

That audit intentionally exits nonzero and reports exactly the 18 reviewed
exceptions above. It must not reveal additional integer, indexing, or unchecked
error findings. An exception for a current Tor format does not authorize use of
these primitives in unrelated or future features.

## Verification

- Normal gosec scan: passed, zero findings and zero loading errors.
- Suppression-disabled audit: exactly 18 reviewed exceptions.
- `go vet ./...` and the complete `go test -race ./... -timeout=60s`: passed.
- Production binary rebuilt successfully.
- Regression tests cover state-file permissions, symlinks, size limits, filename
  traversal, atomic replacement without following the destination symlink,
  integer boundaries, and cleanup failure preventing snapshot publication.
- Five-second fuzz runs passed: `FuzzBodies` (548,752 executions) and
  `FuzzDirectoryDocuments` (1,344 executions).

These results are static-analysis and regression checks, not an independent
security audit or a claim of production anonymity. The implementation limits
remain in [README.md](README.md) and [ROADMAP.md](ROADMAP.md).

## TCP stream milestone follow-up

The 0.6 stream implementation was scanned on 2026-09-20 with the same gosec
version and default rules: **29 production files, zero findings, zero loading
errors, and the existing 14 annotations**. No stream code or new parameter
handling required a suppression. Full race tests and vet passed; stream fuzz
and live C Tor interoperability results are recorded in [VALIDATION.md](VALIDATION.md).

## SOCKS5 milestone follow-up

Veil 0.7 was scanned with gosec 2.29.0 on 2026-09-20: **32 production files,
zero findings, zero loading errors**, and the existing 14 reviewed exceptions.
The loopback-only SOCKS server, dedicated-circuit dialer and proxy CLI introduce
no suppressions. Race tests, SOCKS parser fuzzing and real curl requests through
a private Tor network passed; details are in [VALIDATION.md](VALIDATION.md).

## Public bootstrap milestone follow-up

Veil 0.8 adds two narrowly scoped protocol exceptions in `directory/fast.go`
(G505 import and G401 SHA-1 KDF). The current total is **16**, including the
14 historical exceptions above. CREATE_FAST is private to the one-hop directory
transport, uses fresh random inputs and constant-time key-confirmation checking,
and is covered by Tor's published test vector and live public relay exchanges.
See [CREATE_FAST specification](https://spec.torproject.org/tor-spec/create-created-cells.html).
It provides no independent authentication or forward secrecy beyond the pinned
TLS channel; it never carries application streams or extends to other hops.

The complete directory budget is 64 MiB; per-document and per-download limits
remain in force. Public mode still requires a majority of all nine bundled
authorities and all referenced microdescriptor digests. Neither public bootstrap
nor the browser instructions weaken verification or enable direct fallback.

The 0.8 scan passed on 2026-09-20: **34 production files, zero findings, zero
loading errors**. The suppression-disabled audit reported exactly those 16
exceptions. Full race tests and vet passed; public HTTPS and cache restart
results are recorded in [VALIDATION.md](VALIDATION.md).

## Reliability milestone follow-up

Veil 0.9 adds advisory OS locking for shared state and bounded retries only for
known transient circuit-build failures. Verification failures, unknown errors,
path-selection errors, state failures and application stream failures do not
trigger retries. Joined errors are retryable only when every component is
retryable, so a local cleanup/state failure cannot be hidden by a network error.
The same persistent guard store is used for every attempt.

The current gosec scan covers **37 production files**, with **zero findings,
zero loading errors and the unchanged 16 protocol annotations**. No new
suppressions or dependencies were introduced. Race tests, vet, crash-release and
cross-process contention checks passed; see [VALIDATION.md](VALIDATION.md).

## V3 onion milestone follow-up

Veil 0.10 was checked on 2026-09-20 with gosec 2.29.0: **43 production files,
zero findings and zero loading errors**. The suppression-disabled audit reports
exactly **18** reviewed protocol exceptions: the prior 16 plus two G407
annotations for the hs-ntor INTRODUCE1 cipher and AES-256 service-hop cipher.
The audit has no integer, indexing, or unchecked-error findings.

Address checksum/version and canonical curve encodings are checked before
routing. Signed consensus values determine descriptor periods and HSDirs.
Descriptors have bounded parsing, signatures and expiry checks, MAC verification
before decryption, and signed introduction key bindings. hs-ntor keys are only
installed after authenticating the service reply. Failed onion requests never
fall back to exits or local DNS; application streams are not replayed.

Public services only: client authorization, PoW solving and production privacy
parity remain incomplete. In 0.10, descriptor lifetime/revision was parsed but no
persistent descriptor cache or cross-connection rollback history was maintained.
A valid signed older descriptor can therefore still be used until its validity
ends. The single additional dependency is Edwards25519 public-point/field math,
pinned in go.mod/go.sum. This is not an independent cryptographic review.

## Scoped reuse milestone follow-up (0.11)

Gosec 2.29.0 reports **46 production files, zero findings and zero loading
errors**. The suppression-disabled audit still reports exactly **18** existing
protocol annotations. No suppressions or dependencies were added for pooling,
isolation tokens, descriptor caching or rotation.

Reuse requires explicit tokens plus matching destination, port and IP family.
SOCKS scopes additionally include application IP and listener address; credentials
are hashed with length framing and cleared from parser buffers. API tokens use a
separate namespace. Tokens are not access-control credentials. Untagged requests
continue to use dedicated circuits, and all state remains private to a Dialer.

Pooled setup detaches caller deadlines before publishing a circuit. Individual
stream cancellation/Close does not cancel another stream's circuit. Failed BEGIN
operations retire the circuit for future attachments without replaying the failed
request or killing healthy active streams. Expired directories reject new BEGINs,
including after waiting for a build. Age retirement drains active streams; idle
and failed entries are bounded and discarded. Shutdown cancels and joins pending
builds and closes circuits before the CLI releases directory state ownership.

Descriptors are verified before caching. The 128-record memory bound includes
revision history; live history is never evicted to accept new keys. Expired
plaintext is not reused, lower revisions and equal-revision conflicts fail, and
an equal revision cannot refresh the original TTL. History is scoped and lasts
through its blinded-key period, with expired records pruned on cache access.
No history survives restart; neither first-seen rollback nor cross-scope rollback
can be detected. See README.md for the remaining experimental privacy limits.
