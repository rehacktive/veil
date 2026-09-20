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
| G407 (1 annotation) | `relaycrypto/crypto.go` | Tor's original AES-CTR cipher starts each direction at zero with a fresh per-hop key derived by ntor. Cipher counters persist across cells; callers must never reuse hop key material. Randomizing the initial counter would break the wire protocol. |
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

That audit intentionally exits nonzero and reports exactly the 16 reviewed
exceptions above. It must not reveal additional integer, indexing, or unchecked
error findings. An exception for a current Tor format does not authorize use of
these primitives in unrelated or future features.

## Verification

- Normal gosec scan: passed, zero findings and zero loading errors.
- Suppression-disabled audit: exactly 16 reviewed exceptions.
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
