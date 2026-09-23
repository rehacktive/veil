# Security scanning

## Shared guard channels and live policy — 2026-09-21

Native clients and service hosts now own separate `channel.Pool` instances.
Each pool keys reuse by numeric address and both Tor identity pins. It refuses
bootstrap channels and a different guard-policy owner. New leases reserve IDs
before CREATE; each lease owns its receive queue, cancellation and teardown.
Raw `channel.Dial` still exposes the dedicated transport API. Circuit encryption,
stream IDs, SENDME credit and application isolation remain circuit-local.

The pool caps physical channels at eight and total live/closing leases at 1,024.
Receive queues hold at most 1,024 cells per lease, allowing the existing 1,000-cell
circuit window plus controls. Overflow retires only that lease. Unknown IDs fail
the shared transport. Cells for known retired IDs are discarded: a full window
may already be in flight when a circuit closes, so a short consecutive-cell cap
would let normal teardown disrupt siblings. Circuit IDs remain non-reusable and
the channel allocation cap remains 65,536.

Queued writes keep their order after a circuit request cancels. A lease-local
send gate orders teardown after such writes. Pool lifetime, a 30-second physical
handshake bound and a separate 30-second write bound prevent unbounded transport
work. If DESTROY cannot be queued within 500 ms, the channel stops admitting
new circuits and closes after existing leases drain. Actual TLS/protocol failure
affects all attached circuits; request cancellation alone does not.

`PaddingPolicy` publishes updates only after the guard store accepts a live,
verified, rollback-protected snapshot. Subscribers coalesce updates without an
unbounded notification queue. The sole TLS writer handles timer changes and
START/STOP, retaining the fact that a channel has carried application traffic.
Policy expiry stops cover writes; active circuits continue. Idle-retention
changes affect only channels without live leases. Owner shutdown cancels and
joins handshakes, readers, leases and retained channels.

No new scanner suppressions were added: default gosec reports **66 production
files, zero findings and 19 existing annotations**. These changes have not had
independent review. Shared-transport congestion, scheduling and traffic shape
still need adversarial and matched-workload analysis; this is not a claim of
traffic equivalence to C Tor.

## Client onion circuit padding — 2026-09-21

`circuit/padding.go` implements the two client setup machines against a second
hop advertising authenticated `Padding=2`. The sole reader validates hop, stream,
version, machine/counter and response state before accepting padding controls.
Incoming cover cells are limited to ten for introduction and one for rendezvous.
Unsolicited/wrong-hop padding, duplicate acknowledgments and padding after STOP
or rejection close the circuit. Old-counter replies are ignored within the
existing 128-consecutive-ignored-cell bound. A legitimate negotiation error
disables that machine without changing guards or retrying another path.

The rendezvous client sends at most one cover cell; cryptographic delay sampling,
an output-gate check and the guard-store-wide budget prevent a padding backlog.
Signed disable/reduced/global limits refresh when the guard store accepts a live
consensus, and expired policy cannot authorize new cover writes. Link padding
now follows live policy as described above. The two accounting mechanisms are separate.

`client/introduction.go` retains padded introductions for ten minutes, at most
`MaxCircuits` including reservations. Full capacity waits subject to the setup
deadline; it does not evict existing introductions to hide resource exhaustion.
The dialer owns retained lifetimes independently of application streams and
joins teardown on close. Failed circuits release reservations promptly.
Tests exercise protocol rejection, output pressure/cancellation, retention expiry,
capacity and teardown. Default gosec reports **64 production files, zero findings
and 19 unchanged annotations**; full race tests and vet pass.

This is not an independent audit or evidence of traffic indistinguishability.
Service-side setup, application timing/volume, shared channel lifetime, TLS
differences and cross-session traffic analysis remain review targets. Previous
sections below record earlier milestones and their then-current limitations.

## Running the scanner

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

The complete directory budget is 64 MiB; per-document, compressed-wire and
decompressed-output limits remain in force. Deflate decoding accepts the
concatenated zlib streams required by the directory protocol without weakening
document or digest verification. Public mode still requires a majority of all
nine bundled authorities and all referenced microdescriptor digests. Neither
public bootstrap nor the browser instructions weaken verification or enable
direct fallback.

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

## Onion-only policy follow-up (0.12)

The opt-in onion-only policy is enforced independently by the SOCKS frontend and
native Go dialer. Only addresses accepted by the existing v3 onion parser can
proceed. Hostnames, literal IP destinations and invalid onion addresses are
rejected before destination lookup, circuit construction or pooled-circuit reuse;
the dialer also rejects them before waiting for connection capacity. There is no
exit fallback. Tor relay and directory IP connections remain necessary, and the
policy cannot restrict application traffic sent outside this proxy.

Gosec 2.29.0 reports **46 production files, zero findings and zero loading
errors**, with the unchanged **18** protocol annotations. No cryptographic
changes, dependencies or suppressions were introduced. Race tests and vet pass;
live SOCKS checks rejected hostname, IPv4 and IPv6 destinations while the public
Tor Project v3 onion site returned HTTP 200. See [VALIDATION.md](VALIDATION.md).

## Debug logging follow-up

Proxy diagnostics are opt-in through `-debug`; no global logger is installed and
normal proxy operation is silent by default. Help and fatal errors remain visible.
The CLI uses a shared standard-library slog text handler on stderr, which
serializes concurrent records and escapes values. Request IDs are numeric counters,
independent of SOCKS isolation credentials.

Debug output deliberately includes destination names, exit relay metadata and
onion directory/introduction relay addresses. SOCKS credentials, isolation tokens,
cryptographic keys, descriptor contents and application payloads are not recorded.
Veil creates no log files automatically. Library loggers are explicitly supplied
per instance; nil disables logging, including inherited request logging.

Full race tests and vet pass. Gosec reports **47 production files, zero findings
and zero loading errors**, with the existing **18** protocol annotations unchanged.
No dependency or suppression was added. Quiet-mode, credential exclusion,
concurrent escaping and live public HTTPS checks are recorded in VALIDATION.md.

## Onion hosting follow-up (0.13)

The native host uses a persistent Ed25519 identity and durably reserves revision
counters before publishing. Private state uses the existing audited atomic
write/private read routines under exclusive directory ownership. A missing key
alongside an existing hostname fails rather than silently changing the address.
Blinded signing, descriptor certificates and both encryption layers follow the
Tor specification. A C Tor peer accepted the descriptor and completed hs-ntor.
This is interoperability evidence, not an independent cryptographic review.

INTRODUCE2 is authenticated before its plaintext is parsed or used for routing.
Repeated client keys and cookies are rejected, including cookies replayed through
another introduction point. Replay history is bounded without eviction while its
keys remain accepted; saturation rotates the introduction generation. Processing
is capped at 64 introductions/second across all host generations. Rendezvous and stream
counts, I/O deadlines, publication passes and circuit lifetimes are bounded.

Only the configured virtual port is accepted. The backend is a fixed numeric
loopback endpoint; incoming addresses cannot select a different destination.
Rendezvous relays must match the live verified directory, including the supported
link list and ntor key. All public-network circuits use normal guarded selection.
The localhost-hop helper requires the `veiltest` build tag and is absent from
production builds. No flag enables it in the production CLI.

Gosec reports **53 production files, zero findings and zero loading errors**.
There are **19** narrowly scoped protocol annotations: the previous 18 plus the
protocol-mandated zero CTR IV used to decrypt authenticated hs-ntor introductions.
No new dependency was added. Full race tests, vet, parser fuzzing and private
C Tor interoperability pass. Hosting remains experimental: full Vanguards, PoW,
restricted discovery remain unimplemented; long-running public availability is
not yet validated.

Introduction rotation/recovery retains healthy advertised introduction circuits.
Rendezvous workers belong to the host and keep their original lifetime deadlines;
the same host-wide rendezvous and stream limits cover old and new generations.
Old keys stop accepting requests at the latest certificate expiry of any
attempted descriptor upload. An upload with a lost acknowledgment may still have
reached an HSDir, so retention is recorded before sending, regardless of success.
Certificate expiry, rather than three hours from upload, also covers clients
fetching an older descriptor later. This follows Tor's [descriptor expiration
rules](https://spec.torproject.org/rend-spec/deriving-keys.html#expiring-hidden-service-descriptors).

The host holds at most four generations, including any replacement being built:
12 introduction circuits, 4,096 client keys per introduction and 12,288 cookie
entries per generation (49,152 across the host). Cookie replay detection and the
processing rate budget span all live generations. Saturated replay state rejects
requests and closes the affected reader without evicting live history. At the
generation limit, replacement waits for expiry or loss of all points in a
generation; unexpired advertised keys are not evicted to make room.

Introduction readers stop and join before their cookie history is released;
failed points close independently, preserving healthy siblings. Host cancellation or a
fatal error cancels and joins all rendezvous/stream workers before `Run` returns.
Relay failures, replay-cache saturation and unavailable HSDirs can still cause
connection failures; overlap does not guarantee availability under those conditions.

## Vanguards-Lite, guard-link padding and traffic measurements — 2026-09-21

Vanguards-Lite now covers native onion client and hosting construction. Review
`directory/vanguards.go` for pool membership, lifetime/count clamping and endpoint
independence; `circuit/build.go`, `circuit/onion.go` and `circuit/service.go` for
three/four-relay authentication and virtual service-hop addressing; and
`relaycrypto/crypto.go` for single installation of that virtual hop. Clearnet
family/subnet checks remain separate. The service's remotely supplied rendezvous
must not cause entry-guard exclusions or unrestricted L2 replacement. The Lite
pool intentionally does not persist across process restarts.

`channel/padding.go` schedules idle padding in the sole transport writer, with
cryptographic randomness and queued-data priority. `directory/padding.go` clamps
signed consensus timing values. There is no padding queue or worker per timer;
channel close unblocks the writer and joins it. Inbound relay padding negotiation
is rejected on all link versions. Directory-only bootstrap channels opt out.

A controlled local comparison in `scripts/traffic_fingerprint.py` records only
TLS metadata from test-created loopback connections. The captured ClientHello
structure differs from C Tor 0.4.9.12 (cipher suites, extensions, groups, signature
algorithms and SNI presence). The raw public names, randoms, session IDs, keys and
application payloads are omitted. This is evidence of remaining distinguishers,
not a statistical anonymity evaluation. In particular, adding padding does not
make Go's TLS handshake indistinguishable from Tor's TLS handshake.

Checks passed with default gosec rules: **59 production files, zero findings,
zero loading errors and 19 existing annotations**. Four-hop paths use a bounded
array after validating path length; no additional suppressions were introduced.
Race tests cover padding activation/reset/closure, sticky L2 membership, expiry,
failed selection without fallback and multi-megabyte service-hop flow control.

For independent review, the outstanding acceptance scope includes TLS handshake
and record behavior, live consensus padding changes, shared-channel retention,
circuit setup padding, adversarial endpoint/guard probing, sustained introduction
rotation, cancellation/resource bounds and cross-session isolation. Reviewers
should reproduce `make check`, `make security`, `make service-check` and the local
TLS report command in README.md before conducting matched-workload captures.
Full Vanguards and PoW remain outside this implementation. No independent audit
has taken place as part of these changes.

## TLS profile follow-up — 2026-09-21

Two avoidable differences were corrected using the standard Go TLS engine:
fresh Tor-shaped cover SNI per connection, and support for implemented hybrid
ML-KEM groups instead of the prior classical-only allowlist. The SNI is generated
independently of addresses, service names, isolation tokens and identity keys. TCP
is connected to a numeric pinned relay before TLS is instantiated, so this name
never triggers a DNS lookup. It is not an authentication credential: the exact
TLS certificate must still validate through the RSA/Ed25519-pinned Tor chain.
Resumption remains disabled. This change concerns the TLS link, not a claim of
post-quantum onion or end-to-end security.

The eight-sample before/after comparison remains distinguishable from C Tor.
The TLS 1.3 key shares differ (Tor sends hybrid + P-256; Go sends hybrid + X25519),
and cipher ordering, extension order/content, signature schemes and supported
group ordering also differ. In particular, Go lacks Tor's P-224 group. Enabling
obsolete or unimplemented mechanisms purely to reproduce bytes would not be a
sound compatibility fix. A shorter size gap is not an anonymity measurement.

Options evaluated:

- Keep `crypto/tls`: preserves the maintained standard TLS engine and lets us
  correct SNI and group configuration now. Its public API does not expose full
  ClientHello extension or TLS 1.3 cipher-suite ordering. See the
  [Go TLS Config documentation](https://pkg.go.dev/crypto/tls#Config).
- A custom engine such as [uTLS](https://github.com/refraction-networking/utls)
  exposes ClientHello customization, but is a fork of the TLS implementation.
  Adopting it requires validating the chosen Tor profile, real support for every
  advertised algorithm, authentication/failure behavior and security-update
  maintenance. No such dependency was added and no equivalence was asserted.
- Using the C Tor/OpenSSL engine changes the project's native-Go architecture
  and runtime dependencies. It is outside this bounded configuration correction.

Default gosec rules pass on **61 production files**, with zero findings and the
same **19 annotations**. The complete race suite and vet pass. Channel tests also
pass with Go **1.24.13**. Real TCP tests exercise TLS 1.2/P-256, TLS 1.3/X25519,
TLS 1.3/P-256 via HelloRetryRequest, and TLS 1.3/X25519MLKEM768. Existing invalid
pin, certificate-binding, expiry, cancellation and resource-limit tests remain
in force. The private onion interoperability suite passes with the new TLS,
including bulk transfers, padding and introduction rotation.
