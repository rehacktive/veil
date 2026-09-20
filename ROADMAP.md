# Native Go client roadmap

The goal is an embeddable native Tor client, with a SOCKS command built on the same library. Stages follow dependency order. Checked items exist in this repository; all other stages are unimplemented.

## 1. Wire and cryptographic foundation — complete

- [x] Channel frames and initial version negotiation for link protocols 4/5.
- [x] CREATE2, CREATED2, EXTEND2, and original relay message bodies.
- [x] Client-side type-2 ntor handshake and hop key derivation.
- [x] Multi-hop original relay encryption, recognition, and digest tags.
- [x] Offline inspection command, upstream compatibility vectors, malformed-input tests, fuzz targets, and race checks.

Acceptance: match the upstream handshake/key vector and all eight Tor-generated ciphertext vectors; enforce wire limits; reject authentication failures; preserve stream state across cells and circuit extension.

## 2. Authenticated channels — complete

- [x] Parse CERTS, AUTH_CHALLENGE, and NETINFO.
- [x] Verify RSA/Ed25519 certificate chains, signatures, key binding, and validity periods against expected identity pins.
- [x] Implement TLS transport and the ordered VERSIONS/CERTS/AUTH_CHALLENGE/NETINFO client handshake.
- [x] Add cancellable channel reader/writer loops, backpressure, random circuit-ID allocation, and teardown.
- [x] Add `veil channel-check` with explicit relay address and both identity pins.
- [x] Validate recorded upstream certificates and a local TLS relay fixture (including the compiled CLI).
- [x] Validate interoperability with a running C Tor relay in a controlled network.

Acceptance: establish a channel to a controlled Tor test relay from an explicitly trusted descriptor; reject incorrect identities, altered/expired certificates, and invalid message ordering; close cleanly on cancellation and partial I/O. TLS alone must not be treated as relay authentication.

The implementation and negative tests are present. Automated Go tests use a local TLS protocol fixture, and certificate compatibility tests use recorded upstream Chutney fixtures. The separate `scripts/check_local_tor.py` check passed against C Tor 0.4.9.12 on localhost with link 5/TLS 1.3, including rejection of incorrect RSA and Ed25519 pins. No public-network or anonymity claim is made. See [VALIDATION.md](VALIDATION.md).

## 3. Trusted directory and guard bootstrap — default lifecycle implemented

- [x] Parse authority certificates, microdescriptor consensuses, and microdescriptors with strict resource bounds.
- [x] Verify configured authority majority, validity, required protocols, and every microdescriptor digest before exposing a complete snapshot.
- [x] Download through native one-hop ntor/BEGIN_DIR circuits with bounded HTTP and authenticated download SENDMEs.
- [x] Atomically cache private directory state, reverify on load, reject rollback/conflicts, and distinguish freshness from expiration.
- [x] Persist sampled/confirmed guards, derive primaries, and select compatible weighted paths with flags, protocol support, family/subnet exclusions, and exit-port summaries.
- [x] Validate recorded Arti directory documents and a live BEGIN_DIR fetch against C Tor 0.4.9.12.
- [x] Implement the default guard context: sampling, confirmation, primary preference, separate directory reachability, expiry, jittered retries, and pending-circuit usability.
- [x] Add a cancellable manager and `veil directory-watch` with randomized refresh scheduling, bounded retries, cache reuse, and per-round channel reuse.
- [x] Test failure/cancellation, guard migration and persistence, recent-expiry recovery, scheduled live refresh, and warm restart.
- [ ] Add long-offline recovery beyond 24 hours, restricted/bridge guard contexts, and path-bias integration with application circuits.
- [x] Run a complete live authority-consensus-microdescriptor bootstrap against a controlled three-relay Tor network.

Acceptance: reject forged and expired directories, use only verified descriptors, preserve guards across restarts, and bootstrap reproducibly in a controlled Tor network. Directory access must follow Tor's bootstrap and privacy rules. The live three-relay test proves the complete document download, verification, and cache path. The default lifecycle is implemented and tested against C Tor; the remaining contexts, long-offline recovery, and production privacy requirements are not claimed complete. Full router-descriptor format support is deferred because this implementation uses microdescriptor consensuses.

## 4. Circuits and streams — fixed-window TCP streams implemented

- [x] Build fixed three-hop circuits with CREATE2/EXTEND2, enforce RELAY_EARLY limits and handshake sequencing.
- [x] Integrate verified path selection with tracked guard attempts, confirmation, usability, build deadlines, cancellation, and bounded teardown.
- [x] Provide ordered authenticated relay transport and `veil circuit-check`; test three-hop C Tor construction and a small directory exchange.
- [x] Add bounded transient build retries in the client with a total setup deadline and persistent guard selection.
- [x] Add bounded circuit reuse within explicit isolation scopes and age/idle rotation with active-stream draining.
- [ ] Add preemptive construction, adaptive circuit policy, and path-bias accounting.
- [x] Multiplex TCP streams, BEGIN/CONNECTED/DATA/END, exit-side hostname resolution, and channel/circuit failure propagation.
- [x] Implement authenticated v1 SENDME, fixed-window flow control, bounded backpressure, and stream deadlines.
- [ ] Add stream retry policy, congestion-control negotiation, and additional negotiated protocol features.
- [x] Expose `Circuit.DialContext`, returning cancellable `net.Conn` streams.

Acceptance: transfer data in both directions over a native three-hop circuit in a controlled network, including large transfers, concurrent streams, EOF, cancellation, and failure propagation. Test DNS through Tor without local destination lookups. Validate against C Tor or Arti peers before public-network use.

C Tor 0.4.9.12 interoperability passed for four concurrent 2 MiB round trips, exit-side DNS, EOF, DNS/policy errors, cancellation, deadlines, and circuit close. Protocol fixtures additionally cover forged/replayed SENDMEs, stalled readers, channel failure, and wire timeouts. Tor's currently implemented END closes both directions; TCP half-close is deferred until an interoperable protocol supports it. Scoped pooling and draining rotation are implemented; broader adaptive policy, stream retry policy and production privacy behavior remain incomplete. The SOCKS client now owns circuit lifetimes and retries transient build failures within a bounded setup budget.

## 5. User-facing client — local and public SOCKS5 testing available

- [x] Loopback SOCKS5 CONNECT, bootstrap configuration, dedicated circuits per connection, and bounded defaults.
- [x] Directory startup/refresh, readiness status, connection/circuit lifetime and idle limits, safe diagnostics, and private persistent state.
- [x] Bundle official public-network authority/fallback pins, implement directory-only CREATE_FAST bootstrap, and verify real public HTTPS through SOCKS5.
- [x] Add exclusive state ownership across all stateful CLI commands, crash-safe lock release, and bounded circuit-build retries.
- [x] Add opt-in onion-only destination policy in the CLI, SOCKS server and Go dialer, with explicit readiness mode.
- [x] Add explicit `-debug` terminal diagnostics for proxy lifecycle, routing and exit relays; keep normal proxy operation quiet.
- [x] Add explicit SOCKS token isolation, destination/family separation and bounded circuit reuse/rotation.
- [ ] Add mature adaptive circuit policy and stream retry policy.
- [ ] Implement applicable link/circuit padding and other privacy requirements for supported client behavior.
- [x] End-to-end private-network curl checks, token negotiation, large HTTP transfers, SOCKS parser fuzzing, race tests, and resource-limit/cleanup tests.
- [ ] Broaden protocol differential tests, sustained fuzzing, and independent security review.

Acceptance: `veil proxy` and the Go client API use native verified Tor circuits with no direct-connect fallback and no Rust/C Tor runtime dependency. Document privacy behavior and remaining differences before describing the client as ready for general use.

The `make proxy-demo` launcher builds a private localhost network and prints a working curl command; `make proxy-check` runs the same check and exits. The demo uses explicit test-only hops because production subnet exclusions intentionally reject localhost paths. It has passed with C Tor 0.4.9.12. `make public-proxy` additionally runs the production CLI against public Tor with bundled bootstrap pins. Both are interoperability testing milestones; production-ready anonymous browsing is not claimed.

## 6. V3 onion client — public services implemented

- [x] Validate v3 addresses and derive period-specific blinded keys/subcredentials.
- [x] Select consensus HSDirs and fetch descriptors through guarded three-hop BEGIN_DIR circuits.
- [x] Verify descriptor/certificate signatures, expiry and introduction key bindings; authenticate both encryption layers.
- [x] Establish introductions and hs-ntor rendezvous with fresh keys/cookies, and install the AES-256/SHA3 service hop.
- [x] Route SOCKS5 and Go client onion requests without exit/DNS fallback, with bounded setup and cleanup.
- [x] Check upstream vectors, service-hop bulk transfer/SENDME, negative cases, fuzzing, and live public onion HTTP through the CLI.
- [x] Add scoped descriptor caching with expiry/revision enforcement and service circuit reuse.
- [ ] Add client authorization, proof-of-work solving and subdomains.
- [ ] Support introduction relays outside the current verified consensus and broaden private-network/differential testing.

The live CLI fetched Tor Project's public v3 onion website (HTTP 200). This is an
interoperability milestone with the same experimental privacy limits as the rest
of the client. See README.md for the runnable command and scope.

## 7. Browsing lifecycle — scoped reuse implemented

- [x] Coalesce parallel builds for compatible scopes and share streams over healthy circuits.
- [x] Keep untagged clients, different credentials, application IPs, listeners, destinations and IP families isolated.
- [x] Retire old/failed circuits for new streams while active streams drain; evict idle entries within explicit bounds.
- [x] Cache authenticated onion descriptors per scope and period, enforcing expiry and revision rollback/conflict rejection.
- [x] Test concurrent traffic, waiter/build cancellation, shutdown, 200-request reconnect workloads and cache limits.
- [x] Provide an opt-in public SOCKS reuse/rotation test, including parallel onion HTTP and the HTTPS Tor checker.

This pool is intentionally conservative and requires explicit tokens. It neither
infers browser sessions nor provides Tor Browser's privacy model. Live outcomes
and remaining limits are recorded in VALIDATION.md and README.md.

## Later parity work

ntor-v3 and newer relay cryptography, additional onion client features and service hosting, bridges and pluggable transports, advanced congestion control, RPC, and relay/directory-authority operation are separate milestones. The initial client stages do not claim feature parity with the full Arti workspace.
