# Veil 0.10 v3 onion client validation

Run on 2026-09-20, macOS arm64, Go 1.27.1.

- Full `go test -race -cover ./... -timeout=120s`: passed.
- `go vet ./...`: passed; binary rebuilt as `0.10.0-dev`.
- Gosec 2.29.0: **43 production files, zero findings, zero loading errors**.
  Suppression-disabled audit: exactly 18 documented protocol exceptions.
- Onion package coverage: 81.6%; overall client orchestration coverage is lower
  (37.4%) because live public-network paths run outside the unit-test process.
- Tor/Arti vectors verify v3 blinding/subcredential, descriptor authentication
  and decryption, INTRODUCE1 ciphertext prefix, and hs-ntor reply/session keys.
- An independent cipher peer completes **2.25 MiB** through the service hop,
  exercising AES-256/SHA3 and both SENDME credit windows with 20-byte tags.
  Tests verify destination binding, port-only BEGIN, padded rendezvous replies,
  rejection of forged/unsolicited/wrong-hop replies, invalid descriptors and
  duplicate introduction identity pins, resource cleanup and no exit fallback.
- Directory tests cover noon/midnight SRV selection, disaster SRVs, expired
  consensus rejection, HSDir eligibility, and internal path exclusions.
- Five-second fuzz smoke runs: descriptor parser **2,416 executions**;
  descriptor item/link parsers **161,039 executions**. Both passed.

## Live public-network check

The compiled Go CLI ran with `proxy -public -state ./state-public -listen
127.0.0.1:19050`, preserving the existing private cache and persistent guards.
After `socks5_ready`, curl used `--noproxy '' --socks5-hostname 127.0.0.1:19050`:

- Tor Project's published v3 onion `/index.html`: **HTTP 200**, **23,597 body
  bytes**, with page title `Tor Project | Anonymity Online`.
- `https://check.torproject.org/api/ip`: **HTTPS 200**, `IsTor: true`, with normal
  TLS certificate verification enabled.

This exercised consensus HSDir selection, three-hop descriptor fetch, signature
and two-layer decryption checks, encrypted introduction, authenticated rendezvous,
service-hop streams and SOCKS relay. No C Tor/Arti process ran on the client.
The library-level native onion probe separately received HTTP 200. The temporary
SOCKS process was stopped after the checks; persistent state was retained.

Tests do not establish client-authorization or PoW compatibility, sustained
service availability, traffic fingerprint parity, or production anonymity.
README.md documents supported services and the command to reproduce the test.

---

# Veil 0.9 reliability validation

Run on 2026-09-20, macOS arm64, Go 1.27.1.

- Full `go test -race -cover ./... -timeout=120s`: passed. Client coverage 84.1%.
- `go vet ./...`: passed; binary rebuilt as `0.9.0-dev`.
- Gosec 2.29.0: **37 production files, zero findings, zero loading errors**;
  the same 16 reviewed protocol annotations, with no new suppressions.
- Production binary cross-compiles for Linux, FreeBSD, OpenBSD, NetBSD,
  DragonFly BSD and Windows (amd64). Directory locking is enabled on macOS and
  those Unix targets; Windows and other unsupported targets fail closed for
  stateful commands. Runtime lock tests were performed on macOS only.

## State ownership

Tests exercise competing opens, path aliases, independent directories, concurrent
and repeated Close, unsafe paths, and acquisition after forcibly killing a
separate owner process. All four stateful CLI commands reject an existing owner
before opening state, and startup failures release the lock. The lock is held on
the directory inode; no PID/lock file is created, removed or replaced.

A real second `veil proxy -public` process on a different SOCKS port exited with
`state directory is already in use by another Veil owner` while the first proxy
remained usable. Library consumers must explicitly hold `directory.LockState`
across their cache, guard store, managers and circuits. These are advisory locks
for cooperating writers on local filesystems; callers must not replace or remove
an active state directory.

## Bounded build retries

Deterministic tests inject transient transport failures and confirm recovery
within the attempt count, randomized-backoff bounds, per-attempt context cleanup,
retained concurrency slots, fresh snapshot lookup, total connection deadline,
shutdown cancellation, and established connections surviving setup deadlines.
They reject retries for protocol/authentication/directory/state failures, unknown
errors and joined failures containing a terminal error. No BEGIN/stream-open
failure is retried, and application bytes are never replayed by this mechanism.

An authenticated relay fixture fails an EXTEND2 with CONNECTFAILED, then succeeds
on a fresh build with the same persistent GuardStore. The reachable guard remains
selected and the saved sample is retained. The client adds no exclusion list or
reachability reset, and a path-selection failure terminates the retry loop.

The rebuilt production proxy started with existing public state and completed
HTTPS through `https://check.torproject.org/api/ip`, which returned
**`"IsTor":true`**. Live public success validates compatibility; injected failures
exercise retries deterministically without disrupting public relays. Circuit
pooling, rotation, stream retry policy, padding and production privacy review
remain outstanding.

---

# Veil 0.8 public-network validation

Run on 2026-09-20, macOS arm64, Go 1.27.1.

## Public HTTPS through the production CLI

Built `bin/veil` and ran:

```sh
./bin/veil proxy -public -state ./state-public -listen 127.0.0.1:19050
curl --fail --silent --show-error --max-time 90 --noproxy '' \
  --socks5-hostname 127.0.0.1:19050 https://check.torproject.org/api/ip
```

The cold start downloaded and verified the current public authority certificates,
microdescriptor consensus and complete relay catalog over native Tor directory
circuits. It published `socks5_ready`; the HTTPS checker returned
**`"IsTor":true`**. No C Tor/Arti process supplied client transport, and no private
test harness or explicit test hops were used. Destination DNS was sent through
SOCKS to the exit; curl's ordinary HTTPS certificate verification stayed enabled.

After Ctrl-C and a restart with the same state directory, the production CLI
became ready from its saved verified cache and guards. A fresh SOCKS connection
to **`https://example.com/` returned HTTP 200 and 559 bytes**. The Tor checker
also returned `"IsTor":true` after restart. Test proxy processes were stopped
cleanly; private cache and guard state were retained for the next user run. The earlier request
to that site was interrupted by the deliberate proxy shutdown and is not counted
as a successful transfer.

Public bootstrap exposed a real compatibility issue: the complete catalog
exceeded the former 32 MiB limit. The new bound is 64 MiB, with unchanged 64 KiB
per-descriptor and 4 MiB per-download bounds. Authority majority, digest, validity,
family and subnet checks remain mandatory. A regression fixture above 32 MiB now
passes full catalog assembly; an oversized catalog and oversized download fail.

## Automated checks

- Full `go test -race -cover ./... -timeout=120s`: passed across all packages.
- `go vet ./...`: passed.
- Gosec 2.29.0 default scan: **34 production files, zero findings, zero loading errors**.
- Suppression-disabled audit: exactly **16** reviewed protocol exceptions,
  including two CREATE_FAST SHA-1 KDF annotations documented in [SECURITY.md](SECURITY.md).
- CREATE_FAST matches Tor's published key vector; corrupt key confirmation,
  incorrect lengths and wrong reply commands are rejected. Channel framing and
  bundled pin validation have regression coverage.
- CLI flag tests reject missing state, conflicting `-public`/`-config`, invalid
  deadlines and unsafe listeners. Version: **0.8.0-dev**.

These checks establish public HTTPS interoperability, not traffic fingerprint
parity or production anonymity. Browser UI behavior, sustained browsing loads,
automatic circuit retries, padding and independent security/privacy review remain
outside this validation. The browser settings in README are a manual test recipe.

---

# Veil 0.7 SOCKS5 validation

Run on 2026-09-20, macOS arm64, Go 1.27.1, C Tor 0.4.9.12.

## Automated checks

- `go vet ./...`: passed.
- Full `go test -race -cover ./... -timeout=60s`: passed. New `socks5` package coverage **84.8%**, `client` **78.6%**, CLI **77.7%**.
- `gosec ./...`: **zero findings**, zero loading errors across **32 production files**. The 14 existing documented exceptions are unchanged; no new suppressions.
- Five-second `FuzzRequest` run: passed, **15,321 executions**.
- Binary version and `veil proxy -h`: passed; **0.7.0-dev**.

Tests cover SOCKS5 negotiation with and without username/password tokens,
CONNECT hostname/IPv4/IPv6 framing, pipelined application bytes, unsupported
methods/commands, malformed inputs, failure replies without fallback, connection
caps, handshake/connect/idle/lifetime limits, cancellation and joined cleanup.
Client tests verify one circuit per connection, bounded build slots, cleanup on
build/stream failure, and establishment-context cancellation not closing an
already established connection. Proxy lifecycle tests cover startup timeout,
directory verification failure before and after readiness, output failure, and
clean shutdown of pending SOCKS connections and the directory manager.

## User-facing local demo

`GOCACHE=/private/tmp/go-arti-cache make proxy-check` passed. The launcher built
the real Veil CLI and a race-enabled private-hop test harness, created a temporary
three-peer Tor network and verified directory, and served SOCKS5 using the
production Go server and native circuit/stream stack. An actual `curl` process
requested `http://veil.test:<fixture-port>/` with `--socks5-hostname`; the private
exit DNS fixture observed `veil.test`. A second request used SOCKS tokens and
verified an exact **2 MiB** HTTP body. The successful check shut down all peer
processes and removed temporary configuration, keys, and state.

`make proxy-demo` uses the same setup, prints a working curl command, and keeps
running for manual requests until Ctrl-C. It requires no hand-written
`bootstrap.json`. The exit permits only one port on 127.0.0.1; there are no public
authorities/fallbacks or internet destinations. C Tor implements the test relays,
not Veil's client or SOCKS frontend.

The local demo uses an explicit-hop hook present only in the compiled Go test
binary. It does not claim that localhost paths satisfy the production CLI's
verified directory/subnet selector. `veil proxy` uses the actual directory
manager and per-request production builder; those components are covered by
signed-directory, lifecycle, and circuit tests. Public-network setup and
anonymity are not validated. UDP, GSSAPI, onion services, circuit reuse/retries,
production traffic padding, and TCP half-close are outside this milestone.

SOCKS framing references: [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)
and [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929). Veil implements the
CONNECT subset and does not claim every mandatory/optional method in the RFCs.

---

# Veil 0.6 TCP stream validation (historical)

Run on 2026-09-20, macOS arm64, Go 1.27.1.

## Automated checks

- `go vet ./...`: passed.
- `go test -race -cover ./... -timeout=60s`: all packages passed; circuit coverage **89.0%**.
- `gosec ./...` with all default rules: **zero findings**, zero loading errors, 29 production files and the same 14 reviewed annotations in [SECURITY.md](SECURITY.md). No new suppressions.
- Five-second `FuzzStreamControl` smoke run: passed, **2,641 executions**.
- Production binary reports **0.6.0-dev**; SOCKS remains explicitly unsupported.

The independent encrypted peer fixture checks four concurrent 1 MiB transfers,
ordered authenticated SENDME tags, stream acknowledgements, a nondefault circuit
window, and unpredictable padding in every 100-DATA batch. Negative cases cover
forged/replayed/wrong-hop acknowledgements, unknown streams, duplicate CONNECTED,
receive-window overflow, DNS-name validation, and mixing raw/managed APIs.
Lifecycle tests cover changing read/write deadlines, a writer blocked on credit,
a wire timeout, channel failure, canceled BEGIN with late replies, EOF and exit
errors, unread ended streams counting toward the 32-stream resource bound, and
stream-ID exhaustion without reuse. IPv6 BEGIN flags are checked offline.

## Live C Tor interoperability

Passed against **C Tor 0.4.9.12**, using a race-enabled Go test binary:

```sh
make build
go test -c -race -o bin/circuit-test ./circuit
python3 scripts/check_local_directory.py \
  --tor /absolute/path/to/tor \
  --gencert /absolute/path/to/tor-gencert \
  --stream-test bin/circuit-test
```

The script bootstrapped a fresh signed directory, then the Go client established
three authenticated ntor hops. Four simultaneous streams each wrote and read
**2 MiB** through the exit, exercising repeated circuit and stream SENDMEs in both
directions. A private UDP DNS fixture saw the exit's queries for `veil.test`,
`missing.test`, and `stall.test`. The client forwarded the hostname in BEGIN;
it made no local destination DNS lookup. The test verified EOF after a buffered
tail, DNS failure (END reason 2), exit-policy rejection (reason 4), cancellation
of a pending DNS request, read deadlines, continued circuit usability after
stream errors, and circuit-close propagation to a blocked reader.

The observed consensus was valid after `2026-09-20T09:59:40Z`. All peers and
fixtures listened on localhost. Only the authority's exit was enabled, and its
policy permitted exactly the echo fixture's port on `127.0.0.1`; everything else
was rejected. There were no SOCKS listeners, public authorities, or public
fallbacks. The script stopped its processes and removed keys/state afterward.
C Tor remains an optional test peer, not a Veil runtime dependency.

The live test uses private explicit-hop hooks because localhost relays cannot
pass production subnet separation. Signed-document tests separately cover
production selection. Live IPv6, circuit pooling/isolation/expiry, retry policy,
congestion control, link padding, public-network operation, traffic fingerprint
parity, and anonymity are not claimed. Tor's implemented END closes both stream
directions; this milestone does not claim TCP half-close support.

---

# Veil 0.5 three-hop circuit validation (historical)

Run on 2026-09-20, macOS arm64, Go 1.27.1.

## Automated checks

- `go vet ./...`: passed.
- `go test -race -coverprofile=... ./... -timeout=60s`: passed.
- Overall statement coverage: **82.9%**; new circuit package **88.0%**, directory **78.0%**, CLI **74.8%**. External C Tor processes are not included in coverage.
- `go build -trimpath -o bin/veil ./cmd/veil`, version, and `circuit-check -h`: passed; **0.5.0-dev**.
- Three repeated runs of build, concurrent traffic, cancellation/lifetime, and verified-selection tests: passed.

The circuit fixture implements the server side of ntor and relay encryption
independently from the production client, using standard-library ECDH, HKDF,
AES-CTR, and SHA-1. It checks both extension identity pins, network-byte-order
addresses, CREATE2/EXTEND2 sequencing, all eight RELAY_EARLY cells, persistent
crypto state across extension, mixed-hop traffic, bidirectional exit payloads,
and concurrent outgoing message order. Freshly signed authority/consensus/
microdescriptor documents exercise the verified path and persistent guard
confirmation together; failed exit selection releases tracked attempts.

Negative cases cover wrong circuit IDs, bad ntor replies at each hop, invalid
ciphertext, wrong-hop or malformed EXTENDED2, unsolicited extension messages,
stream messages from earlier hops, inbound RELAY_EARLY, DESTROY/TRUNCATED reason
handling, and bounded padding/DROP/unknown-command floods. Tests exercise stalled
handshakes at each hop, caller cancellation without guard penalty, build timeouts,
unusable/waiting guards, persistence failure, directory expiry during build,
blocked writes/reads, full incoming queues, and concurrent idempotent close.

Existing protocol, directory, crypto, channel, and CLI tests also passed. Parser
fuzz targets were not rerun for this circuit milestone.

## Live C Tor interoperability

Passed against **C Tor 0.4.9.12** with fresh temporary local keys and three peers:

```sh
make build
go test -c -o bin/circuit-test ./circuit
python3 scripts/check_local_directory.py \
  --tor /absolute/path/to/tor \
  --gencert /absolute/path/to/tor-gencert \
  --circuit-test bin/circuit-test
```

The Go builder authenticated a real guard channel, completed CREATE2 and two
EXTEND2 handshakes, and exchanged a small BEGIN_DIR HTTP request/response through
all three hops. The response contained **2,443 bytes**, including HTTP framing,
and ended normally. A wrong middle-hop Ed25519 identity and wrong last-hop ntor
key were rejected without marking the authenticated guard unreachable. C Tor may
return an unauthenticatable ntor reply for the latter; the test accepts either
that authentication failure or a remote circuit teardown, never a timeout.
The directory bootstrap used a consensus valid after `2026-09-20T09:09:40Z`.

All three peers remained non-exits with no SOCKS listener or public authorities/
fallbacks. The script stopped its processes and removed temporary state. The
compiled **test-only** entry point uses explicit localhost hops so wire behavior
can be tested without weakening production subnet/exit restrictions. Production
selection uses separate signed-document tests with distinct subnets. C Tor is
an optional test peer, not a Veil runtime dependency.

## Scope

This milestone implements fixed three-hop construction and low-level relay
transport. It does not implement application stream state machines, stream-ID
ownership, SENDME windows/validation for these circuits, circuit pooling,
application retries, SOCKS, path-bias accounting, production padding, or complete
public-network privacy. The small live directory exchange does not establish
large-transfer or concurrent-stream compatibility. These remain later steps.

---

# Veil 0.4 directory and guard lifecycle validation

Run on 2026-09-20, macOS arm64, Go 1.27.1.

## Automated checks

- `go vet ./...`: passed.
- `go test -race -coverprofile=... ./... -timeout=60s`: passed.
- Overall statement coverage: **82.6%**; directory **77.8%**, CLI **77.0%**. Optional external-process Tor tests are not included in these coverage figures.
- Build and `veil version` / `veil directory-watch -h`: passed, version **0.4.0-dev**.
- Five repeated runs of the guard/manager/timing tests: passed. These exercise randomized choices and dates; this repetition specifically checks those new behaviors.

New tests cover:

- Bounded weighted guard sampling, primary preference, confirmation persistence, and restart.
- Version-1 guard-state migration without replacing the saved identity or inventing a confirmation.
- Separate directory versus connection failure handling, cancellation without penalty, retry bounds, restrictions without resampling, and sample retention under repeated failure.
- Non-primary waiting, retry of primary guards after an outage, idle timeout, confirmation expiry, and unlisted guard removal.
- Persistence failure stopping selection and malformed guard-state rejection.
- Randomized directory refresh bounds, bounded request retries, live snapshot retention during outages, refusal of expired snapshots, recovery through saved guards using a recently expired directory, and clock rollback.
- Fail-closed signature rejection without repeated retries, unchanged microdescriptor reuse, and per-request digest binding.
- Reusable-session cancellation during dialing/queueing, concurrent close, and bounded filtering of late cells for retired circuits.

The existing cryptographic, document, flow-control, channel, and CLI tests also passed. Existing parser fuzz targets were not rerun for this lifecycle change.

## Live C Tor checks

Both checks passed against **C Tor 0.4.9.12** in temporary localhost networks.

```sh
go build -o bin/directory-probe scripts/directory_probe.go
python3 scripts/check_local_tor.py \
  --tor /absolute/path/to/tor \
  --veil bin/veil --directory-probe bin/directory-probe

python3 scripts/check_local_directory.py \
  --tor /absolute/path/to/tor \
  --gencert /absolute/path/to/tor-gencert \
  --veil bin/veil --watch
```

The first check authenticated link 5/TLS 1.3 and completed two consecutive BEGIN_DIR downloads through a reusable session, each on a fresh circuit. It rejected incorrect RSA, Ed25519, and ntor keys. The observed descriptor length was 2,233 bytes.

The second check bootstrapped a complete three-relay directory, then ran `directory-watch` until it observed a newer consensus. It confirmed a directory guard, verified that refresh did not replace the sampled identities, restarted the watcher, and checked immediate restoration of the live cached directory and unchanged persistent guard state. Its initial consensus was valid after `2026-09-20T08:32:20Z`, fresh until `08:32:40Z`, and valid until `08:33:20Z`.

All test processes were stopped and temporary keys/configurations/caches removed. The test peers used only localhost authorities, no public fallbacks, no SOCKS listener, and no exit service. C Tor remains an optional test peer, not a Veil runtime dependency.

## Scope

This validates the default unrestricted guard context and the directory lifecycle. It does not validate bridges or custom reachability/entry filters, application-circuit path-bias accounting, cross-process state ownership, long-offline cache recovery beyond 24 hours, public-network privacy, or three-hop application traffic. These boundaries are documented in README.md and ROADMAP.md. The next main milestone is native application circuits and streams.

---

# Stage 3 directory bootstrap validation (historical)

Run on 2026-09-19, macOS arm64, Go 1.27.1.

## Automated checks

- `go vet ./...`: passed.
- `go test -race -coverprofile=... ./... -timeout=60s`: passed.
- Overall statement coverage: **84.1%**. Directory package: **75.9%**; CLI: **82.6%**. Optional external C Tor runs are not included in these coverage figures.
- Production binary builds and reports `0.3.0-dev`.
- Compiled `directory-check` validates the recorded Arti fixture at its test timestamp: four authority signatures and seven relays.
- `GOMAXPROCS=2 go test ./directory -run='^$' -fuzz='^FuzzDirectoryDocuments$' -fuzztime=10s`: passed, **92,943 executions**. This is a bounded smoke run, not exhaustive validation.
- The six previous protocol/crypto fuzz targets remain in `make fuzz`; their earlier results are retained below. Only the new directory target was fuzzed again for this stage.

Directory tests reject changed signed bytes, duplicate signers masquerading as a quorum, insufficient configured-root majority, unknown signature algorithms, forged authority certificates/cross-certificates, unsupported required protocols, missing/mismatched/duplicate microdescriptors, invalid policy ranges, cache corruption, rollback/conflicts, and expired documents. They check guard persistence, refusal to rotate an unavailable guard, weighted selection, mutual families/shared family IDs, IPv4/IPv6 subnets, and exit-port summaries.

The single-stream transport test transfers 1,200 DATA cells (597,600 bytes), checks all 12 authenticated circuit SENDMEs and 24 stream SENDMEs, and rejects wrong circuit/stream IDs, modified ciphertext, unexpected control messages, and cell floods. HTTP tests cover size limits, truncation, malformed headers, redirects, and unexpected compression. No direct HTTP fallback exists.

## Live C Tor interoperability

The isolated relay check passed against C Tor **0.4.9.12**:

```sh
go build -o bin/directory-probe scripts/directory_probe.go
python3 scripts/check_local_tor.py \
  --tor /absolute/path/to/tor \
  --veil bin/veil \
  --directory-probe bin/directory-probe
```

It authenticated link 5/TLS 1.3, completed a native CREATE2 ntor circuit and BEGIN_DIR stream, downloaded the relay's **2,237-byte** descriptor, and rejected wrong RSA, Ed25519, and ntor keys. This checks transport interoperability; the probe does not claim to verify full router-descriptor signatures.

A complete bootstrap also passed against a fresh private network with one authority and two additional non-exit relays:

```sh
python3 scripts/check_local_directory.py \
  --tor /absolute/path/to/tor \
  --gencert /absolute/path/to/tor-gencert \
  --veil bin/veil
```

The real Go CLI downloaded authority certificates, the current microdescriptor consensus, and all three microdescriptors through native BEGIN_DIR circuits. It verified the single configured authority's signature and all descriptor digests and atomically wrote a mode-0600 cache in private state storage. The observed consensus was valid after `2026-09-19T15:46:00Z`, fresh until `15:46:20Z`, and valid until `15:47:00Z`. The four-authority recorded fixture separately tests multiple signatures and quorum rejection.

Both scripts use only localhost authorities and fallback configuration, no SOCKS or exit service, and temporary private keys/configuration. They stop their Tor processes and delete their temporary state. Tor and tor-gencert remain optional test executables, not Go runtime dependencies.

The live network proves directory bootstrap. It does not validate three-hop application circuits, stream multiplexing, production guard rotation, public-network operation, traffic fingerprint parity, or anonymity. Path selection intentionally retains subnet exclusions, so the localhost-only test network is not used to claim three-hop path compatibility. Guard lifecycle, retries/refresh, and privacy scheduling remain in ROADMAP.md.

---

# Stage 2 validation (historical)

Run on 2026-09-19, macOS arm64, Go 1.27.1.

## Automated Go checks

- `go vet ./...`: passed.
- `go test -race -coverprofile=... ./... -timeout=60s`: passed.
- Overall statement coverage: **94.2%**.
- Package coverage: cell 97.3%, channel 90.4%, cmd/veil 90.6%, ntor 92.9%, relaycrypto 96.2%, torcert 96.1%.
- `make build`: passed. The executable reports `0.2.0-dev`.
- The compiled CLI integration test authenticated a local TLS fixture and verified its JSON output and connection teardown.

Six bounded fuzz runs (`GOMAXPROCS=2 make fuzz`) passed without crashes or failing inputs:

| Target | Executions |
| --- | ---: |
| FuzzChannel | 1,035,229 |
| FuzzVersions | 1,050,171 |
| FuzzBodies | 914,414 |
| FuzzFinish | 155,093 |
| FuzzChannelHandshakeBodies | 1,145,184 |
| FuzzCertificateChain | 14,429 |

Each run used a 10-second fuzz budget. These are bounded smoke runs, not exhaustive validation or a security audit.

## Independent C Tor interoperability

Built Tor 0.4.9.12 from the official release into a temporary directory using the installed OpenSSL and libevent libraries. The tarball checksum matched the published SHA-256; see [UPSTREAM.md](UPSTREAM.md). Nothing was installed globally and Tor is not a runtime dependency of the Go program.

Ran:

```sh
python3 scripts/check_local_tor.py \
  --tor /private/tmp/go-arti-tor-build/tor-0.4.9.12/src/app/tor \
  --veil bin/veil
```

The script generated a private relay configuration and fresh keys, read the relay's public identity pins from its data directory, and invoked the real Go executable against its localhost ORPort. The temporary relay disabled SOCKS, exit service, descriptor publication, default fallback directories, and public authorities. Its only configured authority and DNS resolver were localhost.

Results:

- Authenticated both expected relay identities and the TLS certificate binding.
- Negotiated **Tor link protocol 5** and **TLS 1.3** (`0x0304`).
- Finished the anonymous-client NETINFO handshake.
- Rejected a modified RSA identity pin.
- Rejected a modified Ed25519 identity pin.
- Closed the test connections and stopped the temporary relay; deleted the temporary relay keys.

This validates channel interoperability with one C Tor release. It does not validate directory bootstrap, circuit construction, streams, public-network operation, traffic fingerprint indistinguishability, or anonymity. Those remain later-stage work.
