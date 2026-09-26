# Veil 0.13 native onion hosting validation

## Long-offline directory recovery — 2026-09-26

Authenticated caches older than the 24-hour directory-guard recovery window now
trigger a download through configured pinned bootstrap relays. Saved guards and
rollback protection remain intact; expired snapshots never authorize application
traffic, and refresh returns to sampled guards after a live directory is stored.

Validation passed:

- `go test -race -timeout 2m ./...` and `go vet ./...`.
- Recovery at the exact 24-hour cutoff and after six days, through `Refresh`,
  restarted `Run`, and an already-running manager; cached descriptors are reused
  and the saved guard sample is preserved.
- Rejection of altered signatures, rollback/conflicting guard state, corrupt
  guard state, backward clocks, and expired downloaded consensuses, without
  replacing the cache or guard state.
- A public-network proxy startup using a temporary copy of the local cache that
  expired on September 20 at 23:00 UTC reached `socks5_ready` on September 26 at
  07:28:56 UTC. One bootstrap relay timed out; the next attempt succeeded. The
  proxy was then stopped and the temporary state removed. No application streams
  were opened, and the original state directory was unchanged. Android packaging
  was not tested in this repository.

## Bounded control-cell batching — 2026-09-21

The managed stream writer now groups already-queued SENDME/END controls from
one circuit, up to 16 fixed cells, with no batching timer. The send gate covers
filtering retired-stream ACKs, ordered encryption and whole-batch transport
completion. Channel/lease APIs validate and copy every cell before queueing;
the fixed-cell batch bound limits each request to 8,224 plaintext bytes. Standard
Go TLS still chooses record boundaries. DATA writes and padding policy are
unchanged.

Validation passed on Go 1.27.1:

- Full `go test -race ./...`, ordinary and `veiltraffic`-tagged `go vet ./...`.
- Default gosec: **68 production files, zero findings, 19 annotations**.
- Seven Python metadata/measurement tests.
- New transport fixtures verify all-or-nothing validation before queueing,
  one write for a prepared batch, no early success after only its first cell,
  partial-write failure and rejection of batches containing another lease's ID.
- A canceled lease whose batch has already partially written lets the complete
  batch finish, then sends DESTROY; a sibling remains usable on the same channel.
- Independent relay cipher fixtures verify ordered decryption/digests across
  batches, the 16-control drain bound, retired-stream ACK filtering, immediate
  single-control flushing, harmless pre-encryption cancellation and circuit
  failure after an indeterminate encrypted batch write.

Three repeated Veil download trials now produce **118–122 outbound TLS records**
(median 120), versus 128 in every earlier trial: a **6.25% median reduction**.
Each trial includes 6–10 records with 1,045-byte payloads; the remaining records
have 531-byte payloads. Previously all outbound download records were 531 bytes.
The [repeated matched comparison](reports/workload_batch_2026-09-21.md) records
the full effect against the previous baseline and fresh C Tor samples.
All 36 measured requests passed byte-for-byte validation without measured-phase
retries. One initial Veil warmup was retried. Fresh C Tor trials produced 106–115
outbound download records (median 108); Veil's median download duration remained
about 158 ms locally. Every saved metric was recomputed from the archived traces.
Batching is a transport scheduling change, not evidence of anonymity or a full
implementation of C Tor's output scheduler. The original measurements below
remain a historical baseline.

## Matched application traffic comparison — 2026-09-21

Three pairs of fresh Veil and C Tor clients completed identical workloads against
one C Tor onion service on five private loopback relays. Each trial used the same
guard and SOCKS isolation scope, active Vanguards-Lite, warmup plus five seconds
of settling, one 4 KiB request, four 4 KiB requests with 250 ms gaps, a 2 MiB
download and sixty seconds of application inactivity. All **36 measured requests**
passed exact response validation without retries. The first Veil warmup failed
once before succeeding; preparation is excluded from matched metrics, and the
different circuit age is a possible maintenance-traffic confounder.

Builds: Go 1.27.1 on macOS arm64, without race instrumentation for measurement;
C Tor 0.4.9.12 with OpenSSL 3.6.4. Both clients traverse the same kind of local
SOCKS metadata tap. Veil's route exists only under the `veiltraffic` build tag
and accepts only loopback targets/taps; normal TLS and Tor authentication remain
unchanged. No production option enables this route.

| Observed metric | Veil | C Tor |
| --- | --- | --- |
| Outbound TLS payload lengths during 2 MiB download | 531 bytes only | 531, 1,045 and 1,559 bytes |
| Outbound records during download, per trial | 128 | 95–110 |
| Inbound TLS bytes during download, median | 2,195,040 | 2,195,128 |
| Outbound records during 60-second inactivity | 8–10 | 18–19 |
| Guard channels still open at end | 1 in all trials | 1 in all trials |
| New guard connections during measured phases | 0 | 0 |

ClientHello cipher ordering, extensions, groups, key shares and signature
algorithms remain different. Inactivity records include encrypted protocol
maintenance and cannot be classified as pure padding. Record completion times
are observed at the proxy; these are not IP packets or Tor cell counts. Local
buffering and the observer affect timing. Open channels are right-censored;
their full lifetime, long idle periods and failure recovery were not measured.
Three local pairs do not establish anonymity or statistical indistinguishability.

The [readable comparison](reports/workload_2026-09-21.md),
[summary JSON](reports/workload_2026-09-21.json) and
[compressed metadata traces](reports/workload_2026-09-21.traces.json.gz) preserve
the method, build hash, per-trial data and limitations. Every phase metric was
recomputed from the archive and checked against the summary; application byte
counts match across implementations. The observer saves no record bodies,
onion names, SNI values, keys or application payloads.

Measurement-tool checks passed: seven Python tests (fragmentation, redaction,
record bounds, phase boundaries and guard filtering included), normal channel
tests, channel race tests with `veiltraffic`, normal and tagged `go vet ./...`.
Default gosec reports **67 production files, zero findings, 19 annotations**.
Reproduce with `scripts/compare_workload.py` as documented in README. Earlier
validation sections below record the state at their respective milestones.

## Shared guard channels and live policy — 2026-09-21

Clients and onion hosts now share application guard TLS transports within each
owner. Bootstrap links remain separate. Circuit isolation and the prior
ten-minute introduction retention remain intact; idle transports are retained
and padded under live signed consensus policy.

Validation passed on Go 1.27.1:

- Full `go test -race ./...` and `go vet ./...`.
- Default gosec: **66 production files, zero findings, 19 unchanged annotations**.
- Multiplexing fixtures verify independent queues/IDs, closing one lease while
  another remains usable, reuse after idle, changed identity pins, unknown IDs,
  physical failure propagation, resource caps, coalesced handshakes, canceled
  waiters and pool shutdown joining its leases.
- A slow circuit overflowing its 1,024-cell queue leaves a sibling usable.
  A separate case discards a complete 1,000-cell window for a retired circuit
  without closing the shared channel. A partially written cell is completed in
  order before DESTROY after lease cancellation, then a sibling successfully
  writes over the same transport.
- Live policy fixtures verify disable/resume/expiry, sticky usage activation,
  bounded coalesced updates and changed idle-retention settings. Directory
  tests verify `nf_conntimeout_clients` defaults and 60–86,400-second clamping.
- Private C Tor 0.4.9.12 suite under the race detector: **48.04 seconds** after
  bootstrap (forwarding **39.02 s**, listener **9.02 s**). Test-only ownership
  inspection observed one client guard channel with one retained introduction,
  and one host guard channel with four live circuit leases, in both scenarios.
  Native 2,340,000-byte downloads, concurrent C Tor downloads, actual circuit
  padding, introduction rotation/failure, cached/fresh descriptors and lost
  publication replies passed. One initial service request timed out during
  publication/bootstrap and the existing bounded setup retry succeeded.

Production traffic shaping and independent review remain open. Idle expiry uses
the consensus duration directly; this is not C Tor's complete predicted-circuit
and randomized lifetime policy. Real thirty-minute idle periods and byte/timing
distributions have not been measured in the private-network run; shortened
unit-test timers cover expiry. Earlier sections below are historical milestones.

## Client onion circuit padding — 2026-09-21

Added authenticated setup negotiation with the second physical relay for client
introduction and rendezvous circuits. Introduction circuits are retained for ten
minutes after the exchange, separately bounded by `MaxCircuits`, and survive
closure of the rendezvous stream. This does not alter service introduction-point
rotation or established stream lifetimes.

Validation:

- Independent relay-crypto fixtures check exact negotiation bytes, three/four-hop
  targets, introduction ACK before padding ACK, nine cover cells followed by STOP,
  and rendezvous cover traffic before acknowledgment.
- Negative fixtures cover malformed/unsolicited controls, wrong hops/streams,
  version/machine/response errors, duplicate ACKs, excess cover cells and cells
  after STOP/rejection. Counter mismatches are ignored; legitimate rejection and
  either machine's STOP are accepted.
- Policy tests check authenticated capability, disabled/reduced/expired policy,
  signed bounds, both global-percentage parameter spellings, persistent shared
  accounting, budget exhaustion, busy writers, cancellation and one-cell limits.
- Retention tests check setup cancellation after transfer of ownership, capacity
  backpressure without eviction, expiry, peer failure, idempotent release and
  dialer shutdown joining retained work.
- Full `go test -race ./...`, `go vet ./...` and default gosec pass: **64 production
  files, zero findings, 19 unchanged annotations**. A preexisting post-handshake
  directory-expiry test initially timed out at 30 ms under concurrent race/live
  test load. Its non-timeout cases now allow one second for cryptographic setup;
  the assertions and separate timeout tests remain intact.
- Private C Tor 0.4.9.12 suite under the race detector: **36.57 seconds** after
  bootstrap (forwarding **28.28 s**, listener **8.29 s**). Both scenarios observed
  rendezvous START acknowledgment, one outgoing and one incoming cover cell.
  Introductions received respectively **7 and 9** cover cells, acknowledged STOP
  and remained owned after the HTTP stream closed. Native 2,340,000-byte downloads,
  concurrent C Tor clients, introduction rotation/failure, cached/fresh descriptors
  and lost publication replies all passed.

The private C Tor integration additionally asserts actual padding acknowledgment,
cover-cell counts and retained lifetime after HTTP close, rather than inferring
padding success from a successful download. It uses test-only inspection helpers
absent from production builds. Full ten-minute retention is unit-tested with a
shortened timer; the live suite checks continued ownership after stream close.

Traffic classification, inter-arrival timing, application volume, shared channel
retention and an independent privacy/security review remain unvalidated. The
following sections are historical results from earlier steps.

## Repeated TLS measurement and configuration correction — 2026-09-21

Two independent batches each captured eight Veil and eight C Tor connections to
a temporary local relay. Builds: Veil with Go 1.27.1, C Tor 0.4.9.12 linked with
OpenSSL 3.6.4, macOS arm64. The parser now records SNI presence/length/shape and
key-share group/length metadata while omitting the values. Report schema 2
separates stable-in-sample fields from variable fields and length histograms.

| First outbound TLS record payload | Before | After |
| --- | --- | --- |
| Veil | 264 bytes (8/8) | 1,510–1,526 bytes |
| C Tor reference | 1,539–1,559 bytes | 1,541–1,560 bytes |

Before, SNI was absent and only X25519/P-256 were offered by Veil. After, every
sample uses a Tor-shaped fresh cover SNI and offers implemented hybrid groups.
SNI length varies in both clients. Stable differences remain in cipher suites,
extensions, signature algorithms, groups and key shares. These sample size ranges
still do not overlap. This is a configuration improvement and useful diagnostic
evidence, not successful traffic indistinguishability. The compact summary is
[channel/testdata/tls_comparison_2026-09-21.json](channel/testdata/tls_comparison_2026-09-21.json).
Generate complete traces with the README comparison command.

Validation passed:

- Full `go test -race ./...` and `go vet ./...` on Go 1.27.1.
- `go test ./channel` on Go 1.24.13, exercising the older-toolchain group list.
- Default gosec: **61 production files, zero findings, 19 unchanged annotations**.
- Four Python parser/summary tests: fragmentation, truncation and resource bounds,
  SNI/key-share metadata without values, and stable-versus-variable aggregation.
- Real TCP TLS fixtures restricted to TLS 1.2/P-256, TLS 1.3/X25519,
  TLS 1.3/P-256 (HelloRetryRequest) and TLS 1.3/X25519MLKEM768. TLS session
  resumption remains disabled and relay identity is checked independently of SNI.
- Live C Tor link-5/TLS-1.3 handshake, including rejection of wrong RSA/Ed25519 pins.
- Private native/C Tor onion suite under the race detector: **27.04 seconds**
  after bootstrap (forwarding **17.89 s**, listener **9.15 s**), including native
  client transfers of 2,340,000 bytes, concurrent C Tor downloads, padding,
  cached/fresh descriptors, lost upload replies, rotation and active-stream survival.

The initial P-256 retry test exposed a limitation of zero-buffer `net.Pipe`: both
TLS endpoints can block writing compatibility CCS before reading. The dedicated
profile test uses real loopback TCP and exercises the full public `channel.Dial`
path. Production authentication, TLS engine and minimum TLS version were not
weakened to make that test pass. Earlier sections below are historical results.

## Vanguards-Lite, guard-link padding and TLS comparison — 2026-09-21

Native onion construction now uses Vanguards-Lite: a shared, memory-only L2 set
(default four Fast/Stable relays), signed count/lifetime parameters and
endpoint-independent entry guards. Client rendezvous has three physical relays;
HSDir, introduction and service rendezvous have four. A separate virtual service
hop is installed once, after hs-ntor authentication. Unit tests verify sticky
membership across 100 endpoint changes, expiry/flag replacement, restart behavior,
no unrestricted fallback, allowed A-B-C-A paths, rejection of A-A/A-B-A before
network activity, and unchanged clearnet family/subnet restrictions.

Guard channels now send idle link padding with cryptographic max-of-two random
timeouts and verified consensus bounds. Tests cover START/STOP, deferred user
activation, no padding on directory-only bootstrap, outbound timer reset,
inbound traffic not suppressing padding, distribution/bounds and shutdown while
a padding write is blocked. Relay-originated padding negotiation is rejected.
The complete race suite, follow-up circuit/channel/directory regression tests,
`go vet ./...`, and gosec passed. Gosec reports **59 production files, zero
findings, zero loading errors and 19 unchanged annotations**.

The private C Tor 0.4.9.12 hosting harness uses the production Vanguards selector,
not explicit test hops. Its temporary authority assigns Stable flags, a single
entry guard and signed nonzero bandwidths; relay bandwidth history is seeded
only inside the temporary network because a single authority cannot provide
Tor's required three measured-bandwidth votes. Existing cached/fresh-descriptor,
lost upload acknowledgment, introduction failure, retirement and ongoing-stream
checks pass in forwarding and listener modes. An additional native Veil client
fetches and verifies **2,340,000 bytes** through native HSDir/introduction/
rendezvous construction in both modes. The final race-enabled test body passed
in **56.13 seconds** (forwarding **47.86 s**, listener **8.27 s**) after bootstrap.
Reproduce with `make service-check`.

The local TLS comparison command in README.md captured Veil's authenticated
channel check and a C Tor bridge client's connection to the same local relay.
The ClientHello structure **differs** in cipher suites, extension list/order,
supported groups, signature algorithms and SNI presence. The first outbound TLS
record payload measured **264 bytes** for Veil and **1,558 bytes** for this C Tor
build. The sample is stored in
[channel/testdata/traffic_fingerprint_2026-09-21.json](channel/testdata/traffic_fingerprint_2026-09-21.json).
The parser tests handle TCP/TLS fragmentation, truncation, bounds and omission of
randoms, names and session IDs. Run them with
`python3 -m unittest discover -s scripts -p 'test_traffic_fingerprint.py'`.

These are local interoperability and distinguisher measurements. Aggregate
record counts/timing have different post-handshake workloads and are not parity
metrics. Circuit setup padding, shared/retained channels, live consensus updates
for existing padding timers, full Vanguards, matched-workload traffic analysis
and independent review remain open. Older results below describe earlier code.

## Overlapping introduction generations — 2026-09-21

The private harness now runs two independent C Tor clients with separate
descriptor caches. Both forwarding and listener hosting passed under the race
detector, with this sequence:

- Receive the beginning of an HTTP response and keep that same stream open.
- Trigger introduction rotation and block all replacement descriptor uploads.
  Assert that the old introduction circuits remain open, then successfully open
  a new rendezvous from the original C Tor client using a new SOCKS isolation
  scope and the old descriptor.
- Release publication, but report every successful upload as a lost HSDir
  acknowledgment. Confirm that the host reports incomplete publication. The
  second C Tor client, which has never requested this onion address, discovers
  the uploaded replacement and successfully connects.
- Fail one replacement introduction circuit. Verify that another generation
  starts and that the second C Tor client can open another isolated connection.
- Advance retirement callbacks to simulate certificate expiry. Verify closure
  of the retained introduction circuits and successful completion of the
  original response, including **2,340,000 bytes** checked exactly, without curl
  retry or reconnection.
- Shut down cleanly, joining readers and rendezvous across retained generations.

The test body passed in **35.36 seconds** (forwarding **27.65 s**, listener
**7.70 s**) after private-network bootstrap. The existing HTTP, concurrent bulk
transfer and unmapped-port rejection checks also passed. Reproduce with
`make service-check`.

Offline regression tests cover shared replay detection and rate limiting across
generations, expiry/dead-reader pruning, preservation of unexpired history,
idempotent history cleanup and the signed certificate's absolute expiry for
late-fetched descriptors. `go test -race ./... -timeout=120s`, `go vet ./...`
and gosec passed; gosec reports **56 production files, zero issues**, and the
unchanged **19** protocol annotations.

Retention is bounded to four generations (12 introduction circuits); repeated
failures can postpone further replacement until capacity becomes available.
This is controlled private-network coverage, not long-running public-network
availability or anonymity validation. Padding, vanguards and independent review
remain open.

## Introduction rotation follow-up — 2026-09-21

The initial rotation fix made rendezvous circuits belong to the host rather than an introduction
generation. The private C Tor harness checks both TCP forwarding and the native
Go listener with the race detector enabled:

- Start an HTTP response and receive its first bytes through C Tor.
- Trigger the actual introduction rotation timer without waiting two hours.
- Keep the response open while the old introduction circuits close and three
  fresh introduction circuits are established.
- Close one of those new introduction circuits to force recovery; verify another
  replacement generation starts and the failed generation closes.
- Resume the original HTTP response and verify the remaining **2,340,000 bytes**
  exactly. Curl does not retry or reconnect the transfer.
- Shut down and join hosting workers, including rendezvous from retired
  generations. Existing HTTP, concurrent download and port-rejection checks pass.

The test body passed in **14.66 seconds** (forwarding **7.13 s**, listener
**7.52 s**) after private-network bootstrap. `go test -race ./... -timeout=120s`
and `go vet ./...` also passed. Reproduce with `make service-check`.

This verifies established-stream continuity during controlled local rotation and
failure. It does not verify uninterrupted discovery by new clients, overlapping
introduction generations, or long-running public-network availability. Circuit
lifetime limits still apply; padding, vanguards and anonymity review remain open.

## Initial hosting validation

Run on 2026-09-21, macOS arm64, Go 1.27.1, independent peer C Tor 0.4.9.12.

- `go test -race ./... -timeout=120s`: all packages passed.
- `go vet ./...`: passed.
- Gosec: **53 production files, zero findings, zero loading errors**, with
  **19** reviewed protocol annotations. Production binary rebuilt as **0.13.0-dev**.
- Descriptor tests verify blinded signing, certificates, encryption round trips,
  wrong subcredentials and tampering. Service hs-ntor agrees with client keys;
  mutated/truncated introductions fail authentication.
- State tests verify stable addresses and increasing revisions across reopen,
  private permissions, symlink rejection and refusal to silently replace a lost
  identity when its hostname still exists.
- Stream fixtures cover immediate incoming BEGIN, reversed service-hop crypto,
  multi-megabyte SENDME flow control, duplicate stream IDs, wrong hops and ports.
- Five-second introduction-parser fuzzing passed **21,488 executions**, including
  authenticated adversarial plaintext as well as malformed raw cells.
- Host tests cover fixed loopback backends, concurrency bounds, cross-introduction
  replay rejection, replay-cache saturation and introduction rate limiting.

## Independent private-network interoperability

The private harness runs one authority, four relays, a C Tor SOCKS client and a
local HTTP fixture. Its authority supplies measured fixture bandwidths, HSDir
flags and 75-second votes with `hsdir_interval=30`, matching C Tor's shortened
private-network onion periods. The C Tor client starts after directory readiness.
The service test binary uses explicit localhost hops; production subnet checks
are not disabled. Temporary peer keys, processes and configuration are cleaned up.

The final test body passed in **1.60 seconds** after private directory bootstrap:

- Three native ESTABLISH_INTRO registrations accepted by C Tor relays.
- Signed/encrypted descriptors accepted by all five available HSDirs for each
  of two overlapping periods.
- C Tor independently discovered/decrypted the descriptor, authenticated the
  service rendezvous and fetched HTTP through Veil's loopback forwarding.
- Five **2,340,000-byte** downloads passed integrity checks, four concurrently.
- A request to unmapped onion port **81** failed.
- Hosting, circuits, streams and directory workers shut down under the race detector.

Earlier harness runs exposed idle relay bandwidth/path constraints and C Tor's
special testing-network period rules. These were corrected in the private fixture;
production trust, path selection and protocol authentication were not weakened.

Reproduce with `make service-check`, or specify installed peer binaries with
`scripts/service_check.py --tor /path/to/tor --tor-gencert /path/to/tor-gencert`.

## Public-network hosting interoperability

Also run on 2026-09-21 with the production binary and an independent C Tor
0.4.9.12 client on the real Tor network. The backend served only a temporary
fixture on a numeric loopback address. Service identity, directory state and
persistent guard state were retained across diagnostic restarts.

- C Tor discovered and decrypted the public descriptor, completed service
  rendezvous, and fetched the expected **48-byte HTTP 200** response in
  **2.858 seconds** on the successful probe.
- Three concurrent **2,400,000-byte** downloads matched the expected content
  byte for byte, in **9.919, 10.269 and 14.805 seconds**.
- Unmapped onion port **81** returned SOCKS reply **2** (curl exit 97), with no
  response body, in **11.512 seconds**.
- Both public descriptor periods had successful uploads: the final run reached
  **8/8** HSDirs for one period and **7/8** for the other. Remaining uploads timed
  out and were retried. Full-publication `service_ready` was not reached during
  this run; successful client access was checked independently while publication
  remained partial. One initial client probe timed out before a retry succeeded.
- All temporary host, client and backend processes were stopped. Veil and C Tor
  exited successfully on SIGINT. This was a short interoperability test, not a
  long-duration rotation, availability or anonymity assessment.

The real-network run exposed and fixed three issues:

1. A successful but slow fresh directory download exceeded the three-minute
   attempt deadline. Public attempts now allow eight minutes within the existing
   overall startup deadline.
2. Fixed HSDir endpoints were incorrectly subjected to random middle bandwidth
   weighting. The real consensus assigned some of them zero middle weight.
   Mandatory verified endpoints now bypass only that random sampling step;
   randomly chosen endpoints and middle hops retain bandwidth weighting.
3. Fixed endpoint family/subnet exclusions were applied too late, after choosing
   a guard. They now restrict selection from the persistent guard sample before
   circuit construction. Path separation and authenticated relay checks remain.

Regression tests cover zero-weight fixed endpoints, unavailable relays, and
family/subnet exclusions. Full race tests and vet pass; gosec still reports
**zero findings and zero loading errors**, with the same 19 protocol annotations.
Debug mode now reports reasons for rejected rendezvous relay/link data.

Local evidence is retained under `/private/tmp/veil-public-host-b8g77wli`:
`service.log`, `probe-response.txt` and `transfer-results.json`. The `service`
and `tor` subdirectories contain private test state and must not be published.
The public browsing/onion-client results below remain separate.

---

# Opt-in debug logging validation

Run on 2026-09-20, macOS arm64, Go 1.27.1.

- `go test -race ./... -timeout=120s` and `go vet ./...`: passed.
- Gosec: **47 production files, zero findings, zero loading errors**, with the
  unchanged **18** existing protocol annotations. Binary rebuilt successfully.
- Tests cover explicit `-debug` / `-debug=false`, per-invocation logger isolation,
  quiet readiness/request rejection/shutdown, debug circuit reuse, underlying
  SOCKS failure reporting, credential/token/payload exclusion, and concurrent
  records with escaped newline and terminal-control characters.
- CLI lifecycle tests now consume debug readiness records. Readiness is no longer
  emitted to stdout, and normal operation is silent without `-debug`.

## Live CLI checks

The rebuilt executable used the existing persistent public state. A quiet
`-onion-only` proxy on loopback port 19051 completed SOCKS negotiation and rejected
a clearnet CONNECT with reply 2. Both stdout and stderr remained **zero bytes**
from startup through SIGINT shutdown.

A proxy with `-debug` on loopback port 19052 fetched the public HTTPS Tor checker
through SOCKS5 with explicit isolation credentials and normal TLS verification.
The response confirmed **IsTor=true**. Stderr contained startup/readiness,
request IDs, circuit construction, exit relay details, successful connection
setup and closure, and shutdown records. Stdout remained empty and the supplied
credentials were absent from the logs. Both test proxies exited successfully;
persistent directory and guard state was retained.

---

# Veil 0.12 onion-only mode validation

Run on 2026-09-20, macOS arm64, Go 1.27.1.

- Complete `go test -race ./... -timeout=120s`: passed.
- `go vet ./...`: passed; executable rebuilt as **0.12.0-dev**.
- Gosec 2.29.0: **46 production files, zero findings, zero loading errors**,
  with **18** existing protocol annotations and no new suppressions.
- Policy tests cover scoped and untagged requests, full connection capacity,
  cached exit circuits, ordinary names, literal IPs, invalid onion addresses,
  valid onion routing and reuse, and authenticated/anonymous SOCKS negotiation.
- CLI lifecycle tests verify readiness reports `mode: "onion-only"` when enabled
  and `mode: "all"` otherwise.

## Live onion-only SOCKS test

Started the rebuilt CLI with the existing public directory and guard state:

```sh
./bin/veil proxy -public -onion-only -state ./state-public -listen 127.0.0.1:19050
```

The listener reported `socks5_ready` with `mode: "onion-only"`. Raw SOCKS5
CONNECT requests for `example.com:443`, `1.1.1.1:443` and
`[2606:4700:4700::1111]:443` each received reply **2** (ruleset denial).
A curl request through that same listener, using remote hostname handling and
explicit SOCKS credentials, fetched the Tor Project v3 onion site's `/index.html`:
**HTTP 200, 23,597 bytes**, with title `Tor Project | Anonymity Online`.
The test proxy was stopped afterward; persistent state was preserved.

This verifies the application-destination policy and a live onion connection;
it does not establish production privacy parity or restrict traffic outside Veil.

---

# Veil 0.11 scoped reuse and caching validation

Run on 2026-09-20, macOS arm64, Go 1.27.1.

- Complete `go test -race -cover ./... -timeout=120s`: passed. Client coverage
  **61.2%**, isolation package **100%**; opt-in public paths are excluded from
  the ordinary unit-suite coverage figures.
- `go vet ./...`: passed; executable rebuilt as **0.11.0-dev**.
- Gosec 2.29.0: **46 production files, zero findings, zero loading errors**.
  Suppression-disabled audit: exactly the existing **18** protocol exceptions.
- Five-second `FuzzNegotiate`: **355,236 executions**, passed.
- Existing relay/service encryption, SENDME, directory, guard, SOCKS and state
  ownership regressions pass with the new client lifecycle.

## Concurrency and resource checks

Deterministic fixtures test 16 parallel connections sharing one build/circuit
and transferring 4 MiB in total, cancellation of a waiting caller, setup deadlines
remaining detached after connection establishment, and matching/mismatched scope,
destination, port and family keys. Credential framing, separate API/SOCKS token
namespaces, application-IP/listener boundaries and untagged dedicated behavior
are checked separately.

A 200-request workload repeatedly reuses four scopes, injects circuit failures
and reconnects while checking circuit/connection bounds and final teardown.
Tests retire aged circuits while active streams continue, close them after the
last stream drains, evict idle entries, reject new BEGIN after directory expiry,
avoid replaying failed BEGINs, and join in-progress builds on shutdown.

Descriptor tests exercise shared fetches, independent waiter cancellation, deep
copies, certificate/descriptor and period expiry, retained revision floors,
rollback/conflicting revision rejection, unchanged-revision TTL preservation,
cache capacity exhaustion, scope/period separation, and Close during a fetch.

## Live public SOCKS test

The opt-in `TestPublicSOCKSReuse` runs the real native client behind its loopback
SOCKS5 server with explicit credentials and the existing persistent public guard
state. HTTP keep-alive is disabled, so every request opens a distinct SOCKS/Tor
stream. Normal HTTPS certificate validation remains enabled.

The successful run completed in **18.77 seconds** (20.223 seconds including the
Go test runner) and verified:

- Tor Project's public v3 onion website: **10 HTTP 200 requests**. The initial
  request and two waves of four parallel requests used the same service circuit.
- Forced age retirement caused the tenth request to use a new service circuit;
  the same scoped descriptor cache remained available.
- The HTTPS Tor checker returned **IsTor=true**.
- Test proxy, circuits and directory workers shut down; persistent state remained.

Two preceding runs failed at initial onion setup before exercising reuse (SOCKS
replies 2 and 1). Guard state was retained and no verification or retry policy was
relaxed. The passing run demonstrates interoperability; initial relay/service
availability is still variable, and the test intentionally does not hide failures
with application-request retries.

To reproduce, stop any proxy using that state directory first:

```sh
VEIL_PUBLIC_STATE="$PWD/state-public" go test -race ./client \
  -run '^TestPublicSOCKSReuse$' -v -timeout=12m
```

The test skips unless the environment variable is set. It sends traffic to Tor
Project's published onion site and HTTPS checker through native Tor, with no
C Tor/Arti runtime. These checks do not establish production privacy parity or
long-duration browser stability.

---

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
