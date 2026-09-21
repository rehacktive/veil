# Veil

Veil is a staged, native Go rewrite of [Arti](https://github.com/zydou/arti), the Rust Tor implementation. This is an independent, experimental project, not an official Tor Project release.

**Current stage: experimental SOCKS5 client and v3 onion host.** It authenticates relay channels, downloads and verifies directory documents over native one-hop directory circuits (pinned CREATE_FAST for public bootstrap, ntor afterward), refreshes private caches, and maintains sampled/confirmed/primary guards. It selects compatible guard/middle/exit paths and builds them with CREATE2, EXTEND2, and type-2 ntor. It multiplexes TCP streams through a cancellable Go `net.Conn` API with authenticated SENDME flow control and exit-side DNS. `veil proxy` exposes those streams through a loopback SOCKS5 CONNECT listener, with circuit reuse inside explicit isolation scopes and dedicated circuits for untagged connections. V3 onion connections use authenticated descriptors, hs-ntor introductions/rendezvous, and an encrypted service hop. The Go implementation needs no Rust runtime, C Tor process, or cgo. It uses `filippo.io/edwards25519` for public-key blinding and coordinate conversion. An optional interoperability test launches C Tor separately as a test peer.

## Browse the public internet

From the repository directory:

```sh
make public-proxy
```

This builds the Go binary and runs the equivalent of:

```sh
./bin/veil proxy -public -state ./state-public -listen 127.0.0.1:9050
```

No `bootstrap.json`, Rust, or C Tor installation is needed. Public mode bundles
nine authority identities and 200 pinned fallback relays from official Arti data;
see [bootstrap provenance](directory/data/README.md). It authenticates the
fallback channel, verifies an authority majority and every required descriptor,
then builds application circuits through three directory-selected relays.

The proxy is quiet by default. Add `-debug` to the command above to see
bootstrap progress and the `socks5_ready` message on stderr. First startup
downloads tens of megabytes and can take several minutes (10-minute startup
deadline); SOCKS requests are served once bootstrap completes.
The private cache and persistent guards are reused on restart. Keep
`state-public` between runs, use a separate state directory for private networks,
and run only one Veil process per state directory. An OS lock rejects another
owner automatically. Ctrl-C stops the proxy and releases ownership; a crash also
releases it. Ctrl-C does not discard the persistent cache or guard sample.

In another terminal, test it with:

```sh
curl --fail --max-time 90 --noproxy '' \
  --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
curl --fail --max-time 90 --noproxy '' \
  --socks5-hostname 127.0.0.1:9050 https://example.com/
```

The first response should include `"IsTor":true`. `--socks5-hostname` sends the
hostname to the exit for resolution; `--noproxy ''` prevents environment bypass
rules from making this test connect directly. HTTPS certificate verification
remains enabled. Transient relay failures during circuit construction trigger up to three
build attempts, with randomized backoff, within the connection deadline.
An individual request can still fail; retry it without clearing persistent
guard state. Authentication, protocol, directory and state failures stop
immediately. Streams are never reopened automatically after contacting an exit. If port 9050 is occupied, use
`-listen 127.0.0.1:19050` and change the client port too.

For a browser test, use a separate Firefox test profile. In its
[connection settings](https://support.mozilla.org/en-US/kb/connection-settings-firefox),
select manual proxy configuration, set **SOCKS Host** to **127.0.0.1**, port
**9050**, select **SOCKS v5**, and enable **Proxy DNS when using SOCKS v5**.
Leave HTTP/HTTPS proxy fields empty. Visit
[the Tor checker](https://check.torproject.org/) once bootstrap completes (`socks5_ready` when debugging).
Return that profile to its previous proxy setting when finished.

Public HTTPS through Veil has been tested; details are in [VALIDATION.md](VALIDATION.md).
This remains an experimental interoperability client: padding, traffic fingerprint
parity and independent privacy review are incomplete. A normal browser configured
with this proxy does not provide Tor Browser's privacy protections.

## Connect to v3 onion services

Start the same `make public-proxy` command above. Once bootstrap completes,
connect to Tor Project's public onion site:

```sh
curl --fail --max-time 180 --noproxy '' \
  --socks5-hostname 127.0.0.1:9050 \
  http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/index.html
```

No additional config or C Tor process is needed. Pass onion names through SOCKS5
using `--socks5-hostname` (or `socks5h://`), never local DNS. Veil validates the
v3 address, selects HSDirs from the verified consensus, authenticates and decrypts
the descriptor, then establishes an hs-ntor rendezvous and encrypted service
stream. Onion requests never use exit DNS or fall back to a direct connection.
The Go `client.Dialer` supports the same `host.onion:port` destinations.

Connections in the same explicit session scope can reuse service circuits and
verified descriptors. Untagged connections fetch independently. HSDir
fetches use three hops and close before introduction; setup uses at most two
simultaneous three-hop circuits per connection slot. Descriptors are bounded to
50,000 bytes and stay in memory. The default onion setup budget is three minutes
(`-onion-timeout`), with up to eight directory attempts and three introduction
attempts for supported transient failures. Authentication failures stop setup.

This supports public v3 services. Client authorization/restricted discovery,
proof-of-work solving, onion subdomains, legacy v2 addresses
are not implemented. Experimental service hosting is described below. Introduction points
must appear with matching identity and ntor keys in the current verified
consensus. Services requiring the unsupported features may fail to connect.

## Host a v3 onion service

The experimental native host exposes one onion TCP port. The CLI forwards it to
a local TCP server; Go applications can accept native streams through a
[`net.Listener`](#accept-onion-connections-in-go) without a local TCP backend.
This example publishes a small website as a v3 hidden service on the public Tor
network. You need Go and Python 3; Veil itself does not need a C Tor process.
Start each terminal in the Veil repository directory.

### 1. Create and serve a test page

In terminal 1, build Veil and create a temporary directory containing only the
page you want to publish:

```sh
make build
site_dir=$(mktemp -d "${TMPDIR:-/tmp}/veil-site.XXXXXX")
cat > "$site_dir/index.html" <<'HTML'
<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>My Veil onion service</title>
<h1>Hello from Veil!</h1>
<p>This page is served through a native Go v3 onion service.</p>
</html>
HTML
python3 -m http.server 8080 --bind 127.0.0.1 --directory "$site_dir"
```

Leave this server running. You can check the page locally at
`http://127.0.0.1:8080/`. The server listens only on loopback; no router port
forwarding is needed.

### 2. Start the onion service

In terminal 2:

```sh
./bin/veil service -public -state ./state-service \
  -port 80 -target 127.0.0.1:8080 -debug
```

Leave Veil running too. Onion port **80** forwards to local port **8080**.
First bootstrap and descriptor publication can take several minutes.
`-debug` shows progress in this terminal; omit it for quiet operation.

`service_ready` reports successful publication to every selected HSDir in both
periods. Some HSDirs may be unavailable: the host retries, and clients may already
connect while publication is partial. `service_descriptor_published` reports the
successful/total uploads per period; the hostname file alone is not readiness.

### 3. Open your onion website

In terminal 3, print the complete URL:

```sh
printf 'http://%s/\n' "$(cat ./state-service/hostname)"
```

Open that URL in Tor Browser. You should see **Hello from Veil!**. Use the
`.onion` URL for this check; the loopback URL tests only the local web server.
If the service is still publishing, allow it to progress and retry.

Alternatively, test with curl through Veil's own SOCKS5 proxy. In another
terminal, start a proxy with a separate state directory and leave it running:

```sh
./bin/veil proxy -public -onion-only -state ./state-public \
  -listen 127.0.0.1:19050 -debug
```

After `socks5_ready`, run this in terminal 3:

```sh
curl --fail --max-time 180 --noproxy '' \
  --socks5-hostname 127.0.0.1:19050 \
  "http://$(cat ./state-service/hostname)/"
```

Curl should return the sample HTML above. The separate SOCKS port **19050** in
this example avoids the usual Tor proxy port **9050**.

### Stop or restart

Press `Ctrl-C` in the service and web-server terminals to stop hosting. Stop the
optional SOCKS proxy the same way. To host your own site, serve its directory on
`127.0.0.1:8080` and rerun the same `veil service` command.

Keep `state-service` across restarts to retain the same onion address.
`onion-identity` stores the private identity seed and a durable descriptor
revision counter. Losing that file loses the address; sharing it lets someone
impersonate the service. Keep this directory private and out of version control.
State is exclusively locked: the service and browsing proxy must use different
state directories. The temporary sample page is separate from the service state.

### Behavior and current limits

Hosting uses three introduction points, signed/encrypted descriptors in two
overlapping publication periods, service-side hs-ntor, and native incoming
streams. Publication is retried and renewed, introduction keys rotate, and
failed introduction circuits are rebuilt without resetting persistent guards.
Only the configured virtual port is accepted. The backend must be a numeric
loopback address; client-supplied addresses are never dialed directly.

Defaults bound the host to 16 rendezvous circuits and 32 streams,
5 minutes idle per forwarded stream and a 1-hour circuit lifetime. Replays are rejected,
introduction processing is rate-limited, and replay caches have fixed bounds.
Each introduction generation lasts at most two hours. This first implementation
restarts the generation on introduction failure or rotation, closing its active
streams; seamless draining/replacement is future work. Client rendezvous links
must exactly match the supported links of a relay in the live consensus.

Public-network interoperability has been verified with an independent C Tor
client: HTTP, three concurrent 2.4 MB downloads and unmapped-port rejection.
See [VALIDATION.md](VALIDATION.md) for results and partial-publication limitations.

This is a first hosting milestone, not production anonymity parity. Restricted
services/client authorization, PoW defenses, vanguards, multiple port mappings,
offline identity keys and transparent introduction rotation remain unimplemented.
The normal Tor identity/guard/descriptor verification rules remain in force.

For a reproducible private-network interoperability check, with C Tor and
`tor-gencert` installed:

```sh
make service-check
# Or select existing test-peer executables:
python3 scripts/service_check.py --tor /path/to/tor --tor-gencert /path/to/tor-gencert
```

The check runs a temporary authority, relays, an independent C Tor client and a
loopback HTTP fixture; no public service is published. It builds a test-only
binary with explicit localhost hops because normal subnet exclusions reject
localhost networks. The `veiltest` helpers are absent from the production binary.
C Tor is a test peer only; `veil service` itself needs no C Tor process.

### Accept onion connections in Go

`service.Listen` returns a `net.Listener` backed directly by incoming onion
streams. It starts the host in the background and requires an empty `Target`:

```go
listener, err := service.Listen(ctx, manager, guards, identity, service.Options{
    Port: 80,
})
if err != nil {
    return err
}
defer listener.Close()

// Addr().String() is "<v3-address>.onion:80"; Network() is "onion".
fmt.Println(listener.Addr())
server := &http.Server{Handler: handler, ReadHeaderTimeout: 30 * time.Second}
return server.Serve(listener)
```

The caller holds the state lock, bootstraps the directory manager, and keeps it
running for the listener's lifetime. A complete example handles this setup and
shutdown, with no TCP listener, C Tor process, or cgo:

```sh
go run ./examples/onion-listener -state ./state-listener -port 80
```

Returning from `Listen` does not mean the descriptors are published yet;
`Accept` waits for incoming connections. A host failure unblocks `Accept` with
an error matching `net.ErrClosed` and retaining the underlying cause.

`Close` rejects pending streams and unblocks all waiting `Accept` calls. It
preserves connections already accepted by the application; close those
connections to let the host drain. Canceling the context passed to `Listen`
stops the host and closes all its streams. Wait for `<-listener.Done()` before
releasing the state lock or stopping its directory manager.

`MaxStreams` bounds pending and accepted streams together. Applications own and
must close accepted connections, and set their read/write deadlines; the
forwarder's `IdleTimeout` does not apply. `LocalAddr` identifies the onion service;
`RemoteAddr` is an anonymous stream label, not a client IP address. Circuit
lifetime limits and the introduction-rotation interruptions described above
still apply. `make service-check` exercises both forwarding and listener hosting
with an independent C Tor client on a private test network.

## Onion-only (dark) mode

To permit only v3 onion application destinations:

```sh
make build
./bin/veil proxy -public -onion-only -state ./state-public -listen 127.0.0.1:9050
```

Use the onion curl command above once bootstrap completes. With `-debug`,
readiness is reported as `socks5_ready mode=onion-only`. Ordinary hostnames and literal IPv4/IPv6 destinations are rejected
with SOCKS reply **2** (connection not allowed by ruleset). Malformed requests
may receive parser errors instead. Invalid, legacy v2 and unsupported onion
addresses are also rejected; only valid supported v3 addresses proceed.

Both the SOCKS frontend and native Go dialer enforce the policy before destination
lookup, circuit construction, connection-slot waiting or pooled-circuit reuse.
Valid onion requests retain the usual descriptor verification and isolation rules.
Library callers enable the same restriction with `client.Options{OnionOnly: true}`;
policy failures can be checked with `errors.Is(err, client.ErrOnionOnly)`.
A standalone SOCKS server can also use `socks5.Options{OnionOnly: true}`.

The flag defaults to false and is not persisted in the state directory; include
it each time you start dark mode. Debug output reports `mode=all` in normal mode.
`-public` still selects public Tor bootstrap data. Veil must still contact Tor
relays/directories by IP; this is an application-destination restriction, not an
IP firewall or a block on connections applications make outside this proxy.

## Debug output

Add `-debug` when launching the proxy:

```sh
./bin/veil proxy -public -state ./state-public -debug
# Onion-only, with the same diagnostics:
./bin/veil proxy -public -state ./state-public -onion-only -debug
```

Timestamped terminal messages go to **stderr**. They report startup, directory
bootstrap/refresh progress, readiness, SOCKS requests and failures, policy blocks,
circuit build attempts/retries/reuse, connection setup time and duration, and
shutdown. SOCKS connections carry a numeric `request_id` so concurrent activity
can be followed. Clearnet circuits report the exit relay's nickname, fingerprint
and advertised relay address; that address is not necessarily the outbound IP
seen by a website. Onion setup reports descriptor fetching, introduction attempts
and rendezvous completion, with `exit=none`.

Logs include destination hostnames/onion names and relay metadata. They exclude
SOCKS credentials, isolation tokens, keys, descriptor contents and traffic
payloads. Values are escaped, and concurrent records are serialized. Veil writes
no log files automatically.

Without `-debug` (or with `-debug=false`), the proxy produces no normal logs,
including no progress or readiness event on stdout. Help and fatal errors remain
visible. Debug mode is not persisted; enable it explicitly on each launch.
Library users may supply an optional `*slog.Logger` through `client.Options.Logger`
or `socks5.Options.Logger`; nil is silent and no global logger is installed.

## Reuse circuits within a session

The existing proxy command enables reuse for clients that send SOCKS5
username/password tokens. Reuse requires the same two token fields, application
IP, proxy listener, destination hostname/IP, destination port and IP family.
Different onion services always remain separate. Requests without tokens keep
getting dedicated circuits; ordinary browser proxy settings alone do not enable
sharing because Veil cannot infer which application/session owns a connection.

For repeated curl requests, keep the same test-session token:

```sh
curl --fail --max-time 180 --noproxy '' \
  --socks5-hostname 127.0.0.1:9050 --proxy-user 'test-session:one' \
  https://example.com/
```

Run it again to reuse the circuit. Use a different token for an unrelated session.
These are grouping labels, not passwords checked against an account. Every HTTP
request still opens its own stream; no failed BEGIN or application data is replayed.
A known-dead circuit is discarded before the next request attempts a stream.

Default limits:

- Stop adding streams after **10 minutes** (`-circuit-max-age`). Active streams
  finish normally, subject to their existing connection timeouts.
- Close pooled circuits after **2 minutes idle** (`-circuit-idle-timeout`).
- Keep at most **16 pooled circuits**, counting builds, active and draining
  circuits (`-max-pooled-circuits`). Idle entries can be evicted for new scopes.
- Share at most **16 simultaneous streams per circuit**. The independent
  `-max-connections` limit still bounds all active/pending SOCKS connections.
  Dedicated circuits count toward that connection limit, outside the pool.

Use `-circuit-reuse=false` to retain dedicated circuits even with tokens.
Descriptors still cache within explicit scopes. The cache holds at most 128
service/period/scope records in memory. It enforces descriptor/certificate expiry,
rejects lower revisions and conflicting bytes at the same revision, and retains
revision floors until the blinded-key period ends. Re-fetching the same revision
cannot extend its original cache lifetime. A full cache rejects new entries until
period history expires; it never discards a live revision floor to make room.
Expired records are pruned on cache access. No descriptor history survives
process restart or crosses isolation scopes.

Library callers opt in with `isolation.WithToken(ctx, "session-name")` before
calling `client.Dialer.DialContext`. Close every returned connection, then call
`Dialer.Close()` before releasing the directory state lock. Closing the dialer
cancels pending builds and active circuits, joins its pool workers and clears the
in-memory descriptor cache. This remains an experimental, conservative pool;
it does not implement Tor Browser site isolation or full Arti circuit policy.

## Try SOCKS5 locally

From the repository directory, run:

```sh
make proxy-demo
```

This builds Veil, creates a temporary three-relay Tor network, starts private
HTTP/DNS fixtures, and tests the native SOCKS5 server with `curl`. It prints:

```text
Veil SOCKS5 works: this HTTP response crossed three native Go Tor hops.
```

It then prints an exact `curl --socks5-hostname ...` command to paste into another
terminal and stays running. Try the printed URL with `/large` for a 2 MiB
response. Ctrl-C stops all demo processes and deletes their keys and state.
Initial bootstrap can take up to 150 seconds. **No `bootstrap.json` is needed
for this demo**, and it does not access the public Tor network or public internet.

Requirements: Go 1.24+, Python 3, `curl`, and existing C Tor / `tor-gencert`
executables. The launcher finds them on PATH or reuses the earlier temporary
Tor build on this machine. To specify them yourself:

```sh
python3 scripts/proxy_demo.py --tor /absolute/path/to/tor \
  --tor-gencert /absolute/path/to/tor-gencert
```

For the same self-check followed by automatic cleanup, run `make proxy-check`.
Nothing is downloaded or installed by either command. C Tor supplies the test
network's relays only; Veil handles SOCKS, the client TLS channel, circuit
construction, encryption, streams, and flow control in Go.

The localhost demo uses a compiled **test harness** to supply explicit private
hop pins to the native builder. It runs the production SOCKS server, but does
not bypass the production CLI's directory-based path selection. Localhost relays
cannot satisfy that selector's subnet separation; there is no production switch
to disable it. The demo exit permits only its local fixture port.

## Run the proxy on your own controlled network

With independently trusted bootstrap pins and a network whose relays satisfy
subnet separation and exit policies:

```sh
./bin/veil proxy -config bootstrap.json -state ./state -listen 127.0.0.1:9050
```

The command restores or bootstraps a verified directory and keeps refreshing it.
With `-debug`, a `socks5_ready` message reports the listening address once
startup completes. Without the flag, normal operation produces no logs.
Use `curl --socks5-hostname 127.0.0.1:9050 ...` or `socks5h://127.0.0.1:9050`
so destination hostnames reach Veil without local DNS lookup. Ordinary names
resolve at the exit; v3 onion names use the service rendezvous protocol. The JSON schema
for your controlled network’s bootstrap pins is below. Use `-public` instead
of `-config` for the bundled public Tor network setup above.

Defaults are 16 simultaneous connections (including pending handshakes), a
10-second SOCKS handshake, a 1-minute ordinary connection deadline (3 minutes
for onion setup, controlled by `-onion-timeout`), 5 minutes idle,
and a 1-hour maximum connection lifetime. Circuit construction has up to
three attempts of at most 20 seconds each, sharing the total connection budget
with backoff and stream establishment. Use `-build-attempts 1` to disable retries,
or adjust `-build-attempts` (1..5), `-build-timeout` and `-connect-timeout`. `veil proxy -h` lists the controls.
Listeners must be numeric loopback addresses. Explicit SOCKS tokens permit reuse
within the same application IP, listener, destination, port and address family.
Untagged connections remain dedicated; guards stay shared and persistent. Tokens
are isolation metadata, **not access-control credentials**. Other local processes can use the
listener. Debug mode logs destinations and exit relay metadata; payloads, credentials
and isolation tokens are never logged.

CONNECT supports hostnames and numeric IPv4/IPv6 addresses. Hostnames currently
use IPv4 exits. BIND, UDP, SOCKS4, GSSAPI, automatic stream retries,
and TCP half-close are unsupported. Tor END closes both
stream directions. There is no direct-connect fallback. A fatal directory
verification/state error stops the proxy; expired snapshots reject new circuits.
One process must own the state directory. Public-network anonymity, traffic
fingerprint parity, and complete production privacy behavior remain unvalidated.

## Build and run

Requires Go 1.24 or newer (the compatibility tests use standard-library SHAKE256).

```sh
go test ./...
go build -trimpath -o bin/veil ./cmd/veil
./bin/veil version
./bin/veil help
```

Inspect a binary stream of already decrypted channel frames:

```sh
./bin/veil inspect -link 4 < cells.bin
./bin/veil inspect -handshake -payload < handshake-and-cells.bin
```

`-handshake` reads the initial VERSIONS frame before switching to four-byte circuit IDs. Otherwise `-link` specifies the already negotiated link protocol, 4 or 5. Output is newline-delimited JSON. Fixed-cell payload lengths include the 509-byte padded body. `-payload` includes raw payloads; encrypted relay payloads remain encrypted. TLS packet captures must be decrypted and reassembled before using this tool.

Check a relay using identity pins obtained independently from a trusted descriptor:

```sh
./bin/veil channel-check \
  -address "$RELAY_IP_PORT" \
  -rsa "$RSA_IDENTITY_HEX" \
  -ed25519 "$ED25519_IDENTITY_HEX" \
  -timeout 30s
```

The address must be a numeric `IP:port` (bracket IPv6). The RSA fingerprint is 40 hex characters and the Ed25519 identity is 64 hex characters. Both are required and checked. The command prints authenticated connection metadata as JSON and closes the connection; it does not build circuits or send application traffic. It makes a direct connection to the chosen relay, so it is not an anonymous operation. The separate directory-bootstrap command requires explicit authority and bootstrap-relay pins.

## Implemented

| Go package | Upstream area | Coverage |
| --- | --- | --- |
| `cell` | `tor-cell`, parts of `tor-linkspec` | Link 4/5 frames; initial/repeated VERSIONS; CERTS, AUTH_CHALLENGE, NETINFO; CREATE2, CREATED2, EXTEND2; original relay message encoding and padding |
| `ntor` | `tor-proto/crypto/handshake/ntor.rs` | Type-2 client handshake; X25519; transcript authentication; HKDF-SHA256; 92-byte hop key derivation |
| `relaycrypto` | `tor-proto/crypto/cell/tor1.rs` | Persistent AES-128-CTR layers and running SHA-1 digests; outbound targeting; inbound hop recognition; circuit extension; SENDME digest tags |
| `torcert` | `tor-cert`, channel certificate checks | Ed25519 identity/signing/TLS chain; RSA identity and cross-certificate; validity, pin, and TLS binding checks |
| `channel` | `tor-proto/channel`, client channel handshake | TLS 1.2/1.3; ordered client handshake; bounded cell queues; cancellation; random circuit IDs; teardown |
| `directory` | `tor-netdoc`, initial `tor-dirmgr`/`tor-guardmgr`/path selection | Authority certificates, signed microdescriptor consensus, digest binding, native BEGIN_DIR fetches, private cache, refresh/retry manager, reusable channels, sampled/confirmed/primary guards, weighted path selection |
| `circuit` | `tor-proto/circuit`, circuit construction | Verified three-hop selection, tracked guard attempts, CREATE2/EXTEND2, RELAY_EARLY budget, ordered relay messages, multiplexed `net.Conn` streams, SENDME/backpressure, deadlines/cancellation, bounded teardown |
| `onion` | `tor-hscrypto`, `tor-netdoc/hsdesc` | V3 addresses, blinded keys, authenticated/decrypted descriptors, hs-ntor |
| `client` | Client lifecycle | Verified snapshot/guard integration, scoped circuit reuse/rotation, dedicated untagged circuits, bounded descriptor caching, lifetime ownership and SOCKS failure mapping |
| `socks5` | SOCKS frontend | Loopback CONNECT, IPv4/IPv6/hostnames, token negotiation, bounded connections, timeouts, bidirectional relay and cleanup |
| `cmd/veil` | Client and development tooling | `proxy`, version/help, offline frame inspection, pinned channel check, directory-check, directory-bootstrap, directory-watch, and circuit-check |

The module path is currently `veil`; change it and the internal imports together when a hosting location is chosen. The public API is provisional.

The offline codec retains unknown commands. Live channels reject unsupported commands and invalid handshake order, while ignoring padding and repeated VERSIONS as specified. The circuit package implements fixed three-hop construction and relay transport. Managed TCP streams use the circuit package; the directory package retains a dedicated single-stream, one-hop transport. PADDING_NEGOTIATE cells on link 5 are exposed to the caller; padding policy and scheduling are not yet implemented.

## Authenticated channel API

```go
// trustedIdentity must come from a verified descriptor or out-of-band pins.
ch, err := channel.Dial(ctx, channel.Target{
    Address:  netip.MustParseAddrPort("127.0.0.1:9001"),
    Identity: trustedIdentity,
}, channel.Options{HandshakeTimeout: 30 * time.Second})
if err != nil {
    return err
}
defer ch.Close()
info := ch.Info()
_ = info
```

`ctx` governs the entire channel lifetime; canceling it closes the connection. `HandshakeTimeout` bounds TCP, TLS, and Tor negotiation separately. `Send` copies a frame into a bounded queue and waits for its write to complete. A canceled send that was already queued closes the connection because its delivery is ambiguous. A canceled `Receive` does not close the connection. Both methods unblock on channel failure; `Close` waits for the reader, writer, and context watcher to exit.

Use `AllocateCircuitID` before sending circuit cells. It picks random IDs with the initiator's high bit set, rejects collisions, and never reuses an ID on the same channel. A 65,536-allocation lifetime cap bounds the retained ID set; open a new channel when exhausted. The receive queue applies backpressure when full. Circuit multiplexing and interpretation of received circuit messages remain future work.

The TLS connection is never exposed before Tor certificate verification completes. Web PKI hostname/CA validation is replaced by the Tor identity-to-signing-key-to-TLS-certificate chain; TLS session resumption is disabled. Handshake work is bounded by time, cell count, and byte count. Client NETINFO sends no local address list or timestamp.

## Directory verification and bootstrap

Verify the recorded Arti test network offline (these certificates are expired, so this example supplies the fixture time):

```sh
./bin/veil directory-check \
  -certificates directory/testdata/authorities.txt \
  -consensus directory/testdata/consensus.txt \
  -microdescriptors directory/testdata/microdescriptors.txt \
  -authorities 0B8997614EC647C1C6B6A044E2B5408F0B823FB0,5B591AD684C1AB8E0AB76C839E93FD097526A4BC,8A1777F0BF97344A7ABB97530EEEE38A5BDE8A4D,D190BF3B00E311A9AEB6D62B51980E9B2109BAD1 \
  -at 2000-01-01T00:02:30Z
```

`bootstrap.json` is a user-supplied file; Veil does not ship one or create it
automatically. Public mode uses bundled authority and fallback pins instead.

To try the live watcher locally, use existing C Tor and `tor-gencert` executables:

```sh
make build
python3 scripts/check_local_directory.py \
  --tor /absolute/path/to/tor \
  --gencert /absolute/path/to/tor-gencert \
  --demo
```

Replace the two executable paths. The demo starts a private localhost network,
generates its keys and a valid temporary `bootstrap.json`, bootstraps Veil, and
runs `directory-watch` for you. Initial setup can take up to 150 seconds. It prints
the exact watcher command and JSON status updates. Ctrl-C stops the watcher and
Tor processes and removes all temporary configuration, keys, and state. The demo
downloads and installs nothing and does not connect to the public Tor network.

For your own controlled live network, save the following schema as `bootstrap.json`
and fill it with independently trusted values:

```json
{
  "authorities": ["AUTHORITY_RSA_FINGERPRINT_HEX40"],
  "relay": {
    "address": "127.0.0.1:9001",
    "rsa": "RELAY_RSA_FINGERPRINT_HEX40",
    "ed25519": "RELAY_ED25519_PUBLIC_KEY_HEX64",
    "ntor": "RELAY_NTOR_PUBLIC_KEY_HEX64"
  }
}
```

Replace every placeholder; use the complete intended authority trust set, not just available signers. Then run:

```sh
./bin/veil directory-bootstrap -config bootstrap.json -state ./state -timeout 5m
```

The command requests certificates, a microdescriptor consensus, and all referenced microdescriptors over one-hop Tor circuits, using the configured relay for initial bootstrap and sampled guards once available. It never uses direct HTTP or DNS fallback. It checks a majority of **all configured authority identities**, certificate signatures and lifetimes, required client protocols, consensus validity, and every SHA-256 microdescriptor digest. Missing descriptors fail the entire bootstrap. The command writes a private, atomically replaced cache and prints directory metadata. It persists a guard sample for subsequent directory requests. It does not create application circuits.

Keep the directory current until interrupted:

```sh
./bin/veil directory-watch -config bootstrap.json -state ./state
```

`directory-watch` restores verified cached state immediately, schedules a randomized refresh before expiry, and prints JSON when directory or retry status changes. `-timeout` optionally bounds the whole run. Refreshes use sampled directory guards after initial bootstrap. The manager uses capped, randomized retry delays; each download round shares one authenticated channel across separate one-hop circuits. It requests only microdescriptors absent from the cache, and verifies each response against the exact requested digest set.

`directory.NewManager(cache, guards, bootstrapRelays, options)` provides the same lifecycle to Go callers. `Run(ctx)` blocks until canceled or a verification/state error occurs; `Refresh(ctx)` performs one bounded download round. `Snapshot()` is safe to call concurrently and refuses expired or not-yet-valid data, even during an outage. A failed refresh retains the previous verified snapshot only within its validity interval. Authentication, document, clock-validity, rollback, and state-write errors stop the automatic loop rather than triggering indefinite retries.

`directory.Cache.Load(now)` re-verifies every document; `Store` rejects an older or conflicting consensus. The manager can authenticate a recently expired cache at its original validation time solely to reconnect to already sampled directory guards, for up to 24 hours after expiry. It never exposes that snapshot as an application directory or expands the sample from expired data. Older cache recovery is deliberately refused; long-offline recovery beyond that window remains future work. `Snapshot.Valid(now)` and `Fresh(now)` distinguish validity from freshness. `-at` exists only for offline inspection.

`GuardStore` persists a bounded, bandwidth-weighted sample and confirmation order. Primary guards are derived from that state; failures do not delete identities or select an unrestricted new set. Separate directory reachability prevents a failed directory request from poisoning ordinary-circuit reachability. Guard dates are randomized, unlisted/old entries expire under live consensuses, retry delays are jittered, and pending non-primary attempts must pass a usability check. Existing version-1 single-guard files migrate while preserving the chosen identity as an unconfirmed sampled guard.

Circuit builders use `GuardStore.Select`, report authenticated circuit success or failure through its `GuardAttempt`, check `Usability`, and call `Close` when done. Cancellation closes an attempt without recording a failure. Guard state write failures stop further selection until the store is reopened. `GuardStore.Guard` and `Snapshot.SelectPath(guardStore, port, ipv6, now)` remain offline previews, not circuit-attempt tracking. Path selection enforces flags/protocols, mutual fingerprint families/shared family IDs, IPv4 /16 or IPv6 /32 separation, and exit-port summaries. It does not guarantee an exit permits a particular destination address.

All stateful CLI commands (`proxy`, `directory-bootstrap`, `directory-watch`,
and `circuit-check`) acquire a nonblocking exclusive lock before opening state.
Go embedders must call `directory.LockState(path)` before constructing their
shared cache/guard owner and close the lock only after all users have stopped;
the individual constructors do not lock independently. Locking uses the directory
inode, so aliases contend and there is no stale PID file to remove. Never delete
or replace a state directory while a process uses it. Supported locking targets
are macOS, Linux, FreeBSD, OpenBSD, NetBSD and DragonFly BSD; unsupported systems
or filesystems fail closed. Use a local filesystem. macOS is runtime-tested;
other targets are compile-checked. State directories must have mode 0700 and files 0600. Only the default unrestricted guard context is implemented; bridges and custom entry/reachability filters require later work. Three-hop construction now uses tracked guard attempts; application path-bias accounting remains unimplemented. Count-valued guard parameters are capped at 1,024 to bound state. Sampling uses the current guard specification's count-based threshold; it does not reproduce Arti's bandwidth-fraction variant.

Only the microdescriptor directory route is implemented. Full router-descriptor parsing, compressed downloads, consensus diffs, and partial-directory sufficiency remain future work. Public bootstrap uses bundled authority/fallback pins. Link padding, traffic fingerprints, and complete production privacy behavior are not implemented or validated. Veil remains an experimental development implementation.

## Three-hop circuit API

```go
// Hold directory.LockState(statePath) while manager, guards and circuits run.
// manager and guards share the same in-process state owner.
snapshot, err := manager.Snapshot()
if err != nil {
    return err
}
circ, err := circuit.Build(ctx, snapshot, guards, circuit.Options{
    Port: 443,
    BuildTimeout: time.Minute,
})
if err != nil {
    return err
}
defer circ.Close()
```

`Build` selects a tracked guard, then a weighted middle and exit with the existing
family/subnet exclusions and exit-port summary checks. It authenticates CREATE2
at the guard and sends two EXTEND2 messages in RELAY_EARLY cells, including both
RSA and Ed25519 identities. Each new hop is added only after its ntor reply
verifies. A successful full circuit confirms the guard; construction waits for
guard usability and rechecks directory validity before returning. Parent
cancellation does not penalize guards; extension failures do not mark an
already authenticated guard unreachable. This milestone makes one build attempt,
without automatic retries or path-bias accounting. The higher-level `client.Dialer`
adds bounded retries for transient build errors using the same persistent guard
store. It refreshes the snapshot between attempts, keeps one concurrency slot
for the entire request and tears down failed attempts before retrying. It never
replays stream opens or application bytes.

`ctx` owns the circuit lifetime; the separate build timeout stops applying after
construction. Each circuit owns a dedicated authenticated channel. `Send` and
`Receive` expose low-level relay messages, hop indices, and digest tags. Outgoing
messages are serialized through encryption and writing; incoming messages are
authenticated in wire order and delivered through a bounded queue. Stream
messages may target only the exit. Raw API callers must implement their own
stream state and flow control. For application traffic, use `DialContext` below;
a circuit rejects mixing managed streams with raw `Send`/`Receive` calls.

The circuit sends at most eight RELAY_EARLY cells, including both extensions and
the initial later-hop messages. Unsolicited extension replies, wrong-hop stream
messages, invalid digests, malformed cells, DESTROY, and TRUNCATED terminate the
circuit. Unknown authenticated commands and DROP are ignored with bounded runs.
Canceled queued sends and individual receives leave the circuit usable; failed
writes after encryption terminate it. `Close` joins the reader/lifetime loops and
attempts a bounded DESTROY with reason NONE before closing the dedicated channel.
Channel sharing across circuits and production padding remain future work;
the client now pools complete circuits within explicit isolation scopes. Protocol
references: [circuit construction](https://spec.torproject.org/tor-spec/creating-circuits.html),
[RELAY_EARLY](https://spec.torproject.org/tor-spec/relay-early.html), and
[teardown](https://spec.torproject.org/tor-spec/tearing-down-circuits.html).

For a controlled network with compatible exits and separated relay subnets,
`circuit-check` re-verifies an **existing live cache**, builds a circuit, prints
`authenticated_hops: 3`, and closes it without opening a stream:

```sh
./bin/veil circuit-check -state ./state -authorities "$AUTHORITY_FINGERPRINTS" -port 443
```

Set `AUTHORITY_FINGERPRINTS` to the full comma-separated trust set used for your
directory bootstrap. Stop other processes using that state directory first;
it now acquires the same exclusive state lock as the proxy. The localhost `--demo` network has no exits
and shares a subnet, so it deliberately cannot pass this production path selector.
To validate construction locally, use the separate test-only interoperability
check below; there is no production flag to bypass path restrictions.

## TCP stream API

```go
// circ was built with Options{Port: 443}; ctx still owns its lifetime.
conn, err := circ.DialContext(dialCtx, "tcp", "example.com:443")
if err != nil {
    return err
}
defer conn.Close()
if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
    return err
}
// conn implements net.Conn. Wrap it with tls.Client for application TLS.
```

`DialContext` accepts `tcp`, `tcp4`, or `tcp6` and a numeric destination port.
The port and IP family must match the circuit's selection options; build another
circuit for other ports/families. `tcp` uses that selected family. Hostnames are
sent in BEGIN for the exit to resolve; there is no local destination lookup or
direct-connect fallback. ASCII DNS labels (including externally encoded IDNA)
and numeric IPs are accepted; scoped IPv6 addresses are not. Ordinary exit
circuits reject `.onion` names. Use `client.New(...).DialContext` for onion
services; it builds and authenticates the service circuit before opening a stream.
IPv6 is covered by wire-format tests, but the live test currently uses IPv4.

Dial cancellation applies only until CONNECTED. Established streams support
concurrent Read/Write, changing deadlines, and idempotent Close. END preserves
buffered input before returning EOF (reason DONE) or a typed `circuit.StreamError`.
Tor's current END closes both directions, so there is no `CloseWrite`/half-close.
Local END always uses reason MISC. Channel/circuit failure unblocks streams;
an interrupted write after encryption closes the circuit because delivery and
cipher state are ambiguous. Cancellation while waiting for flow credit leaves
other streams usable.

The implementation uses fixed 500-cell stream windows and authenticated v1
circuit SENDMEs with ordered digest matching. Every 100 outgoing DATA cells
include unpredictable padding; replayed, forged, or wrong-hop acknowledgements
close the circuit. Stream acknowledgements pause while unread data accumulates.
Payload buffering is bounded to roughly 254 KB per stream, with at most 32
open streams or ended streams that still retain unread data. Closed stream IDs
retain bounded late-DATA credit and are never reused; 65,535 allocations exhaust
a circuit. The verified `circwindow` is clamped to 100..1000; this implementation
supports multiples of 100 and rejects unsupported SENDME versions before building.
The raw circuit stream API does not negotiate congestion control, isolate application
identities, pool circuits, retry failed streams, or implement production traffic
padding. The `client`/SOCKS layer isolates connections by allocating separate circuits.

Protocol references: [opening streams](https://spec.torproject.org/tor-spec/opening-streams.html),
[flow control](https://spec.torproject.org/tor-spec/flow-control.html), and
[closing streams](https://spec.torproject.org/tor-spec/closing-streams.html).

## Library flow

1. Obtain a relay identity and ntor public key from a **verified** directory descriptor. Use `directory.Verify` or `directory.Bootstrap` to authenticate microdescriptor directories against explicitly supplied authority roots.
2. Call `ntor.Start(relay)` and put its request in `cell.EncodeCreate2(cell.HandshakeNtor, request[:])`, or in `cell.EncodeExtend2` for a later hop.
3. Extract the length-delimited handshake from the reply with `cell.DecodeCreated2`, then call `state.Finish(reply)` once. Failed attempts consume the state too.
4. Use the returned keys in `relaycrypto.NewClient(keys)` or `client.AddHop(keys)` after a successful extension.
5. Encode a relay message using `cell.EncodeRelay`, then call `client.Encrypt(targetHop, body)`. Serialize the returned ciphertext in a RELAY or RELAY_EARLY channel cell as required by the circuit state machine.
6. For received relay cells, call `client.Decrypt` **before** `cell.DecodeRelay`. An unauthenticated body invalidates all cipher state and requires circuit teardown.

See the executable example in `cell/example_test.go`. The `circuit.Build` API handles construction and `Circuit.DialContext` opens managed `net.Conn` streams.

Cipher and digest state persists across cells. Never reuse handshake secrets, share hop keys between circuits, or reorder encrypted cells. Cryptographic primitives come from Go's standard library; SHA-1 and AES-CTR here implement the original Tor protocol, not a new encryption scheme. The library has not undergone an independent security audit and provides no anonymity by itself.

## Validation

```sh
make check  # vet, race detector, test coverage
make security # gosec (requires an installed gosec executable)
make fuzz   # nine bounded 10-second fuzz runs
```

The gosec scan uses all default rules. Narrow protocol/CLI exceptions and their
audit command are documented in [SECURITY.md](SECURITY.md).

Tests include upstream ntor handshake/key vectors, eight Tor-generated three-hop ciphertext vectors across 51 cells, mixed-hop bidirectional traffic, circuit extension, failed digest rollback, low-order X25519 key rejection, modified and truncated handshakes, invalid lengths, partial I/O, and parser fuzz targets. Certificate tests use Arti's recorded Chutney chain and reject byte mutations, truncation, wrong pins, expired certificates, and incorrect TLS bindings.

Channel integration tests use a local Go TLS relay fixture over both in-memory pipes and localhost TCP, covering link 4/5 and TLS 1.2/1.3. A compiled-binary test runs `veil channel-check` against that fixture. Lifecycle tests cover stalled I/O, cancellation, bounded queues, concurrent sends/ID allocation, malformed ordering, handshake resource limits, and teardown. The suite needs permission to bind an ephemeral localhost port. Compatibility fixtures and exact provenance are documented in [UPSTREAM.md](UPSTREAM.md).

Interoperability also passed against a running **C Tor 0.4.9.12** relay on localhost, negotiating link 5 and TLS 1.3, downloading its descriptor through native ntor/BEGIN_DIR, and rejecting wrong identity and ntor keys. To repeat it with an existing Tor executable:

```sh
make build
go build -o bin/directory-probe scripts/directory_probe.go
python3 scripts/check_local_tor.py --tor /absolute/path/to/tor --veil bin/veil --directory-probe bin/directory-probe
```

The script starts a temporary local relay with private keys/configuration, no SOCKS or exit service, no descriptor publication, no default authorities/fallback directories, and a dummy localhost authority. It stops that process and removes its temporary keys afterward. It downloads and installs nothing.

A second check creates a private network with one authority and two additional
non-exit relays and runs the complete Go bootstrap command:

```sh
python3 scripts/check_local_directory.py \
  --tor /absolute/path/to/tor \
  --gencert /absolute/path/to/tor-gencert \
  --veil bin/veil --watch
```

This passed against C Tor 0.4.9.12, verifying the live authority signature and
three microdescriptors, refreshing to a later consensus, confirming and preserving the guard sample, and restoring the cache on restart. It uses only localhost
authorities and removes all temporary processes, keys, and state on exit.


The three-hop interoperability check uses the same temporary network, with a
compiled Go **test binary** receiving explicit local public pins:

```sh
make build
go test -c -o bin/circuit-test ./circuit
python3 scripts/check_local_directory.py \
  --tor /absolute/path/to/tor \
  --gencert /absolute/path/to/tor-gencert \
  --circuit-test bin/circuit-test
```

It builds a three-hop circuit, exchanges a small BEGIN_DIR request/response
through all three hops, and rejects a wrong middle identity and last-hop ntor
key. All peers remain non-exits. This tests wire interoperability independently
of production path selection, which is covered with freshly signed directory
fixtures and separated subnets. It does not validate public-network operation,
large application transfers, or stream flow control.

The application-stream check adds a private DNS fixture and an authority exit
restricted to one loopback echo port:

```sh
go test -c -race -o bin/circuit-test ./circuit
python3 scripts/check_local_directory.py \
  --tor /absolute/path/to/tor \
  --gencert /absolute/path/to/tor-gencert \
  --stream-test bin/circuit-test
```

It passed against C Tor 0.4.9.12: four concurrent 2 MiB round trips, exit-side DNS,
EOF, DNS/exit-policy failures, pending-dial cancellation, read deadlines, and
circuit-close propagation. All network fixtures bind only to localhost and are
removed on exit. This test uses explicit test-only hop pins; production path
selection still enforces subnet separation and verified exit summaries.

Remaining work includes adaptive circuit management, stream retry policy, padding and independent privacy/security review; see [ROADMAP.md](ROADMAP.md). Public HTTPS interoperability has been tested. TLS traffic fingerprint parity and end-to-end anonymity properties remain **unvalidated**. Recorded results and limits are in [VALIDATION.md](VALIDATION.md).

## License

MIT; see [LICENSE](LICENSE). Upstream-derived protocol code and fixtures retain The Tor Project's copyright notice. This port does not use Arti's optional LGPL components.
