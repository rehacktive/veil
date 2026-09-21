//go:build veiltest

package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"veil/circuit"
	"veil/client"
	"veil/directory"
)

type hostingReadyHandler struct {
	slog.Handler
	ready  chan struct{}
	failed chan struct{}
}

func (h hostingReadyHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == "service_ready" {
		select {
		case h.ready <- struct{}{}:
		default:
		}
	}
	if r.Message == "service_publish_failed" {
		select {
		case h.failed <- struct{}{}:
		default:
		}
	}
	return h.Handler.Handle(ctx, r)
}

func TestLocalTorHosting(t *testing.T) {
	for _, mode := range []string{"forward", "listener"} {
		t.Run(mode, func(t *testing.T) { testLocalTorHosting(t, mode == "listener") })
	}
}

func testLocalTorHosting(t *testing.T, listen bool) {
	config := os.Getenv("VEIL_TEST_HOST_CONFIG")
	if config == "" {
		t.Skip("requires private hosting harness")
	}
	state := os.Getenv("VEIL_TEST_HOST_STATE")
	lock, err := directory.LockState(state)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	raw, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Authorities []string
		Relay       struct{ Address, RSA, Ed25519, NTor string }
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	root, err := directory.ParseFingerprint(cfg.Authorities[0])
	if err != nil {
		t.Fatal(err)
	}
	cache, err := directory.NewCache(state, []directory.Fingerprint{root})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := cache.Load(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var pins []struct{ RSA, Ed25519 string }
	if err := json.Unmarshal([]byte(os.Getenv("VEIL_TEST_CIRCUIT_PEERS")), &pins); err != nil {
		t.Fatal(err)
	}
	var relays []directory.Relay
	for _, pin := range pins {
		rsa, err := directory.ParseFingerprint(pin.RSA)
		if err != nil {
			t.Fatal(err)
		}
		b, err := hex.DecodeString(pin.Ed25519)
		if err != nil {
			t.Fatal(err)
		}
		var ed [32]byte
		copy(ed[:], b)
		r, err := snapshot.RelayByIdentity(rsa, ed)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("private relay %s: Guard=%v Stable=%v Fast=%v bandwidth=%d", r.Nickname(), r.HasFlag("Guard"), r.HasFlag("Stable"), r.HasFlag("Fast"), r.Bandwidth())
		relays = append(relays, r)
	}
	guards, err := directory.NewGuardStore(state)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := directory.NewManager(cache, guards, []directory.TorSource{{Target: relays[2].Target(), OnionKey: relays[2].NTor().OnionKey}}, directory.ManagerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Distinct identities prevent the C Tor client reusing a cached descriptor
	// from the other mode after its introduction circuits have been closed.
	identityState := filepath.Join(state, "forward-identity")
	if listen {
		identityState = filepath.Join(state, "listener-identity")
	}
	identityLock, err := directory.LockState(identityState)
	if err != nil {
		t.Fatal(err)
	}
	defer identityLock.Close()
	identity, err := directory.OpenServiceIdentity(identityState)
	if err != nil {
		t.Fatal(err)
	}
	name, err := identity.Address()
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("Veil onion hosting works!\n"), 90000)
	resume := make(chan struct{})
	defer close(resume)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/held" {
			_, _ = io.WriteString(w, "before rotation\n")
			w.(http.Flusher).Flush()
			select {
			case <-resume:
				_, _ = w.Write(payload)
			case <-r.Context().Done():
			}
		} else if r.URL.Path == "/large" {
			_, _ = w.Write(payload)
		} else {
			_, _ = io.WriteString(w, "Veil onion hosting works!\n")
		}
	})
	ready := make(chan struct{}, 16)
	failedPublication := make(chan struct{}, 16)
	options := Options{Port: 80, Logger: slog.New(hostingReadyHandler{slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}), ready, failedPublication})}
	if !listen {
		backend := httptest.NewServer(handler)
		defer func() { backend.CloseClientConnections(); backend.Close() }()
		options.Target = strings.TrimPrefix(backend.URL, "http://")
	}
	h, err := newHost(manager, guards, identity, options, listen)
	if err != nil {
		t.Fatal(err)
	}
	var blockPublication atomic.Bool
	var loseReply atomic.Bool
	publicationBlocked := make(chan struct{}, 1)
	publicationRelease := make(chan struct{})
	upload := h.upload
	h.upload = func(ctx context.Context, s *directory.Snapshot, target directory.Relay, raw []byte) error {
		if blockPublication.Load() {
			select {
			case publicationBlocked <- struct{}{}:
			default:
			}
			select {
			case <-publicationRelease:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		err := upload(ctx, s, target, raw)
		if err == nil && loseReply.Load() {
			return errors.New("test: HSDir accepted the descriptor but its acknowledgment was lost")
		}
		return err
	}
	retirements := make(chan *time.Timer, 16)
	h.newRetireTimer = func(d time.Duration, f func()) *time.Timer {
		timer := time.AfterFunc(d, f)
		retirements <- timer
		return timer
	}
	h.selectIntro = func(s *directory.Snapshot, excluded []directory.Fingerprint) (directory.Relay, error) {
		for _, r := range relays {
			found := false
			for _, id := range excluded {
				if id == r.Identity() {
					found = true
				}
			}
			if !found {
				return r, nil
			}
		}
		return directory.Relay{}, directory.ErrPath
	}
	introBuilt := make(chan *circuit.Circuit, 3)
	type liveGeneration struct {
		intros [3]*circuit.Circuit
		timer  *time.Timer
	}
	generations := make(chan liveGeneration, 4)
	h.newIntroTimer = func() *time.Timer {
		g := liveGeneration{timer: time.NewTimer(2 * time.Hour)}
		for j := range g.intros {
			g.intros[j] = <-introBuilt
		}
		generations <- g
		return g.timer
	}
	h.build = func(ctx context.Context, s *directory.Snapshot, target *directory.Relay, p circuit.OnionPurpose) (*circuit.Circuit, error) {
		if target == nil {
			t.Error("missing target")
			return nil, circuit.ErrProtocol
		}
		c, err := circuit.BuildInternal(ctx, s, guards, target, p, h.options.BuildTimeout, h.channels)
		if err == nil && len(c.Path().Relays()) != 4 {
			t.Error("service circuit did not use four-relay Vanguards-Lite path")
		}
		if err == nil && p == circuit.OnionServiceIntroduction {
			introBuilt <- c
		}
		return c, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	directoryDone := make(chan error, 1)
	go func() { directoryDone <- manager.Run(ctx) }()
	defer func() { cancel(); <-directoryDone }()
	for {
		if _, err := manager.Snapshot(); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	done := make(chan error, 1)
	if listen {
		listener := startListener(ctx, h, onionAddr(name+":80"))
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
		go func() { done <- server.Serve(listener) }()
		defer func() { server.Close(); cancel(); <-listener.Done() }()
	} else {
		go func() { done <- h.Run(ctx) }()
	}
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("hosting workers leaked")
		}
	}()
	address := "http://" + name
	var data []byte
	for j := 0; j < 6; j++ {
		cmd := exec.CommandContext(ctx, "curl", "--fail", "--silent", "--show-error", "--max-time", "20", "--noproxy", "", "--socks5-hostname", os.Getenv("VEIL_TEST_HOST_SOCKS"), address)
		data, err = cmd.Output()
		if err == nil {
			break
		}
		t.Log("waiting for service publication/client bootstrap", err)
		select {
		case err := <-done:
			done <- err
			t.Fatal("host stopped", err)
		case <-time.After(time.Second):
		}
	}
	if err != nil || !bytes.Equal(data, []byte("Veil onion hosting works!\n")) {
		t.Fatal("onion HTTP failed", err, string(data))
	}
	// Exercise the native client's production four-relay HSDir/introduction
	// and three-relay rendezvous paths through the same independent Tor relays.
	native, err := client.New(ctx, manager, guards, client.Options{OnionOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	nativeConnections := make(chan net.Conn, 1)
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := native.DialContext(ctx, network, address)
		if err == nil {
			nativeConnections <- conn
		}
		return conn, err
	}, DisableKeepAlives: true}
	defer native.Close()
	nativeHTTP := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	response, nativeErr := nativeHTTP.Get(address + "/large")
	if nativeErr == nil {
		var body []byte
		body, nativeErr = io.ReadAll(response.Body)
		response.Body.Close()
		if nativeErr == nil && (response.StatusCode != 200 || !bytes.Equal(body, payload)) {
			nativeErr = errors.New("native onion response mismatch")
		}
	}
	transport.CloseIdleConnections()
	if nativeErr != nil {
		t.Fatal("native client through production onion paths", nativeErr)
	}
	rendezvousStats, ok := client.RendezvousPaddingForTest(<-nativeConnections)
	if !ok || !rendezvousStats.Negotiated || rendezvousStats.Rejected || rendezvousStats.Received != 1 || rendezvousStats.Sent > 1 {
		t.Fatalf("C Tor rendezvous padding missing: %+v", rendezvousStats)
	}
	t.Logf("C Tor rendezvous padding: %+v", rendezvousStats)
	// The HTTP stream has closed; the introduction must remain alive and finish
	// its independent C Tor padding exchange, not merely succeed at HTTP.
	paddingDeadline := time.Now().Add(3 * time.Second)
	for {
		stats := native.IntroductionPaddingForTest()
		if len(stats) == 1 && stats[0].Negotiated && stats[0].Stopped && !stats[0].Rejected && stats[0].Received >= 7 && stats[0].Received <= 10 && stats[0].Sent == 0 {
			t.Logf("C Tor introduction padding: %+v; circuit retained after HTTP close", stats[0])
			break
		}
		if time.Now().After(paddingDeadline) {
			t.Fatalf("C Tor introduction padding/retention missing: %+v", stats)
		}
		time.Sleep(10 * time.Millisecond)
	}
	clientChannels, clientLeases := native.ChannelPoolForTest()
	if clientChannels != 1 || clientLeases < 1 {
		t.Fatalf("native client did not share/retain guard TLS: %d channels, %d circuits", clientChannels, clientLeases)
	}
	hostChannels, hostLeases := h.channels.CountsForTest()
	if hostChannels != 1 || hostLeases < 3 {
		t.Fatalf("host did not share guard TLS: %d channels, %d circuits", hostChannels, hostLeases)
	}
	t.Logf("shared guard TLS: client %d channel/%d circuits, host %d channel/%d circuits", clientChannels, clientLeases, hostChannels, hostLeases)
	native.Close()
	t.Log("native client: four-relay HSDir/introduction, three-relay rendezvous, 2340000-byte response passed")
	cmd := exec.CommandContext(ctx, "curl", "--fail", "--silent", "--show-error", "--max-time", "30", "--noproxy", "", "--socks5-hostname", os.Getenv("VEIL_TEST_HOST_SOCKS"), address+"/large")
	data, err = cmd.Output()
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatal("bulk transfer failed", err, len(data))
	}
	var parallel sync.WaitGroup
	for j := 0; j < 4; j++ {
		parallel.Add(1)
		go func(j int) {
			defer parallel.Done()
			cmd := exec.CommandContext(ctx, "curl", "--fail", "--silent", "--show-error", "--max-time", "30", "--noproxy", "", "--socks5-hostname", os.Getenv("VEIL_TEST_HOST_SOCKS"), "--proxy-user", fmt.Sprintf("test:%d", j), address+"/large")
			got, err := cmd.Output()
			if err != nil || !bytes.Equal(got, payload) {
				t.Errorf("parallel transfer %d failed: %v, %d bytes", j, err, len(got))
			}
		}(j)
	}
	parallel.Wait()
	denied := exec.CommandContext(ctx, "curl", "--fail", "--silent", "--show-error", "--max-time", "10", "--noproxy", "", "--socks5-hostname", os.Getenv("VEIL_TEST_HOST_SOCKS"), address+":81/")
	if err := denied.Run(); err == nil {
		t.Fatal("unmapped virtual port accepted")
	}
	// Read real response bytes before changing generations, then resume the same
	// HTTP response after both timer rotation and a failed introduction circuit.
	// Curl has no retry option: reconnecting cannot make this assertion pass.
	held := exec.CommandContext(ctx, "curl", "--fail", "--silent", "--show-error", "--no-buffer", "--max-time", "60", "--noproxy", "", "--socks5-hostname", os.Getenv("VEIL_TEST_HOST_SOCKS"), address+"/held")
	output, err := held.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var heldErrors bytes.Buffer
	held.Stderr = &heldErrors
	if err := held.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Process.Kill(); _ = held.Wait() }()
	prefix := make([]byte, len("before rotation\n"))
	if _, err := io.ReadFull(output, prefix); err != nil || string(prefix) != "before rotation\n" {
		t.Fatal("could not start persistent transfer", err, string(prefix))
	}
	nextGeneration := func() liveGeneration {
		t.Helper()
		select {
		case g := <-generations:
			return g
		case <-time.After(30 * time.Second):
			t.Fatal("introduction replacement stalled while a stream was active")
			return liveGeneration{}
		}
	}
	retired := func(g liveGeneration) {
		t.Helper()
		for _, c := range g.intros {
			select {
			case <-c.Done():
			case <-time.After(10 * time.Second):
				t.Fatal("old introduction circuit did not close")
			}
		}
	}
	first := nextGeneration()
	select {
	case <-ready:
	case <-time.After(20 * time.Second):
		t.Fatal("initial descriptor publication incomplete")
	}
	blockPublication.Store(true)
	first.timer.Reset(0)
	second := nextGeneration()
	select {
	case <-publicationBlocked:
	case <-time.After(10 * time.Second):
		t.Fatal("replacement did not attempt publication")
	}
	for _, c := range first.intros {
		select {
		case <-c.Done():
			t.Fatal("cached introduction point closed before replacement publication")
		default:
		}
	}
	fetchNew := func(socks, scope string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "curl", "--fail", "--silent", "--show-error", "--max-time", "20", "--noproxy", "", "--socks5-hostname", socks, "--proxy-user", scope, address)
		got, err := cmd.Output()
		if err != nil || !bytes.Equal(got, []byte("Veil onion hosting works!\n")) {
			t.Fatal("new connection failed during introduction replacement", scope, err, string(got))
		}
	}
	// A new SOCKS isolation scope forces a fresh rendezvous. No replacement
	// descriptor has been uploaded: this connection must use the cached old one.
	fetchNew(os.Getenv("VEIL_TEST_HOST_SOCKS"), "rotation:cached")
	loseReply.Store(true)
	blockPublication.Store(false)
	close(publicationRelease)
	select {
	case <-failedPublication:
	case <-time.After(20 * time.Second):
		t.Fatal("lost publication replies were not reported")
	}
	loseReply.Store(false)
	// This second C Tor process has never requested the onion address, so it
	// discovers the replacement descriptor with an independent, empty cache.
	fetchNew(os.Getenv("VEIL_TEST_HOST_FRESH_SOCKS"), "rotation:fresh")
	if err := second.intros[0].Close(); err != nil {
		t.Fatal(err)
	}
	_ = nextGeneration()
	// Healthy points from the damaged generation still serve its cached
	// descriptor while a third generation is being published.
	fetchNew(os.Getenv("VEIL_TEST_HOST_FRESH_SOCKS"), "rotation:recovered")
	// Advance the retirement callbacks, separately from the rotation timers,
	// to check expiry cleanup without waiting for certificate expiration.
	for n := 0; n < 2; n++ {
		select {
		case timer := <-retirements:
			timer.Reset(0)
		case <-time.After(10 * time.Second):
			t.Fatal("advertised generation was not retained")
		}
	}
	retired(first)
	retired(second)
	// A send releases just this request; the deferred close also releases it if
	// the test fails, without leaking the HTTP fixture during cleanup.
	select {
	case resume <- struct{}{}:
	case <-time.After(5 * time.Second):
		t.Fatal("active transfer was canceled by introduction replacement")
	}
	tail, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := held.Wait(); err != nil || !bytes.Equal(tail, payload) {
		t.Fatalf("transfer did not survive rotation and intro failure: %v, %d bytes, %s", err, len(tail), heldErrors.String())
	}
	t.Log("new C Tor rendezvous succeeded with cached and fresh descriptors during replacement and lost upload replies; retained introductions closed at simulated expiry, and the original HTTP stream survived rotation and intro failure")
	t.Logf("C Tor client -> native Veil service: HTTP, five %d-byte downloads (four concurrent), and unmapped-port rejection passed", len(data))
}
