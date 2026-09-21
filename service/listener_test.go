package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"veil/directory"
)

type failingSnapshot struct{ err error }

func (s failingSnapshot) Snapshot() (*directory.Snapshot, error) { return nil, s.err }

func testListener(t *testing.T) (*Listener, context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h, err := newHost(&directory.Manager{}, &directory.GuardStore{}, &directory.ServiceIdentity{}, Options{Port: 80}, true)
	if err != nil {
		t.Fatal(err)
	}
	// Keep Run in its recoverable retry loop without touching the network.
	h.source = failingSnapshot{errors.New("directory unavailable")}
	l := startListener(ctx, h, "test.onion:80")
	t.Cleanup(func() { cancel(); waitListener(t, l.Done()) })
	return l, ctx, cancel
}

func waitListener(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("listener worker did not stop")
	}
}

type pipeRequest struct {
	net.Conn
	ready chan struct{}
}

func (r pipeRequest) Accept(context.Context) (net.Conn, error) {
	close(r.ready)
	return r.Conn, nil
}

func offerPipe(t *testing.T, l *Listener, ctx context.Context) (net.Conn, <-chan struct{}) {
	t.Helper()
	server, peer := net.Pipe()
	if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	ready, done := make(chan struct{}), make(chan struct{})
	go func() { defer close(done); l.serve(ctx, pipeRequest{server, ready}) }()
	// A concurrent Close may reject the request before its handshake.
	select {
	case <-ready:
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stream did not start")
	}
	return peer, done
}

func TestListenerCloseDrainsAcceptedStreams(t *testing.T) {
	l, ctx, _ := testListener(t)
	peer, served := offerPipe(t, l, ctx)
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.LocalAddr().String() != "test.onion:80" || l.Addr().Network() != "onion" {
		t.Fatal("incorrect onion address", c.LocalAddr(), l.Addr())
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	select {
	case <-l.Done():
		t.Fatal("Close stopped an accepted stream")
	default:
	}
	written := make(chan error, 1)
	go func() { _, err := peer.Write([]byte("alive")); written <- err }()
	b := make([]byte, 5)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "alive" {
		t.Fatal(err, string(b))
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	waitListener(t, served)
	waitListener(t, l.Done())
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestListenerCloseUnblocksAllAccepts(t *testing.T) {
	l, _, _ := testListener(t)
	var wg sync.WaitGroup
	for j := 0; j < 16; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		}()
	}
	l.Close()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	waitListener(t, done)
}

func TestListenerCloseRejectsPendingStreams(t *testing.T) {
	l, ctx, _ := testListener(t)
	peer, served := offerPipe(t, l, ctx)
	l.Close()
	waitListener(t, served)
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

type blockedRequest struct {
	started chan struct{}
	closed  chan struct{}
}

func (r blockedRequest) Accept(ctx context.Context) (net.Conn, error) {
	close(r.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (r blockedRequest) Close() error { close(r.closed); return nil }

func TestListenerCloseCancelsPendingHandshakeWhileDraining(t *testing.T) {
	l, ctx, _ := testListener(t)
	_, activeDone := offerPipe(t, l, ctx)
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := blockedRequest{make(chan struct{}), make(chan struct{})}
	go l.serve(ctx, r)
	waitListener(t, r.started)
	l.Close()
	waitListener(t, r.closed)
	select {
	case <-l.Done():
		t.Fatal("pending handshake cancellation stopped an accepted stream")
	default:
	}
	c.Close()
	waitListener(t, activeDone)
	waitListener(t, l.Done())
}

func TestListenerCircuitCancellationRejectsPendingStream(t *testing.T) {
	l, ctx, _ := testListener(t)
	circuitCtx, cancel := context.WithCancel(ctx)
	peer, served := offerPipe(t, l, circuitCtx)
	cancel()
	waitListener(t, served)
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	// The listener remains available for a stream from a replacement circuit.
	_, replacement := offerPipe(t, l, ctx)
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	waitListener(t, replacement)
}

func TestListenerCancellationClosesConnections(t *testing.T) {
	l, ctx, cancel := testListener(t)
	peer, served := offerPipe(t, l, ctx)
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cancel()
	waitListener(t, served)
	waitListener(t, l.Done())
	if _, err := l.Accept(); !errors.Is(err, context.Canceled) || !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestListenerConnectionDeadlines(t *testing.T) {
	l, ctx, _ := testListener(t)
	peer, served := offerPipe(t, l, ctx)
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = peer.Write([]byte{1}) }()
	if _, err := c.Read(make([]byte, 1)); err != nil {
		t.Fatal("deadline reset failed", err)
	}
	c.Close()
	waitListener(t, served)
}

func TestListenerHostFailure(t *testing.T) {
	cause := errors.New("identity persistence failed")
	h := &Host{source: failingSnapshot{&persistentError{cause}}}
	l := startListener(context.Background(), h, "test.onion:80")
	defer l.Close()
	waitListener(t, l.Done())
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) || !errors.Is(err, cause) {
		t.Fatal(err)
	}
}

func TestListenValidationAndAddress(t *testing.T) {
	m, g, i := &directory.Manager{}, &directory.GuardStore{}, &directory.ServiceIdentity{}
	for _, options := range []Options{{}, {Port: 80, Target: "127.0.0.1:8080"}, {Port: 80, MaxStreams: -1}, {Port: 80, MaxRendezvous: 65}} {
		if l, err := Listen(context.Background(), m, g, i, options); err == nil {
			l.Close()
			t.Fatal("invalid options accepted", options)
		}
	}
	if _, err := Listen(context.Background(), nil, g, i, Options{Port: 80}); err == nil {
		t.Fatal("nil manager accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Listen(ctx, m, g, i, Options{Port: 80}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// A real identity verifies Addr without starting a network connection.
	state := filepath.Join(t.TempDir(), "state")
	lock, err := directory.LockState(state)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	i, err = directory.OpenServiceIdentity(state)
	if err != nil {
		t.Fatal(err)
	}
	roots, sources, err := directory.Mainnet()
	if err != nil {
		t.Fatal(err)
	}
	cache, err := directory.NewCache(state, roots)
	if err != nil {
		t.Fatal(err)
	}
	g, err = directory.NewGuardStore(state)
	if err != nil {
		t.Fatal(err)
	}
	m, err = directory.NewManager(cache, g, sources, directory.ManagerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	name, err := i.Address()
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen(context.Background(), m, g, i, Options{Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	waitListener(t, l.Done())
	if l.Addr().String() != name+":8080" {
		t.Fatal(l.Addr())
	}
}

func TestListenerHTTPServer(t *testing.T) {
	l, ctx, _ := testListener(t)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "native onion listener") }), ReadHeaderTimeout: time.Second}
	served := make(chan error, 1)
	go func() { served <- server.Serve(l) }()
	defer server.Close()
	transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		peer, _ := offerPipe(t, l, ctx)
		return peer, nil
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get("http://test.onion/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "native onion listener" {
		t.Fatal(err, string(body))
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		t.Fatal(err)
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
	waitListener(t, l.Done())
}

func TestListenerAcceptCloseRace(t *testing.T) {
	for j := 0; j < 100; j++ {
		l, ctx, cancel := testListener(t)
		_, served := offerPipe(t, l, ctx)
		accepted := make(chan struct{})
		go func() {
			defer close(accepted)
			c, err := l.Accept()
			if err == nil {
				c.Close()
			} else if !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		}()
		go cancel()
		l.Close()
		waitListener(t, accepted)
		waitListener(t, served)
		waitListener(t, l.Done())
		l.mu.Lock()
		active := l.active
		l.mu.Unlock()
		if active != 0 {
			t.Fatal("leaked stream ownership", active)
		}
	}
}
