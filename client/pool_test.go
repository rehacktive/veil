package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"veil/circuit"
	"veil/directory"
	"veil/isolation"
)

type echoCircuit struct {
	mu           sync.Mutex
	peers        []net.Conn
	err, dialErr error
	opens        atomic.Int32
	closes       atomic.Int32
	once         sync.Once
}

func (c *echoCircuit) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	c.opens.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	if c.dialErr != nil {
		return nil, c.dialErr
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	a, b := net.Pipe()
	c.peers = append(c.peers, b)
	go func() { defer b.Close(); _, _ = io.Copy(b, b) }()
	return a, nil
}
func (c *echoCircuit) Close() error {
	c.once.Do(func() {
		c.closes.Add(1)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.err = net.ErrClosed
		for _, p := range c.peers {
			p.Close()
		}
	})
	return nil
}
func (c *echoCircuit) Err() error { c.mu.Lock(); defer c.mu.Unlock(); return c.err }

type poolFixture struct {
	mu       sync.Mutex
	circuits []*echoCircuit
	gate     <-chan struct{}
	started  chan struct{}
}

func (f *poolFixture) build(ctx context.Context, _ *directory.Snapshot, _ circuit.Options) (streamCircuit, error) {
	if f.started != nil {
		select {
		case f.started <- struct{}{}:
		default:
		}
	}
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c := &echoCircuit{}
	f.mu.Lock()
	f.circuits = append(f.circuits, c)
	f.mu.Unlock()
	return c, nil
}
func (f *poolFixture) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.circuits) }
func poolDialer(t *testing.T, o Options) (*Dialer, *poolFixture) {
	t.Helper()
	f := &poolFixture{}
	d, err := newDialer(context.Background(), source{}, o, f.build)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d, f
}
func connectPool(t *testing.T, d *Dialer, token, network, address string) net.Conn {
	t.Helper()
	c, err := d.DialContext(isolation.WithToken(context.Background(), token), network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func roundTrip(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() { _, err := c.Write(payload); done <- err }()
	got := make([]byte, len(payload))
	_, err := io.ReadFull(c, got)
	if err != nil || !bytes.Equal(got, payload) {
		t.Error("round trip", err)
	}
	if err := <-done; err != nil {
		t.Error(err)
	}
}
func TestPoolReuseIsolationAndRotation(t *testing.T) {
	d, f := poolDialer(t, Options{MaxPooledCircuits: 16})
	a := connectPool(t, d, "session-a", "tcp", "EXAMPLE.invalid:443")
	b := connectPool(t, d, "session-a", "tcp4", "example.invalid.:443")
	if f.count() != 1 {
		t.Fatal("same destination/scope was not shared", f.count())
	}
	a.Close()
	roundTrip(t, b, []byte("other stream survives close"))
	for _, tc := range []struct{ token, network, address string }{
		{"session-b", "tcp", "example.invalid:443"}, {"session-a", "tcp", "other.invalid:443"},
		{"session-a", "tcp", "example.invalid:80"}, {"session-a", "tcp6", "example.invalid:443"},
		{"", "tcp", "example.invalid:443"}, {"", "tcp", "example.invalid:443"},
	} {
		connectPool(t, d, tc.token, tc.network, tc.address).Close()
	}
	if f.count() != 7 {
		t.Fatal("crossed isolation boundary", f.count())
	}
	old := b.(*pooledConn).entry
	d.pool.mu.Lock()
	old.created = time.Now().Add(-11 * time.Minute)
	d.prunePool(time.Now())
	d.pool.mu.Unlock()
	fresh := connectPool(t, d, "session-a", "tcp", "example.invalid:443")
	if fresh.(*pooledConn).entry == old || old.c.(*attemptCircuit).streamCircuit.(*echoCircuit).closes.Load() != 0 {
		t.Fatal("rotation reused or killed active circuit")
	}
	roundTrip(t, b, []byte("download drains after rotation"))
	b.Close()
	if f.circuits[0].closes.Load() != 1 {
		t.Fatal("retired circuit not closed after drain")
	}
}
func TestPoolCoalescesParallelBuildsAndWaiterCancellation(t *testing.T) {
	d, f := poolDialer(t, Options{MaxCircuits: 32})
	gate := make(chan struct{})
	f.gate = gate
	f.started = make(chan struct{}, 32)
	results := make(chan net.Conn, 16)
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() {
			c, e := d.DialContext(isolation.WithToken(context.Background(), "same"), "tcp", "x.invalid:443")
			if e != nil {
				errs <- e
			} else {
				results <- c
			}
		}()
	}
	<-f.started
	ctx, cancel := context.WithTimeout(isolation.WithToken(context.Background(), "same"), 20*time.Millisecond)
	if _, err := d.DialContext(ctx, "tcp", "x.invalid:443"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	cancel()
	close(gate)
	var streams []net.Conn
	for i := 0; i < 16; i++ {
		select {
		case e := <-errs:
			t.Fatal(e)
		case c := <-results:
			streams = append(streams, c)
		case <-time.After(time.Second):
			t.Fatal("build wait stuck")
		}
	}
	if f.count() != 1 {
		t.Fatal("duplicate concurrent builds", f.count())
	}
	var wg sync.WaitGroup
	for i, c := range streams {
		wg.Add(1)
		go func(i int, c net.Conn) {
			defer wg.Done()
			defer c.Close()
			roundTrip(t, c, bytes.Repeat([]byte{byte(i)}, 256*1024))
		}(i, c)
	}
	wg.Wait()
	if len(d.slots) != 0 || f.circuits[0].closes.Load() != 0 {
		t.Fatal("slots leaked or reusable circuit closed")
	}
}
func TestPoolFailureDoesNotReplayOrKillOtherStreams(t *testing.T) {
	d, f := poolDialer(t, Options{})
	active := connectPool(t, d, "a", "tcp", "x.invalid:443")
	original := f.circuits[0]
	original.mu.Lock()
	original.dialErr = &circuit.StreamError{Reason: 5}
	original.mu.Unlock()
	if _, err := d.DialContext(isolation.WithToken(context.Background(), "a"), "tcp", "x.invalid:443"); err == nil {
		t.Fatal("expected stream failure")
	}
	if f.count() != 1 || original.opens.Load() != 2 {
		t.Fatal("replayed stream open")
	}
	roundTrip(t, active, []byte("active survives failed BEGIN"))
	connectPool(t, d, "a", "tcp", "x.invalid:443").Close()
	if f.count() != 2 {
		t.Fatal("failed circuit reused")
	}
	active.Close()
	if original.closes.Load() != 1 {
		t.Fatal("retired failure leaked")
	}
	// A known-dead cached circuit is discarded before a new BEGIN is attempted.
	dead := f.circuits[1]
	dead.Close()
	connectPool(t, d, "a", "tcp", "x.invalid:443").Close()
	if f.count() != 3 || dead.opens.Load() != 1 {
		t.Fatal("reused known dead circuit")
	}
}
func TestPoolBoundsIdleEvictionAndShutdown(t *testing.T) {
	d, f := poolDialer(t, Options{MaxPooledCircuits: 1, CircuitIdleTimeout: 30 * time.Millisecond})
	active := connectPool(t, d, "a", "tcp", "x.invalid:443")
	ctx, cancel := context.WithTimeout(isolation.WithToken(context.Background(), "b"), 20*time.Millisecond)
	if _, err := d.DialContext(ctx, "tcp", "x.invalid:443"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	cancel()
	if f.count() != 1 {
		t.Fatal("pool bound ignored")
	}
	active.Close()
	connectPool(t, d, "b", "tcp", "x.invalid:443").Close()
	if f.count() != 2 || f.circuits[0].closes.Load() != 1 {
		t.Fatal("idle eviction failed")
	}
	deadline := time.Now().Add(time.Second)
	for f.circuits[1].closes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.circuits[1].closes.Load() != 1 {
		t.Fatal("idle cleanup requires new requests")
	}
	c := connectPool(t, d, "a", "tcp", "x.invalid:443")
	d.Close()
	c.Close()
	d.Close()
	if f.circuits[2].closes.Load() != 1 || len(d.slots) != 0 {
		t.Fatal("shutdown leak")
	}
	if _, err := d.DialContext(isolation.WithToken(context.Background(), "a"), "tcp", "x.invalid:443"); err == nil {
		t.Fatal("dial after Close")
	}
}
func TestPoolCloseCancelsBuildAndDirectoryMustBeLive(t *testing.T) {
	d, f := poolDialer(t, Options{})
	gate := make(chan struct{})
	f.gate = gate
	f.started = make(chan struct{}, 1)
	result := make(chan error, 1)
	go func() {
		_, e := d.DialContext(isolation.WithToken(context.Background(), "a"), "tcp", "x.invalid:443")
		result <- e
	}()
	<-f.started
	d.Close()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	d2, f2 := poolDialer(t, Options{})
	connectPool(t, d2, "a", "tcp", "x.invalid:443").Close()
	d2.source = source{err: directory.ErrTime}
	if _, err := d2.DialContext(isolation.WithToken(context.Background(), "a"), "tcp", "x.invalid:443"); !errors.Is(err, directory.ErrTime) {
		t.Fatal(err)
	}
	if f2.circuits[0].opens.Load() != 1 {
		t.Fatal("BEGIN sent without live directory")
	}
}
func TestPoolCanBeDisabled(t *testing.T) {
	d, f := poolDialer(t, Options{DisableReuse: true})
	connectPool(t, d, "a", "tcp", "x.invalid:443").Close()
	connectPool(t, d, "a", "tcp", "x.invalid:443").Close()
	if f.count() != 2 || f.circuits[0].closes.Load() != 1 {
		t.Fatal("dedicated mode ignored")
	}
}

func TestPoolSustainedReconnects(t *testing.T) {
	d, f := poolDialer(t, Options{MaxPooledCircuits: 4})
	for i := 0; i < 200; i++ {
		token := string(rune('a' + i%4))
		c := connectPool(t, d, token, "tcp", "x.invalid:443")
		roundTrip(t, c, bytes.Repeat([]byte{byte(i)}, 4096))
		c.Close()
		if i%17 == 0 {
			c.(*pooledConn).entry.c.Close()
		}
		d.pool.mu.Lock()
		count := len(d.pool.entries)
		d.pool.mu.Unlock()
		if count > 4 || len(d.slots) != 0 {
			t.Fatal("sustained workload exceeded bounds", count, len(d.slots))
		}
	}
	if f.count() > 20 {
		t.Fatal("failed to reuse across requests", f.count())
	}
	d.Close()
	for _, c := range f.circuits {
		if c.closes.Load() != 1 {
			t.Fatal("circuit leaked")
		}
	}
}

func TestOnionPoolScopesAndPorts(t *testing.T) {
	const host = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
	d, f := poolDialer(t, Options{})
	d.build = func(context.Context, *directory.Snapshot, circuit.Options) (streamCircuit, error) {
		t.Error("onion sent to exit")
		return nil, errors.New("unexpected exit")
	}
	d.onionBuild = func(life, setup context.Context, host string, port uint16) (streamCircuit, error) {
		return f.build(life, nil, circuit.Options{})
	}
	a := connectPool(t, d, "a", "tcp", host+":80")
	b := connectPool(t, d, "a", "tcp4", host+":80")
	if a.(*pooledConn).entry != b.(*pooledConn).entry {
		t.Fatal("service circuit not reused")
	}
	connectPool(t, d, "b", "tcp", host+":80").Close()
	connectPool(t, d, "a", "tcp", host+":443").Close()
	if f.count() != 3 {
		t.Fatal("service scope or port crossed", f.count())
	}
}

func TestPooledSetupDeadlineDetachedAndDedicatedShutdown(t *testing.T) {
	d, _ := poolDialer(t, Options{ConnectTimeout: 30 * time.Millisecond})
	ctx, cancel := context.WithCancel(isolation.WithToken(context.Background(), "a"))
	c, err := d.DialContext(ctx, "tcp", "x.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cancel()
	select {
	case <-c.(*pooledConn).entry.life.Done():
		t.Fatal("caller cancellation killed pooled circuit")
	case <-time.After(50 * time.Millisecond):
	}
	roundTrip(t, c, []byte("established stream remains usable"))
	dedicated := connectPool(t, d, "", "tcp", "other.invalid:443")
	d.Close()
	if len(d.pool.dedicated) != 0 {
		t.Fatal("dedicated connection retained")
	}
	if _, err := dedicated.Write([]byte("closed")); err == nil {
		t.Fatal("dedicated circuit survived Close")
	}
}

type switchSource struct{ expired atomic.Bool }

func (s *switchSource) Snapshot() (*directory.Snapshot, error) {
	if s.expired.Load() {
		return nil, directory.ErrTime
	}
	return &directory.Snapshot{}, nil
}
func TestPoolRechecksDirectoryAfterBuildWait(t *testing.T) {
	d, f := poolDialer(t, Options{})
	src := &switchSource{}
	d.source = src
	gate := make(chan struct{})
	f.gate = gate
	f.started = make(chan struct{}, 1)
	result := make(chan error, 1)
	go func() {
		_, err := d.DialContext(isolation.WithToken(context.Background(), "a"), "tcp", "x.invalid:443")
		result <- err
	}()
	<-f.started
	src.expired.Store(true)
	close(gate)
	if err := <-result; !errors.Is(err, directory.ErrTime) {
		t.Fatal(err)
	}
	if f.circuits[0].opens.Load() != 0 || len(d.slots) != 0 {
		t.Fatal("BEGIN sent after directory expired")
	}
}
