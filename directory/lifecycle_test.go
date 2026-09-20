package directory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func manyGuards(count int) *Snapshot {
	s := pathFixture()
	base := s.relays[0]
	s.relays = nil
	s.consensus.params = map[string]int64{}
	for i := 1; i <= count; i++ {
		r := base
		r.status.rsa = Fingerprint{byte(i), byte(i >> 8)}
		r.descriptor.ed25519 = [32]byte{byte(i), byte(i >> 8)}
		r.status.address = netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 1}), 9001)
		s.relays = append(s.relays, r)
	}
	return s
}
func guardStore(t *testing.T) *GuardStore {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	g, err := NewGuardStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func TestGuardSamplingConfirmationRestart(t *testing.T) {
	s := manyGuards(200)
	g := guardStore(t)
	now := time.Now()
	a, err := g.Select(s, false, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.state.Sample) != 20 || len(g.primary) != 3 {
		t.Fatalf("sample %d primary %d", len(g.state.Sample), len(g.primary))
	}
	for _, r := range g.state.Sample {
		if r.Added.After(now) || r.Added.Before(now.Add(-12*24*time.Hour)) {
			t.Fatal("bad randomized age")
		}
	}
	if a.Usability(now) != GuardWaiting {
		t.Fatal("unbuilt circuit usable")
	}
	id := a.Relay().Identity()
	if err := a.Success(now); err != nil {
		t.Fatal(err)
	}
	if a.Usability(now) != GuardUsable {
		t.Fatal("primary not usable")
	}
	a.Close()
	again, err := g.Select(s, false, nil, now)
	if err != nil || again.Relay().Identity() != id {
		t.Fatal("confirmed guard not preferred", err)
	}
	again.Close()
	restarted, err := NewGuardStore(g.path)
	if err != nil {
		t.Fatal(err)
	}
	a, err = restarted.Select(s, false, nil, now)
	if err != nil || a.Relay().Identity() != id {
		t.Fatal("confirmation lost", err)
	}
	a.Close()
	if restarted.record(id).Confirmed.IsZero() {
		t.Fatal("confirmation not persisted")
	}
	// Transient failures grow only the bounded sample; they never erase it.
	originals := append([]guardRecord(nil), restarted.state.Sample...)
	for i := 0; i < 100; i++ {
		a, err := restarted.Select(s, false, nil, now)
		if errors.Is(err, ErrPath) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Failure(now, false); err != nil {
			t.Fatal(err)
		}
	}
	if len(restarted.state.Sample) > 40 {
		t.Fatal("sample cap exceeded")
	}
	for _, r := range originals {
		if restarted.record(r.RSA) == nil {
			t.Fatal("failure erased guard")
		}
	}
}
func TestGuardDirectoryFailureCancellationAndRecovery(t *testing.T) {
	s := manyGuards(6)
	g := guardStore(t)
	now := time.Now()
	a, err := g.Select(s, true, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	id := a.Relay().Identity()
	if err := a.Success(now); err != nil {
		t.Fatal(err)
	}
	if err := a.Failure(now, true); err != nil {
		t.Fatal(err)
	}
	if g.reachable(id, true, now) || !g.reachable(id, false, now) {
		t.Fatal("directory failure poisoned data reachability")
	}
	retry := g.rt(id).directory.retryAt
	if retry.Before(now.Add(time.Minute)) || retry.After(now.Add(6*time.Hour)) {
		t.Fatal("retry bounds")
	}
	if !g.reachable(id, true, retry) {
		t.Fatal("guard did not recover")
	}
	data, err := g.Select(s, false, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	data.Close()
	if g.rt(data.Relay().Identity()).connection.no {
		t.Fatal("cancellation penalized guard")
	}
	if err := data.Success(now); err == nil {
		t.Fatal("accepted stale outcome")
	}
	// Restrictions cannot change the persistent sample.
	before := len(g.state.Sample)
	var blocked []Fingerprint
	for _, r := range g.state.Sample {
		blocked = append(blocked, r.RSA)
	}
	if _, err := g.Select(s, false, blocked, now); !errors.Is(err, ErrPath) {
		t.Fatal(err)
	}
	if len(g.state.Sample) != before {
		t.Fatal("restriction grew sample")
	}
}
func TestGuardNonprimaryWaitAndTimeout(t *testing.T) {
	s := manyGuards(5)
	g := guardStore(t)
	now := time.Now()
	if _, err := g.Guard(s, now); err != nil {
		t.Fatal(err)
	}
	// Confirm all existing primary guards so a fourth success cannot displace
	// them immediately, then force the primary connection attempts to fail.
	primary := append([]Fingerprint(nil), g.primary...)
	for _, id := range primary {
		var exclude []Fingerprint
		for _, r := range s.relays {
			if r.Identity() != id {
				exclude = append(exclude, r.Identity())
			}
		}
		a, err := g.Select(s, false, exclude, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Success(now); err != nil {
			t.Fatal(err)
		}
		a.Close()
	}
	for _, id := range primary {
		g.rt(id).connection = reachability{no: true, retryAt: now.Add(time.Hour)}
	}
	g.lastInternet = time.Time{}
	a, err := g.Select(s, false, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if a.primaryAtSelection {
		t.Fatal("expected nonprimary")
	}
	if err := a.Success(now); err != nil {
		t.Fatal(err)
	}
	if a.Usability(now) != GuardWaiting {
		t.Fatal("did not retry primary after outage")
	}
	if a.Usability(now.Add(10*time.Minute)) != GuardUnusable {
		t.Fatal("waiting circuit did not time out")
	}
	for _, id := range primary {
		g.rt(id).connection = reachability{no: true, retryAt: now.Add(time.Hour)}
	}
	if a.Usability(now.Add(time.Second)) != GuardUsable {
		t.Fatal("nonprimary blocked after all preferred guards failed")
	}
	a.Close()
}
func TestGuardExpiryMigrationAndCorruption(t *testing.T) {
	now := time.Now()
	s := manyGuards(1)
	g := guardStore(t)
	id := s.relays[0].Identity()
	legacy := fmt.Sprintf(`{"Version":1,"RSA":%s,"Ed25519":%s}`, jsonBytes(id), jsonBytes(s.relays[0].descriptor.ed25519))
	if err := os.WriteFile(g.path+"/guard.json", []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Guard(s, now); err != nil {
		t.Fatal(err)
	}
	if len(g.state.Sample) != 1 || g.state.Sample[0].RSA != id || !g.state.Sample[0].Confirmed.IsZero() {
		t.Fatal("legacy guard not preserved as unconfirmed")
	}
	b, _ := os.ReadFile(g.path + "/guard.json")
	if !bytes.Contains(b, []byte(`"Version":2`)) {
		t.Fatal("migration not saved")
	}
	// A new live consensus can mark a guard absent, but not delete it immediately.
	empty := *s
	c := *s.consensus
	c.validAfter = now
	c.freshUntil = now.Add(time.Hour)
	c.validUntil = now.Add(2 * time.Hour)
	empty.consensus = &c
	empty.relays = nil
	g.mu.Lock()
	err := g.update(&empty, now, false)
	g.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if g.record(id) == nil || g.record(id).Listed {
		t.Fatal("unlisted guard was discarded")
	}
	later := now.Add(21 * 24 * time.Hour)
	c.validAfter = later
	c.freshUntil = later.Add(time.Hour)
	c.validUntil = later.Add(2 * time.Hour)
	g.mu.Lock()
	err = g.update(&empty, later, false)
	g.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if g.record(id) != nil {
		t.Fatal("unlisted guard did not expire")
	}
	if err := os.WriteFile(g.path+"/guard.json", []byte(`{"Version":9}`), 0600); err != nil {
		t.Fatal(err)
	}
	broken, _ := NewGuardStore(g.path)
	if _, err := broken.Guard(s, now); err == nil {
		t.Fatal("corruption accepted")
	}
}
func jsonBytes(v any) string { b, _ := json.Marshal(v); return string(b) }
func TestGuardClockAndExpiredDirectory(t *testing.T) {
	s := manyGuards(3)
	now := time.Now()
	g := guardStore(t)
	if _, err := g.Guard(s, now); err != nil {
		t.Fatal(err)
	}
	expired := s.consensus.validUntil.Add(time.Minute)
	if _, err := g.Select(s, false, nil, expired); !errors.Is(err, ErrTime) {
		t.Fatal("expired application guard accepted", err)
	}
	a, err := g.Select(s, true, nil, expired)
	if err != nil {
		t.Fatal("recent directory recovery failed", err)
	}
	a.Close()
	if _, err := g.Select(s, true, nil, s.consensus.validUntil.Add(24*time.Hour)); !errors.Is(err, ErrTime) {
		t.Fatal("old directory accepted", err)
	}
	if _, err := g.Select(s, false, nil, s.consensus.validAfter.Add(-time.Second)); !errors.Is(err, ErrTime) {
		t.Fatal("backward clock accepted", err)
	}
}
func TestRefreshAndRetryTiming(t *testing.T) {
	s := pathFixture()
	c := s.consensus
	c.validAfter = time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	c.freshUntil = c.validAfter.Add(time.Hour)
	c.validUntil = c.validAfter.Add(3 * time.Hour)
	for i := 0; i < 100; i++ {
		at, err := RefreshTime(s)
		if err != nil {
			t.Fatal(err)
		}
		if at.Before(c.validAfter.Add(105*time.Minute)) || !at.Before(c.validAfter.Add(170*time.Minute+37*time.Second+500*time.Millisecond)) {
			t.Fatal(at)
		}
	}
	var delay time.Duration
	for i := 0; i < 100; i++ {
		next, err := retryDelay(delay, 30*time.Second, 6*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if next < 30*time.Second || next > 6*time.Hour || next >= max(31*time.Second, delay*3) {
			t.Fatal(next, delay)
		}
		delay = next
	}
}

type testClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *testClock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *testClock) advance(d time.Duration) { c.mu.Lock(); c.at = c.at.Add(d); c.mu.Unlock() }
func (c *testClock) wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.advance(max(d, 0))
	return nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

type sourceFunc func(context.Context, string, int) ([]byte, error)

func (f sourceFunc) Fetch(ctx context.Context, p string, n int) ([]byte, error) { return f(ctx, p, n) }
func testManager(t *testing.T, d Documents, roots []Fingerprint, now time.Time) (*Manager, *testClock) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	cache, err := NewCache(dir, roots)
	if err != nil {
		t.Fatal(err)
	}
	guards, err := NewGuardStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	fallback := TorSource{OnionKey: [32]byte{1}}
	fallback.Target.Address = netip.MustParseAddrPort("127.0.0.1:1")
	fallback.Target.Identity.RSA = [20]byte{1}
	fallback.Target.Identity.Ed25519 = [32]byte{1}
	m, err := NewManager(cache, guards, []TorSource{fallback}, ManagerOptions{Attempts: 3})
	if err != nil {
		t.Fatal(err)
	}
	clock := &testClock{at: now}
	m.now = clock.now
	m.wait = clock.wait
	m.factory = func(ctx context.Context, _ TorSource, a *GuardAttempt) (Source, io.Closer) {
		f := &fixtureSource{d: d}
		return sourceFunc(func(ctx context.Context, p string, n int) ([]byte, error) {
			if a != nil && !a.succeeded {
				if err := a.Success(clock.now()); err != nil {
					return nil, err
				}
			}
			return f.Fetch(ctx, p, n)
		}), closerFunc(func() error { return nil })
	}
	return m, clock
}
func TestManagerRetriesRetainsSnapshotAndReusesDescriptors(t *testing.T) {
	d, roots, now := fixture(t)
	m, clock := testManager(t, d, roots, now)
	calls, closed, attempts := 0, 0, 0
	m.factory = func(ctx context.Context, _ TorSource, a *GuardAttempt) (Source, io.Closer) {
		attempts++
		f := &fixtureSource{d: d}
		fail := attempts <= 2
		return sourceFunc(func(ctx context.Context, p string, n int) ([]byte, error) {
			calls++
			if fail {
				return nil, io.ErrUnexpectedEOF
			}
			if a != nil && !a.succeeded {
				if err := a.Success(clock.now()); err != nil {
					return nil, err
				}
			}
			return f.Fetch(ctx, p, n)
		}), closerFunc(func() error { closed++; return nil })
	}
	if _, err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || closed != 3 || calls != 5 {
		t.Fatalf("attempts %d closed %d calls %d", attempts, closed, calls)
	}
	before := calls
	if _, err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls-before != 2 {
		t.Fatal("unchanged descriptors downloaded again")
	}
	m.factory = func(context.Context, TorSource, *GuardAttempt) (Source, io.Closer) {
		return sourceFunc(func(context.Context, string, int) ([]byte, error) { return nil, io.ErrUnexpectedEOF }), closerFunc(func() error { return nil })
	}
	if _, err := m.Refresh(context.Background()); err == nil {
		t.Fatal("outage accepted")
	}
	if _, err := m.Snapshot(); err != nil {
		t.Fatal("live snapshot discarded", err)
	}
	clock.advance(time.Hour)
	if _, err := m.Snapshot(); !errors.Is(err, ErrTime) {
		t.Fatal("expired snapshot exposed", err)
	}
}

func TestManagerCleanupFailureStopsPublication(t *testing.T) {
	d, roots, now := fixture(t)
	m, _ := testManager(t, d, roots, now)
	failed := errors.New("transport close failed")
	calls := 0
	m.factory = func(context.Context, TorSource, *GuardAttempt) (Source, io.Closer) {
		calls++
		return &fixtureSource{d: d}, closerFunc(func() error { return failed })
	}
	if _, err := m.Refresh(context.Background()); !errors.Is(err, failed) || !errors.Is(err, ErrState) {
		t.Fatal("cleanup failure lost", err)
	}
	if calls != 1 {
		t.Fatal("retried a local cleanup failure", calls)
	}
	if _, err := m.Snapshot(); err == nil {
		t.Fatal("published after cleanup failure")
	}
	if _, err := os.Stat(m.cache.path + "/directory.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("persisted after cleanup failure", err)
	}
}
func TestManagerRestartAndRunSchedule(t *testing.T) {
	d, roots, now := fixture(t)
	m, clock := testManager(t, d, roots, now)
	if _, err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(m.cache, guardStoreAt(t, m.guards.path), m.fallbacks, ManagerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = clock.now
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waits := 0
	restarted.wait = func(ctx context.Context, delay time.Duration) error {
		waits++
		if delay <= 0 {
			t.Fatal("restart did not honor refresh window")
		}
		cancel()
		return ctx.Err()
	}
	restarted.factory = func(context.Context, TorSource, *GuardAttempt) (Source, io.Closer) {
		t.Fatal("download before refresh window")
		return nil, nil
	}
	if err := restarted.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if waits != 1 {
		t.Fatal(waits)
	}
	if _, err := restarted.Snapshot(); err != nil {
		t.Fatal(err)
	}
}
func guardStoreAt(t *testing.T, path string) *GuardStore {
	t.Helper()
	g, err := NewGuardStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func TestManagerVerificationFailsClosedAndCancel(t *testing.T) {
	d, roots, now := fixture(t)
	m, clock := testManager(t, d, roots, now)
	if _, err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	forged := d
	forged.Consensus = bytes.Replace(d.Consensus, []byte("Bandwidth=208"), []byte("Bandwidth=209"), 1)
	count := 0
	m.factory = func(context.Context, TorSource, *GuardAttempt) (Source, io.Closer) {
		count++
		return &fixtureSource{d: forged}, closerFunc(func() error { return nil })
	}
	if _, err := m.Refresh(context.Background()); !errors.Is(err, ErrTrust) {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("retried invalid signatures")
	}
	if _, err := m.Snapshot(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	count = 0
	if _, err := m.Refresh(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("request after cancellation")
	}
	clock.advance(-time.Hour)
	if _, err := m.Snapshot(); !errors.Is(err, ErrTime) {
		t.Fatal("backward clock bypassed validity")
	}
}
func TestBootstrapPerRequestDigestBinding(t *testing.T) {
	d, roots, now := fixture(t)
	parts, _ := splitMicrodescriptors(d.Microdescriptors, MaxMicrodescriptorBatch)
	previous := Documents{Microdescriptors: bytes.Join(parts[1:], nil)}
	source := &fixtureSource{d: d} // returns already-cached, unrequested descriptors too
	if _, _, err := bootstrap(context.Background(), source, roots, now, previous); !errors.Is(err, ErrTrust) {
		t.Fatal("accepted unrequested descriptors", err)
	}
	source.d.Microdescriptors = parts[0]
	if _, _, err := bootstrap(context.Background(), source, roots, now, previous); err != nil {
		t.Fatal(err)
	}
	if len(source.requests) < 3 || !strings.HasPrefix(source.requests[2], "/tor/micro/d/") {
		t.Fatal(source.requests)
	}
}

func TestManagerRecoversRecentlyExpiredDirectory(t *testing.T) {
	d, roots, now, sign := signedFixture(t)
	m, clock := testManager(t, d, roots, now)
	if _, err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Minute)
	if _, err := m.Snapshot(); !errors.Is(err, ErrTime) {
		t.Fatal("expired directory exposed", err)
	}
	base := d.Consensus[:bytes.Index(d.Consensus, []byte("directory-signature "))]
	newer := d
	newer.Consensus = sign(bytes.ReplaceAll(bytes.ReplaceAll(base, []byte("valid-until 2000-01-01 00:03:00"), []byte("valid-until 2000-01-01 00:04:00")), []byte("00:02:"), []byte("00:03:")))
	guarded := false
	m.factory = func(ctx context.Context, _ TorSource, a *GuardAttempt) (Source, io.Closer) {
		if a != nil {
			guarded = true
			if err := a.Success(clock.now()); err != nil {
				t.Fatal(err)
			}
		}
		return &fixtureSource{d: newer}, closerFunc(func() error { return nil })
	}
	if _, err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !guarded {
		t.Fatal("recovery bypassed persisted guards")
	}
	s, err := m.Snapshot()
	if err != nil || !s.Info().ValidAfter.Equal(now.Add(50*time.Second)) {
		t.Fatal(s.Info(), err)
	}
}
func TestGuardPersistenceFailureStopsSelection(t *testing.T) {
	s := manyGuards(4)
	g := guardStore(t)
	now := time.Now()
	a, err := g.Select(s, false, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	// Replacing the destination with a directory makes atomic rename fail on
	// every platform, even when the tests run with elevated filesystem access.
	if err := os.Remove(g.path + "/guard.json"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(g.path+"/guard.json", 0700); err != nil {
		t.Fatal(err)
	}
	if err := a.Success(now); err == nil {
		t.Fatal("ignored persistence failure")
	}
	if a.Usability(now) != GuardUnusable {
		t.Fatal("used unpersisted confirmation")
	}
	if _, err := g.Select(s, false, nil, now); err == nil {
		t.Fatal("continued after state write failure")
	}
	a.Close()
}
func TestManagerCancellationDoesNotPenalizeGuard(t *testing.T) {
	d, roots, now := fixture(t)
	m, _ := testManager(t, d, roots, now)
	if _, err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var attempted Fingerprint
	m.factory = func(_ context.Context, _ TorSource, a *GuardAttempt) (Source, io.Closer) {
		if a == nil {
			t.Fatal("expected directory guard")
		}
		attempted = a.Relay().Identity()
		return sourceFunc(func(ctx context.Context, _ string, _ int) ([]byte, error) {
			cancel()
			<-ctx.Done()
			return nil, ctx.Err()
		}), closerFunc(func() error { return nil })
	}
	if _, err := m.Refresh(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if m.guards.rt(attempted).connection.no || m.guards.rt(attempted).directory.no || len(m.guards.attempts) != 0 {
		t.Fatal("cancellation penalized or leaked guard attempt")
	}
}
func TestGuardConfirmedLifetimeAndPendingExpiry(t *testing.T) {
	s := manyGuards(4)
	g := guardStore(t)
	now := time.Now()
	a, err := g.Select(s, false, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Success(now); err != nil {
		t.Fatal(err)
	}
	id := a.Relay().Identity()
	confirmed := g.record(id).Confirmed
	future := confirmed.Add(60*24*time.Hour + time.Second)
	next := *s
	c := *s.consensus
	c.validAfter = future
	c.freshUntil = future.Add(time.Hour)
	c.validUntil = future.Add(2 * time.Hour)
	next.consensus = &c
	if _, err := g.Guard(&next, future); err != nil {
		t.Fatal(err)
	}
	if a.Usability(future) != GuardUnusable {
		t.Fatal("expired guard attempt still usable")
	}
	if r := g.record(id); r != nil && !r.Confirmed.IsZero() {
		t.Fatal("confirmation did not expire")
	}
	a.Close()
}
