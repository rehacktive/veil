package directory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// ManagerOptions bounds retries and I/O. The zero value supplies defaults.
type ManagerOptions struct {
	Attempts            int           // Per Refresh call, default 4, at most 16.
	AttemptTimeout      time.Duration // Whole download attempt, default 2 minutes.
	RetryBase, RetryCap time.Duration // Defaults 1 second and 5 minutes.
}
type ManagerStatus struct {
	Phase                 string    `json:"phase,omitempty"`
	DownloadRequests      int       `json:"download_requests,omitempty"`
	DownloadBytes         int64     `json:"download_bytes,omitempty"`
	Microdescriptors      int       `json:"microdescriptors,omitempty"`
	MicrodescriptorsTotal int       `json:"microdescriptors_total,omitempty"`
	Directory             Info      `json:"directory"`
	Live                  bool      `json:"live"`
	NextAttempt           time.Time `json:"next_attempt"`
	Failures              int       `json:"failures"`
	LastError             string    `json:"last_error,omitempty"`
}

// BootstrapProgress is a UI-safe snapshot. Progress is indeterminate while
// fetching certificates and the consensus; once the signed consensus is
// verified, descriptor counts provide an exact determinate download progress.
// Ready becomes true only after the complete directory is verified and stored.
type BootstrapProgress struct {
	Phase       string `json:"phase"`
	Completed   int    `json:"completed"`
	Total       int    `json:"total"`
	Percent     int    `json:"percent"`
	Determinate bool   `json:"determinate"`
	Ready       bool   `json:"ready"`
}

func (s ManagerStatus) BootstrapProgress() BootstrapProgress {
	p := BootstrapProgress{Phase: s.Phase, Completed: s.Microdescriptors, Total: s.MicrodescriptorsTotal, Ready: s.Live}
	if p.Ready {
		p.Phase = "ready"
		p.Determinate = true
		p.Percent = 100
		return p
	}
	if p.Phase == "" {
		p.Phase = "starting"
	}
	if p.Total > 0 {
		p.Determinate = true
		p.Completed = max(0, min(p.Completed, p.Total))
		p.Percent = p.Completed * 100 / p.Total
	}
	return p
}

// Manager owns the directory lifecycle. Run refreshes until canceled; Refresh
// performs one bounded round. Snapshot rejects expired data even during outages.
// All network requests go through the pinned bootstrap source initially, then
// through the sampled guard set. Corrupt state or verification failure fails
// closed. Use one manager/guard/cache owner per state directory.
type Manager struct {
	cache     *Cache
	guards    *GuardStore
	fallbacks []TorSource
	options   ManagerOptions
	gate      chan struct{}
	runGate   chan struct{}
	mu        sync.RWMutex
	current   *Snapshot
	docs      Documents
	restored  bool
	status    ManagerStatus
	delay     time.Duration
	now       func() time.Time
	wait      func(context.Context, time.Duration) error
	factory   func(context.Context, TorSource, *GuardAttempt) (Source, io.Closer)
}

func NewManager(cache *Cache, guards *GuardStore, fallbacks []TorSource, options ManagerOptions) (*Manager, error) {
	if cache == nil || guards == nil || len(fallbacks) == 0 || len(fallbacks) > 64 {
		return nil, errors.New("cache, guard store, and 1 to 64 explicit bootstrap relays are required")
	}
	if options.Attempts == 0 {
		options.Attempts = 4
	}
	if options.AttemptTimeout == 0 {
		options.AttemptTimeout = 2 * time.Minute
	}
	if options.RetryBase == 0 {
		options.RetryBase = time.Second
	}
	if options.RetryCap == 0 {
		options.RetryCap = 5 * time.Minute
	}
	if options.Attempts < 1 || options.Attempts > 16 || options.AttemptTimeout < 0 || options.RetryBase < time.Second || options.RetryCap < options.RetryBase || options.RetryCap > 24*time.Hour {
		return nil, errors.New("invalid directory manager retry limits")
	}
	for _, s := range fallbacks {
		if !s.Target.Address.IsValid() || s.Target.Address.Port() == 0 || s.Target.Address.Addr().Zone() != "" || s.Target.Identity.RSA == ([20]byte{}) || s.Target.Identity.Ed25519 == ([32]byte{}) || (s.OnionKey == ([32]byte{})) != s.DirectoryOnlyFast || s.Timeout < 0 {
			return nil, errors.New("bootstrap relay requires an address, both identity pins, and either an ntor key or directory-only CREATE_FAST")
		}
	}
	m := &Manager{cache: cache, guards: guards, fallbacks: append([]TorSource(nil), fallbacks...), options: options, gate: make(chan struct{}, 1), runGate: make(chan struct{}, 1), now: time.Now, wait: waitContext}
	m.factory = func(ctx context.Context, source TorSource, attempt *GuardAttempt) (Source, io.Closer) {
		session := source.Open(ctx)
		if attempt != nil {
			reported := false
			session.onCircuit = func(ctx context.Context) error {
				if !reported {
					if err := attempt.Success(m.now()); err != nil {
						return err
					}
					reported = true
				}
				if attempt.Usability(m.now()) != GuardUsable {
					return ErrGuardWaiting
				}
				return nil
			}
		}
		return session, session
	}
	return m, nil
}
func waitContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(max(d, 0))
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (m *Manager) Snapshot() (*Snapshot, error) {
	m.mu.RLock()
	s := m.current
	m.mu.RUnlock()
	if !s.Valid(m.now()) {
		return nil, ErrTime
	}
	return s, nil
}
func (m *Manager) Status() ManagerStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.status
	s.Directory = m.current.Info()
	s.Live = m.current.Valid(m.now())
	return s
}

// BootstrapProgress returns a lock-safe snapshot suitable for polling from a
// client UI. Callers should treat Determinate=false as an indeterminate phase.
func (m *Manager) BootstrapProgress() BootstrapProgress {
	return m.Status().BootstrapProgress()
}
func (m *Manager) restore() error {
	if m.restored {
		return nil
	}
	s, d, err := m.cache.restore(m.now())
	if errors.Is(err, os.ErrNotExist) {
		m.restored = true
		return nil
	}
	if err != nil {
		return err
	}
	m.guards.mu.Lock()
	err = m.guards.update(s, m.now(), true)
	m.guards.mu.Unlock()
	if err != nil {
		return err
	}
	next, err := RefreshTime(s)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.current = s
	m.docs = d
	m.status.NextAttempt = next
	m.mu.Unlock()
	m.restored = true
	return nil
}
func (m *Manager) source(attemptNumber int) (TorSource, *GuardAttempt, error) {
	m.mu.RLock()
	s := m.current
	m.mu.RUnlock()
	m.guards.mu.Lock()
	err := m.guards.load(m.now())
	hasSample := len(m.guards.state.Sample) > 0
	m.guards.mu.Unlock()
	if err != nil {
		return TorSource{}, nil, err
	}
	if hasSample {
		a, err := m.guards.Select(s, true, nil, m.now())
		if err != nil {
			return TorSource{}, nil, err
		}
		r := a.Relay()
		return TorSource{Target: r.Target(), OnionKey: r.NTor().OnionKey}, a, nil
	}
	index, err := randomDuration(time.Duration(len(m.fallbacks)))
	if err != nil {
		return TorSource{}, nil, err
	}
	return m.fallbacks[(int(index)+attemptNumber)%len(m.fallbacks)], nil, nil
}

var ErrState = errors.New("directory state could not be persisted")

func permanent(err error) bool {
	return errors.Is(err, ErrState) || errors.Is(err, ErrTrust) || errors.Is(err, ErrDocument) || errors.Is(err, ErrUnsupported) || errors.Is(err, ErrTime)
}
func (m *Manager) failed(err error) error {
	delay, e := retryDelay(m.delay, m.options.RetryBase, m.options.RetryCap)
	if e != nil {
		return e
	}
	m.delay = delay
	m.mu.Lock()
	m.status.Phase = "retry"
	m.status.Failures++
	m.status.LastError = err.Error()
	m.status.NextAttempt = m.now().Add(delay)
	m.mu.Unlock()
	return nil
}

// Refresh retains the last valid snapshot on failure, but never publishes an
// unverified replacement. Cancellation does not penalize a guard.
func (m *Manager) Refresh(ctx context.Context) (*Snapshot, error) {
	select {
	case m.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-m.gate }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := m.restore(); err != nil {
		return nil, err
	}
	var last error
	for i := 0; i < m.options.Attempts; i++ {
		if i > 0 {
			if err := m.wait(ctx, m.Status().NextAttempt.Sub(m.now())); err != nil {
				return nil, err
			}
		}
		source, guard, err := m.source(i)
		if err == nil {
			attemptCtx, cancel := context.WithTimeout(ctx, m.options.AttemptTimeout)
			fetcher, closer := m.factory(attemptCtx, source, guard)
			m.mu.RLock()
			previous := m.docs
			m.mu.RUnlock()
			var s *Snapshot
			var docs Documents
			m.mu.Lock()
			m.status.DownloadRequests = 0
			m.status.DownloadBytes = 0
			m.status.Microdescriptors = 0
			m.status.MicrodescriptorsTotal = 0
			m.mu.Unlock()
			s, docs, err = bootstrap(attemptCtx, progressSource{Source: fetcher, manager: m}, m.cache.roots, m.now(), previous)
			closeErr := closer.Close()
			cancel()
			if closeErr != nil {
				if guard != nil {
					guard.Close()
				}
				// Cleanup failure is local state failure, not guard reachability.
				return nil, errors.Join(err, fmt.Errorf("%w: directory session cleanup: %w", ErrState, closeErr))
			}
			if guard != nil {
				if err != nil && ctx.Err() == nil && !errors.Is(err, ErrGuardWaiting) {
					var request *RequestError
					directoryOnly := errors.As(err, &request) && request.Authenticated || permanent(err)
					if e := guard.Failure(m.now(), directoryOnly); e != nil {
						guard.Close()
						return nil, e
					}
				}
				guard.Close()
			}
			if err == nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				m.mu.Lock()
				m.status.Phase = "cache"
				m.mu.Unlock()
				s, err = m.cache.Store(docs, m.now())
				if err != nil {
					return nil, fmt.Errorf("%w: %v", ErrState, err)
				}
				m.guards.mu.Lock()
				err = m.guards.update(s, m.now(), false)
				m.guards.mu.Unlock()
				if err != nil {
					return nil, err
				}
				next, e := RefreshTime(s)
				if e != nil {
					return nil, e
				}
				if !next.After(m.now()) {
					delay, e := retryDelay(m.delay, m.options.RetryBase, m.options.RetryCap)
					if e != nil {
						return nil, e
					}
					m.delay = delay
					next = m.now().Add(delay)
				} else {
					m.delay = 0
				}
				m.mu.Lock()
				completed := m.status.Microdescriptors
				total := m.status.MicrodescriptorsTotal
				m.current = s
				m.docs = docs
				m.status = ManagerStatus{NextAttempt: next, Microdescriptors: completed, MicrodescriptorsTotal: total}
				m.mu.Unlock()
				return s, nil
			}
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		last = err
		if e := m.failed(err); e != nil {
			return nil, e
		}
		if permanent(err) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("directory refresh failed after %d attempts: %w", m.options.Attempts, last)
}

// Run restores valid cached state without a startup download, then follows the
// randomized refresh schedule. Only one Run may be active. Verification/state
// errors stop the loop; transient network outages retry with capped jitter.
func (m *Manager) Run(ctx context.Context) error {
	select {
	case m.runGate <- struct{}{}:
	default:
		return errors.New("directory manager is already running")
	}
	defer func() { <-m.runGate }()
	select {
	case m.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	err := m.restore()
	<-m.gate
	if err != nil {
		return err
	}
	for {
		status := m.Status()
		if !status.NextAttempt.IsZero() {
			if err := m.wait(ctx, status.NextAttempt.Sub(m.now())); err != nil {
				return err
			}
		}
		_, err := m.Refresh(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil && (permanent(err) || m.guards.poisonedError() != nil) {
			return err
		}
		// Persistence errors must not turn into a hot retry loop.
		if err != nil && m.Status().NextAttempt.Equal(status.NextAttempt) {
			return err
		}
	}
}
func (g *GuardStore) poisonedError() error { g.mu.Lock(); defer g.mu.Unlock(); return g.poisoned }

// Only coarse progress is exposed: never digest URLs, relay identities or paths.
type progressSource struct {
	Source
	manager *Manager
}

func (p progressSource) descriptorProgress(total, available int) {
	p.manager.mu.Lock()
	p.manager.status.Phase = "microdescriptors"
	if total > 0 && available == total {
		p.manager.status.Phase = "verification"
	}
	p.manager.status.Microdescriptors = available
	p.manager.status.MicrodescriptorsTotal = total
	p.manager.mu.Unlock()
}

func (p progressSource) Fetch(ctx context.Context, path string, limit int) ([]byte, error) {
	phase := "certificates"
	if strings.HasPrefix(path, "/tor/status-vote/") {
		phase = "consensus"
	}
	if strings.HasPrefix(path, "/tor/micro/") {
		phase = "microdescriptors"
	}
	m := p.manager
	m.mu.Lock()
	m.status.Phase = phase
	m.mu.Unlock()
	b, err := p.Source.Fetch(ctx, path, limit)
	if err == nil {
		m.mu.Lock()
		m.status.DownloadRequests++
		m.status.DownloadBytes += int64(len(b))
		m.mu.Unlock()
	}
	return b, err
}
