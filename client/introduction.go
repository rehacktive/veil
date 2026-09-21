package client

import (
	"context"
	"sync"
	"time"
)

const introductionRetention = 10 * time.Minute

type retainedIntroduction interface {
	Done() <-chan struct{}
	Close() error
}

// Separate from stream slots: closing a stream must not reveal a short-lived
// introduction circuit. A full retainer makes new introductions wait for space;
// it never evicts existing circuits or silently skips padding.
type introductionRetainer struct {
	slots  chan struct{}
	mu     sync.Mutex
	active map[retainedIntroduction]struct{}
	work   sync.WaitGroup
}

func newIntroductionRetainer(limit int) *introductionRetainer {
	return &introductionRetainer{slots: make(chan struct{}, limit), active: make(map[retainedIntroduction]struct{})}
}

func (r *introductionRetainer) reserve(setup, life context.Context) (func(), error) {
	select {
	case <-setup.Done():
		return nil, setup.Err()
	case <-life.Done():
		return nil, life.Err()
	case r.slots <- struct{}{}:
	}
	var once sync.Once
	release := func() { once.Do(func() { <-r.slots }) }
	if err := setup.Err(); err != nil {
		release()
		return nil, err
	}
	if err := life.Err(); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

// hold is called only by DialContext workers. Close first cancels the dialer,
// then joins those workers before waiting here, so Add cannot race Wait.
func (r *introductionRetainer) hold(life context.Context, c retainedIntroduction, cancel context.CancelFunc, release func(), duration time.Duration) {
	r.mu.Lock()
	r.active[c] = struct{}{}
	r.work.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.work.Done()
		timer := time.NewTimer(duration)
		defer timer.Stop()
		select {
		case <-life.Done():
		case <-c.Done():
		case <-timer.C:
		}
		cancel()
		_ = c.Close() // Circuit.Close is idempotent and currently always returns nil.
		r.mu.Lock()
		delete(r.active, c)
		r.mu.Unlock()
		release()
	}()
}
