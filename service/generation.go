package service

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// At most twelve introduction circuits, including the generation being built.
// Under repeated failures, defer replacement rather than discard unexpired
// advertised keys or grow circuit/replay state without bound.
const maxIntroductionGenerations = 4

type generation struct {
	ctx         context.Context
	cancel      context.CancelFunc
	workers     sync.WaitGroup
	alive       atomic.Int32
	retireTimer *time.Timer
	retainUntil time.Time // Latest certificate expiry of any attempted upload.
	admission   *introductionAdmission
	changed     chan struct{}
	intros      []*introduction
	mu          sync.RWMutex
	subs        [][32]byte
	cookies     map[[20]byte]bool
}

type introductionAdmission struct {
	mu       sync.Mutex
	cookies  map[[20]byte]*generation
	window   time.Time
	received int
}

func newIntroductionAdmission() *introductionAdmission {
	return &introductionAdmission{cookies: make(map[[20]byte]*generation)}
}

func (a *introductionAdmission) allow(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.window.IsZero() || now.Sub(a.window) >= time.Second {
		a.window = now
		a.received = 0
	}
	if a.received >= 64 {
		return false
	}
	a.received++
	return true
}

func newGeneration(parent context.Context, admission *introductionAdmission, changed chan struct{}) *generation {
	ctx, cancel := context.WithCancel(parent)
	return &generation{ctx: ctx, cancel: cancel, admission: admission, changed: changed, cookies: make(map[[20]byte]bool)}
}

func (g *generation) notify() {
	select {
	case g.changed <- struct{}{}:
	default:
	}
}

func (g *generation) close() {
	g.cancel()
	if g.retireTimer != nil {
		g.retireTimer.Stop()
	}
	for _, i := range g.intros {
		_ = i.circuit.Close()
	}
	g.workers.Wait()
	// Keys can no longer accept introductions. Only now release their shared
	// cookie history; other generations retain their own replay protection.
	g.admission.mu.Lock()
	for cookie := range g.cookies {
		delete(g.admission.cookies, cookie)
	}
	clear(g.cookies)
	g.admission.mu.Unlock()
}

func pruneGenerations(generations []*generation, now time.Time) []*generation {
	live := generations[:0]
	for _, g := range generations {
		if !now.Before(g.retainUntil) || g.alive.Load() == 0 {
			g.close()
		} else {
			live = append(live, g)
		}
	}
	clear(generations[len(live):])
	return live
}
