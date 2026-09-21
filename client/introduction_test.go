package client

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type retainedFixture struct {
	done   chan struct{}
	closed chan struct{}
	once   sync.Once
}

func (c *retainedFixture) Done() <-chan struct{} { return c.done }
func (c *retainedFixture) Close() error          { c.once.Do(func() { close(c.closed) }); return nil }

func TestIntroductionRetentionBoundsAndCancellation(t *testing.T) {
	d, _ := poolDialer(t, Options{MaxCircuits: 1})
	setup, cancelSetup := context.WithCancel(context.Background())
	release, err := d.intros.reserve(setup, d.lifetime)
	if err != nil {
		t.Fatal(err)
	}
	ic := &retainedFixture{done: make(chan struct{}), closed: make(chan struct{})}
	introLife, cancelIntro := context.WithCancel(d.lifetime)
	d.intros.hold(d.lifetime, ic, cancelIntro, release, time.Hour)
	cancelSetup()
	select {
	case <-ic.closed:
		t.Fatal("setup cancellation closed retained intro")
	default:
	}
	blocked, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := d.intros.reserve(blocked, d.lifetime); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("full retainer bypassed", err)
	}
	if len(d.intros.slots) != 1 {
		t.Fatal("existing intro evicted")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ic.closed:
	default:
		t.Fatal("dialer close did not join intro teardown")
	}
	if introLife.Err() == nil || len(d.intros.slots) != 0 || len(d.intros.active) != 0 {
		t.Fatal("retained resources leaked")
	}
	if _, err := d.intros.reserve(context.Background(), d.lifetime); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestIntroductionRetentionExpiryAndPeerFailure(t *testing.T) {
	for _, peerFailure := range []bool{false, true} {
		r := newIntroductionRetainer(1)
		life, cancel := context.WithCancel(context.Background())
		release, err := r.reserve(life, life)
		if err != nil {
			t.Fatal(err)
		}
		ic := &retainedFixture{done: make(chan struct{}), closed: make(chan struct{})}
		duration := time.Millisecond
		if peerFailure {
			duration = time.Hour
			close(ic.done)
		}
		r.hold(life, ic, cancel, release, duration)
		select {
		case <-ic.closed:
		case <-time.After(time.Second):
			t.Fatal("intro did not expire")
		}
		r.work.Wait()
		release() // Reservation cleanup is idempotent.
		if len(r.slots) != 0 || len(r.active) != 0 || life.Err() == nil {
			t.Fatal("intro resource leak")
		}
	}
}
