package service

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"veil/directory"
	"veil/onion"
)

func publicationFixture(t *testing.T) (*Host, *directory.Snapshot, *generation, []directory.ServicePeriod, time.Time) {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile("../directory/testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var roots []directory.Fingerprint
	for _, raw := range []string{"0B8997614EC647C1C6B6A044E2B5408F0B823FB0", "5B591AD684C1AB8E0AB76C839E93FD097526A4BC", "8A1777F0BF97344A7ABB97530EEEE38A5BDE8A4D", "D190BF3B00E311A9AEB6D62B51980E9B2109BAD1"} {
		id, err := directory.ParseFingerprint(raw)
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, id)
	}
	now := time.Date(2000, 1, 1, 0, 2, 30, 0, time.UTC)
	snapshot, err := directory.Verify(directory.Documents{Certificates: read("authorities.txt"), Consensus: read("consensus.txt"), Microdescriptors: read("microdescriptors.txt")}, roots, now)
	if err != nil {
		t.Fatal(err)
	}
	periods, err := snapshot.ServicePeriods(now)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := directory.OpenServiceIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{identity: identity}
	g := newGeneration(context.Background(), newIntroductionAdmission(), nil)
	t.Cleanup(g.cancel)
	for _, relay := range snapshot.Relays()[:3] {
		key, err := onion.NewServiceIntroduction(relayLinks(relay), relay.NTor().OnionKey)
		if err != nil {
			t.Fatal(err)
		}
		g.intros = append(g.intros, &introduction{key: key})
	}
	g.alive.Store(3)
	h.generationStatus(g, nil)
	h.updateStatus(func(s *Status) { s.Running = true })
	return h, snapshot, g, periods, now
}

func TestPublicationStatusPartialRetryAndRecovery(t *testing.T) {
	h, snapshot, g, periods, now := publicationFixture(t)
	for _, mode := range []string{"partial", "none", "complete"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			h.upload = func(context.Context, *directory.Snapshot, directory.Relay, []byte) error {
				calls++
				status := h.Status() // Polling must not contend with a network call.
				if status.Phase != "publishing" || status.Ready || len(status.Publications) == 0 {
					t.Fatal("incorrect in-flight status", status)
				}
				if mode == "none" || mode == "partial" && calls%2 == 0 {
					return io.ErrUnexpectedEOF
				}
				return nil
			}
			err := h.publishWithClock(context.Background(), snapshot, g, periods, func() time.Time { return now })
			if (err == nil) != (mode == "complete") {
				t.Fatal(mode, err)
			}
			next := time.Now().Add(time.Minute)
			h.publicationResult(err, next)
			status := h.Status()
			if len(status.Publications) != len(periods) || status.NextAttempt != next {
				t.Fatal(status)
			}
			for _, p := range status.Publications {
				if p.Attempted != p.Total || p.Total == 0 {
					t.Fatal(p)
				}
				if mode == "none" && p.Uploaded != 0 || mode == "complete" && p.Uploaded != p.Total {
					t.Fatal(p)
				}
			}
			want := map[string]string{"partial": "partial", "none": "retrying", "complete": "degraded"}[mode]
			// The historical fixture's certificates have expired, even if all
			// simulated HSDirs acknowledged them. Never claim current readiness.
			if status.Phase != want || status.Ready {
				t.Fatal(status)
			}
			if (status.LastError == "") != (mode == "complete") {
				t.Fatal(status)
			}
			if mode == "complete" {
				h.updateStatus(func(s *Status) {
					for i := range s.Publications {
						s.Publications[i].Expires = time.Now().Add(time.Hour)
					}
				})
				if !h.Status().Ready {
					t.Fatal("fully published live generation not ready")
				}
			}
			status.Publications[0].Uploaded = -1
			if h.Status().Publications[0].Uploaded < 0 {
				t.Fatal("mutable status escaped")
			}
		})
	}
	if g.retainUntil.IsZero() {
		t.Fatal("publication did not retain advertised keys")
	}
	// Losing an introduction invalidates readiness immediately, even before
	// the owner processes the failure notification.
	g.alive.Add(-1)
	if s := h.Status(); s.Ready || s.Phase != "degraded" || s.IntroductionPoints != 2 {
		t.Fatal(s)
	}
	g.cancel()
	if h.Status().IntroductionPoints != 0 {
		t.Fatal("canceled introductions reported active")
	}
}

func TestStatusConcurrentRotationAndShutdown(t *testing.T) {
	h := &Host{}
	if s := h.Status(); s.Phase != "starting" || s.Running || s.Ready {
		t.Fatal(s)
	}
	g := newGeneration(context.Background(), newIntroductionAdmission(), nil)
	defer g.cancel()
	g.alive.Store(2)
	h.generationStatus(nil, []*generation{g})
	if h.Status().RetainedIntroductions != 2 {
		t.Fatal("retained introductions missing")
	}
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				_ = h.Status()
			}
		}()
	}
	for i := 0; i < 100; i++ {
		h.updateStatus(func(s *Status) { s.Phase = "recovering"; s.Running = true })
		h.generationStatus(g, nil)
		h.generationStatus(nil, []*generation{g})
	}
	workers.Wait()
	l := &Listener{host: h, closed: make(chan struct{})}
	close(l.closed)
	if s := l.Status(); s.Ready || s.Phase != "draining" {
		t.Fatal(s)
	}
	h.stopStatus(errors.Join(context.Canceled))
	if s := l.Status(); s.Phase != "stopped" || s.Running || s.Ready || s.RetainedIntroductions != 0 {
		t.Fatal(s)
	}
	h.stopStatus(io.ErrUnexpectedEOF)
	if s := h.Status(); s.Phase != "failed" || s.LastError == "" {
		t.Fatal(s)
	}
}

func TestPublicationChecksCurrentDirectoryTime(t *testing.T) {
	h, snapshot, g, periods, now := publicationFixture(t)
	h.upload = func(context.Context, *directory.Snapshot, directory.Relay, []byte) error {
		t.Fatal("uploaded after directory expiry")
		return nil
	}
	calls := 0
	err := h.publishWithClock(context.Background(), snapshot, g, periods, func() time.Time {
		calls++
		if calls > 1 {
			return now.Add(time.Hour)
		}
		return now
	})
	if !errors.Is(err, directory.ErrTime) || h.Status().Ready {
		t.Fatal(err, h.Status())
	}
}
