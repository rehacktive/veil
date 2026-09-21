package service

import (
	"context"
	"testing"
	"time"

	"veil/onion"
)

func TestOverlappingGenerationsShareAdmission(t *testing.T) {
	a := newIntroductionAdmission()
	old := newGeneration(context.Background(), a, nil)
	defer old.close()
	next := newGeneration(context.Background(), a, nil)
	defer next.close()
	i := &introduction{clients: make(map[[32]byte]bool)}
	j := &introduction{clients: make(map[[32]byte]bool)}
	request := onion.ServiceRequest{ClientKey: [32]byte{1}, Cookie: [20]byte{2}}
	if ok, err := old.remember(i, request); !ok || err != nil {
		t.Fatal(err)
	}
	// A freshly authenticated request with a different key still cannot reuse
	// a rendezvous cookie while the generation owning its history accepts traffic.
	request.ClientKey[0]++
	if ok, err := next.remember(j, request); ok || err != nil {
		t.Fatal("cookie reused across live generations", err)
	}
	now := time.Now()
	for n := 0; n < 64; n++ {
		g := old
		if n%2 != 0 {
			g = next
		}
		if !g.admission.allow(now) {
			t.Fatal("budget exhausted early")
		}
	}
	if old.admission.allow(now) || next.admission.allow(now) {
		t.Fatal("overlap multiplied the introduction rate budget")
	}
	old.close()
	if ok, err := next.remember(j, request); !ok || err != nil {
		t.Fatal("retired generation did not release its cookie history", err)
	}
	old.close()
	if ok, err := next.remember(i, request); ok || err != nil {
		t.Fatal("repeated cleanup erased another generation's history", err)
	}
	if !a.allow(now.Add(time.Second)) {
		t.Fatal("budget did not replenish")
	}
}

func TestGenerationRetirementPreservesUnexpiredHistory(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := newIntroductionAdmission()
	now := time.Now()
	var generations []*generation
	for n := 0; n < maxIntroductionGenerations; n++ {
		g := newGeneration(ctx, a, nil)
		// No network workers are needed to test the ownership/expiry boundary.
		g.alive.Store(1)
		g.retainUntil = now.Add(time.Duration(n+1) * time.Hour)
		i := &introduction{clients: make(map[[32]byte]bool)}
		if ok, err := g.remember(i, onion.ServiceRequest{Cookie: [20]byte{byte(n)}}); !ok || err != nil {
			t.Fatal(err)
		}
		generations = append(generations, g)
	}
	first := generations[0]
	generations = pruneGenerations(generations, first.retainUntil.Add(-time.Nanosecond))
	if len(generations) != maxIntroductionGenerations || first.ctx.Err() != nil || len(a.cookies) != maxIntroductionGenerations {
		t.Fatal("unexpired advertised keys/history were discarded")
	}
	generations = pruneGenerations(generations, first.retainUntil)
	if len(generations) != maxIntroductionGenerations-1 || first.ctx.Err() == nil || len(a.cookies) != maxIntroductionGenerations-1 {
		t.Fatal("expired generation did not release capacity and history")
	}
	// Losing all intro readers frees capacity without waiting for expiry.
	generations[0].alive.Store(0)
	generations = pruneGenerations(generations, now)
	if len(generations) != maxIntroductionGenerations-2 {
		t.Fatal("dead generation retained capacity")
	}
	for _, g := range generations {
		g.close()
	}
	if len(a.cookies) != 0 {
		t.Fatal("history leaked on shutdown")
	}
}
