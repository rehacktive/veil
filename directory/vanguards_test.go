package directory

import (
	"errors"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"
)

func vanguardFixture(t *testing.T) (*Snapshot, *GuardStore) {
	t.Helper()
	s := pathFixture()
	s.consensus.params = map[string]int64{}
	s.relays = nil
	for j := byte(1); j <= 12; j++ {
		r := pathFixture().relays[0]
		r.status.rsa, r.descriptor.ed25519, r.descriptor.ntor = Fingerprint{j}, [32]byte{j}, [32]byte{j}
		r.status.address = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 9000+uint16(j))
		r.status.protocols, _ = parseProtocols([]string{"Link=4-5", "Relay=2", "HSRend=1"})
		r.descriptor.familyIDs = map[string]bool{"same-family": true}
		s.relays = append(s.relays, r)
	}
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	g, err := NewGuardStore(state)
	if err != nil {
		t.Fatal(err)
	}
	return s, g
}

func TestVanguardsStickyPoolAndOnionPaths(t *testing.T) {
	s, g := vanguardFixture(t)
	now := time.Now()
	var original []vanguardRecord
	for j := 0; j < 100; j++ {
		target := s.relays[j%len(s.relays)]
		p, err := g.SelectVanguardPath(s, s.relays[0], &target, false, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Relays()) != 4 || !sameRelay(p.Guard, s.relays[0]) || !sameRelay(p.Exit, target) {
			t.Fatal("onion endpoint changed the entry guard or path length")
		}
		if j == 0 {
			original = append([]vanguardRecord{}, g.vanguards...)
		}
		if !reflect.DeepEqual(original, g.vanguards) || len(original) != 4 {
			t.Fatal("endpoint requests changed the L2 pool")
		}
		found := false
		for _, v := range original {
			found = found || v.rsa == p.Middle.Identity()
			if v.expires.Before(now.Add(24*time.Hour)) || v.expires.After(now.Add(22*24*time.Hour)) {
				t.Fatal("L2 lifetime outside specification")
			}
		}
		if !found {
			t.Fatal("random middle bypassed pinned L2 set")
		}
	}
	// A client rendezvous uses three physical relays; a hostile service-side
	// rendezvous can equal the guard and uses four, avoiding guard switching.
	target := s.relays[1]
	p, err := g.SelectVanguardPath(s, s.relays[0], &target, true, now)
	if err != nil || len(p.Relays()) != 3 {
		t.Fatal(err)
	}
	if _, err := g.SelectVanguardPath(s, s.relays[0], &s.relays[0], true, now); !errors.Is(err, ErrPath) {
		t.Fatal("A-B-A accepted", err)
	}
	// Clearnet family/subnet policy remains unchanged.
	if _, err := s.SelectPathWithGuard(s.relays[0], 443, false, now); !errors.Is(err, ErrPath) {
		t.Fatal("onion exemption leaked into exit path selection", err)
	}
}

func TestVanguardsRotationParametersAndNoFallback(t *testing.T) {
	s, g := vanguardFixture(t)
	now := time.Now()
	s.consensus.params["guard-hs-l2-number"] = 2
	s.consensus.params["guard-hs-l2-lifetime-min"] = 10
	s.consensus.params["guard-hs-l2-lifetime-max"] = 10
	if err := g.updateVanguards(s, now); err != nil {
		t.Fatal(err)
	}
	if len(g.vanguards) != 2 || !g.vanguards[0].expires.Equal(now.Add(10*time.Second)) {
		t.Fatal("signed pool/lifetime parameters ignored")
	}
	first := g.vanguards[0]
	for j := range s.relays {
		if s.relays[j].Identity() == first.rsa {
			delete(s.relays[j].status.flags, "Stable")
		}
	}
	if err := g.updateVanguards(s, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, v := range g.vanguards {
		if v.rsa == first.rsa {
			t.Fatal("ineligible L2 retained")
		}
	}
	if err := g.updateVanguards(s, now.Add(20*time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, v := range g.vanguards {
		if !v.expires.Equal(now.Add(30 * time.Second)) {
			t.Fatal("expired L2 did not rotate")
		}
	}
	// A singleton L2 that equals this endpoint must fail, not sample a new L2.
	s.consensus.params["guard-hs-l2-number"] = 1
	target := s.relays[11]
	g.vanguards = []vanguardRecord{{target.Identity(), target.descriptor.ed25519, now.Add(time.Hour)}}
	_, err := g.SelectVanguardPath(s, s.relays[0], &target, false, now)
	if !errors.Is(err, ErrPath) || len(g.vanguards) != 1 || g.vanguards[0].rsa != target.Identity() {
		t.Fatal("incompatible endpoint bypassed or rotated pinned L2", err)
	}
	// Lite state is not serialized with persistent entry guards.
	reopened, err := NewGuardStore(g.path)
	if err != nil || len(reopened.vanguards) != 0 {
		t.Fatal("Lite pool survived restart", err)
	}
}
