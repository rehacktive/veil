package directory

import (
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"
)

func pathFixture() *Snapshot {
	now := time.Now()
	s := &Snapshot{consensus: &consensus{validAfter: now.Add(-time.Hour), freshUntil: now.Add(time.Hour), validUntil: now.Add(2 * time.Hour), weights: map[string]uint64{"Wgg": 10000, "Wgd": 10000, "Wed": 10000, "Wee": 10000, "Wmm": 10000, "Wmd": 10000, "Wmg": 10000, "Wme": 10000}}}
	p, _ := parseProtocols([]string{"Link=4-5", "Relay=2"})
	for i := byte(1); i <= 3; i++ {
		r := Relay{status: relayStatus{rsa: Fingerprint{i}, address: netip.AddrPortFrom(netip.AddrFrom4([4]byte{i, 1, 1, 1}), 9001), protocols: p, bandwidth: 100, flags: map[string]bool{"Running": true, "Valid": true, "Fast": true, "Stable": true, "V2Dir": true}}, descriptor: microdescriptor{ed25519: [32]byte{i}, ntor: [32]byte{i}, family: map[Fingerprint]bool{}, familyIDs: map[string]bool{}, ipv4: portPolicy{accept: true, ports: []interval{{443, 443}}}}}
		if i == 1 {
			r.status.flags["Guard"] = true
		}
		if i == 3 {
			r.status.flags["Exit"] = true
		}
		s.relays = append(s.relays, r)
	}
	return s
}
func TestPersistentGuardAndPath(t *testing.T) {
	s := pathFixture()
	now := time.Now()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	g, err := NewGuardStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.SelectPath(g, 443, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.Guard.Identity() != (Fingerprint{1}) || p.Middle.Identity() != (Fingerprint{2}) || p.Exit.Identity() != (Fingerprint{3}) {
		t.Fatal("wrong path")
	}
	restarted, err := NewGuardStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := restarted.Guard(s, now)
	if err != nil || saved.Identity() != p.Guard.Identity() {
		t.Fatalf("guard changed: %v", err)
	}
	if _, err := s.SelectPath(g, 80, false, now); !errors.Is(err, ErrPath) {
		t.Fatal("accepted blocked port", err)
	}
	if _, err := s.SelectPath(g, 443, true, now); !errors.Is(err, ErrPath) {
		t.Fatal("accepted IPv6 without policy", err)
	}
	if _, err := s.SelectPath(g, 443, false, now.Add(3*time.Hour)); !errors.Is(err, ErrTime) {
		t.Fatal("accepted expired directory", err)
	}
	s.relays[0].status.flags["Running"] = false
	s.relays[1].status.flags["Guard"] = true
	if _, err := g.Guard(s, now); err != nil {
		t.Fatal(err)
	}
	if g.record(p.Guard.Identity()) == nil {
		t.Fatal("discarded unavailable guard")
	}
	info, err := os.Stat(dir + "/guard.json")
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v %v", info, err)
	}
}
func TestFamilyAndSubnetSeparation(t *testing.T) {
	for _, test := range []struct {
		name     string
		edit     func(*Relay, *Relay)
		conflict bool
	}{
		{"separate", func(a, b *Relay) {}, false},
		{"identity", func(a, b *Relay) { b.status.rsa = a.status.rsa }, true},
		{"ed identity", func(a, b *Relay) { b.descriptor.ed25519 = a.descriptor.ed25519 }, true},
		{"one sided family", func(a, b *Relay) { a.descriptor.family[b.Identity()] = true }, false},
		{"mutual family", func(a, b *Relay) { a.descriptor.family[b.Identity()] = true; b.descriptor.family[a.Identity()] = true }, true},
		{"shared family id", func(a, b *Relay) { a.descriptor.familyIDs["family"] = true; b.descriptor.familyIDs["family"] = true }, true},
		{"IPv4 subnet", func(a, b *Relay) {
			a.status.address = netip.MustParseAddrPort("1.2.3.4:9")
			b.status.address = netip.MustParseAddrPort("1.2.255.5:9")
		}, true},
		{"IPv6 subnet", func(a, b *Relay) {
			a.status.extra = []netip.AddrPort{netip.MustParseAddrPort("[2001:abcd::1]:9")}
			b.status.extra = []netip.AddrPort{netip.MustParseAddrPort("[2001:abcd:ffff::1]:9")}
		}, true},
		{"IPv6 separate", func(a, b *Relay) {
			a.status.extra = []netip.AddrPort{netip.MustParseAddrPort("[2001:abcd::1]:9")}
			b.status.extra = []netip.AddrPort{netip.MustParseAddrPort("[2001:abce::1]:9")}
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := pathFixture()
			a, b := s.relays[0], s.relays[1]
			test.edit(&a, &b)
			if conflict(a, b) != test.conflict || conflict(b, a) != test.conflict {
				t.Fatal("constraint mismatch")
			}
		})
	}
}
func TestWeightsAndNoSubnetBypass(t *testing.T) {
	s := pathFixture()
	s.relays[0].status.bandwidth = 0
	for i := 0; i < 20; i++ {
		r, err := choose(s, s.relays[:2], "middle")
		if err != nil || r.Identity() != s.relays[1].Identity() {
			t.Fatal(r.Identity(), err)
		}
	}
	s.relays[1].status.bandwidth = 0
	if _, err := choose(s, s.relays[:2], "middle"); !errors.Is(err, ErrPath) {
		t.Fatal(err)
	}
	d, roots, now := fixture(t)
	verified, err := Verify(d, roots, now)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	g, err := NewGuardStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verified.SelectPath(g, 443, false, now); !errors.Is(err, ErrPath) {
		t.Fatal("same-subnet Chutney fixture must not bypass exclusions", err)
	}
}

func TestPathUsesTrackedGuardAndCurrentDescriptor(t *testing.T) {
	s := pathFixture()
	g := guardStore(t)
	a, err := g.Select(s, false, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	// The attempt pins the identity, while the current authenticated snapshot
	// supplies address and rotated onion keys for the actual construction.
	s.relays[0].descriptor.ntor[3] = 99
	p, err := s.SelectPathWithGuard(a.Relay(), 443, false, time.Now())
	if err != nil || p.Guard.Identity() != a.Relay().Identity() || p.Guard.NTor().OnionKey[3] != 99 {
		t.Fatal(p, err)
	}
	foreign := a.Relay()
	foreign.descriptor.ed25519[0] ^= 1
	if _, err := s.SelectPathWithGuard(foreign, 443, false, time.Now()); !errors.Is(err, ErrPath) {
		t.Fatal("accepted changed guard identity", err)
	}
	if _, err := s.SelectPathWithGuard(Relay{}, 443, false, time.Now()); !errors.Is(err, ErrPath) {
		t.Fatal("accepted foreign guard", err)
	}
	if _, err := s.SelectPathWithGuard(a.Relay(), 0, false, time.Now()); !errors.Is(err, ErrPath) {
		t.Fatal("accepted zero port", err)
	}
	if _, err := s.SelectPathWithGuard(a.Relay(), 443, false, time.Now().Add(3*time.Hour)); !errors.Is(err, ErrTime) {
		t.Fatal("accepted expired snapshot", err)
	}
	s.relays[1].descriptor.family[s.relays[0].Identity()] = true
	s.relays[0].descriptor.family[s.relays[1].Identity()] = true
	if _, err := s.SelectPathWithGuard(a.Relay(), 443, false, time.Now()); !errors.Is(err, ErrPath) {
		t.Fatal("ignored guard family restriction", err)
	}
}
