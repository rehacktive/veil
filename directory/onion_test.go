package directory

import (
	"crypto/sha3"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// C Tor test_hs_indexes, also recorded in Arti's hsdir_ring.rs.
func TestOnionRingTorVectors(t *testing.T) {
	var id, srv [32]byte
	for i := range id {
		id[i] = 0x42
		srv[i] = 0x43
	}
	relay := onionRelayIndex(id, srv, 42, 1440)
	service := onionServiceIndex(id, 1, 42, 1440)
	if hex.EncodeToString(relay[:]) != "db475361014a09965e7e5e4d4a25b8f8d4b8f16cb1d8a7e95eed50249cc1a2d5" || hex.EncodeToString(service[:]) != "37e5cbbd56a22823714f18f1623ece5983a0d64c78495a8cfab854245e5f9a8a" {
		t.Fatal("Tor HSDir ring index mismatch")
	}
}

func TestOnionPeriodSharedRandomBoundaries(t *testing.T) {
	// Midnight rotates SRVs; noon rotates descriptor periods. Before noon the
	// client must still use yesterday's SRV, even with today's consensus.
	for _, hour := range []int{0, 11, 12, 23} {
		now := time.Date(2026, 9, 20, hour, 0, 0, 0, time.UTC)
		s := pathFixture()
		c := s.consensus
		c.validAfter = now
		c.freshUntil = now.Add(time.Hour)
		c.validUntil = now.Add(3 * time.Hour)
		prev, cur := [32]byte{1}, [32]byte{2}
		c.sharedRandom = [2][]string{{"9", base64.StdEncoding.EncodeToString(prev[:])}, {"9", base64.StdEncoding.EncodeToString(cur[:])}}
		p, m, srv, err := s.OnionPeriod(now)
		want := cur
		if hour < 12 {
			want = prev
		}
		if err != nil || m != 1440 || p != uint64((now.Unix()-43200)/86400) || srv != want {
			t.Fatal(hour, p, m, srv, err)
		}
		c.sharedRandom = [2][]string{}
		_, _, srv, err = s.OnionPeriod(now)
		b := binary.BigEndian.AppendUint64([]byte("shared-random-disaster"), 1440)
		b = binary.BigEndian.AppendUint64(b, p)
		if err != nil || srv != sha3.Sum256(b) {
			t.Fatal("disaster SRV", err)
		}
		if _, _, _, err = s.OnionPeriod(c.validUntil); !errors.Is(err, ErrTime) {
			t.Fatal("expired consensus accepted", err)
		}
	}
}

func TestOnionInternalPathAndDirectoryEligibility(t *testing.T) {
	s := pathFixture()
	now := time.Now()
	for i := range s.relays {
		s.relays[i].status.protocols, _ = parseProtocols([]string{"Link=4-5", "Relay=2", "HSDir=2", "HSRend=1"})
		s.relays[i].status.flags["HSDir"] = true
		delete(s.relays[i].status.flags, "Exit")
	}
	p, err := s.SelectInternalPath(s.relays[0], &s.relays[2], now)
	if err != nil || p.Middle.Identity() != s.relays[1].Identity() || p.Exit.Identity() != s.relays[2].Identity() {
		t.Fatal(p, err)
	}
	if _, err = s.SelectInternalPath(s.relays[0], &s.relays[0], now); !errors.Is(err, ErrPath) {
		t.Fatal("guard reused as target", err)
	}
	s.relays[1].descriptor.family[s.relays[2].Identity()] = true
	s.relays[2].descriptor.family[s.relays[1].Identity()] = true
	if _, err = s.SelectInternalPath(s.relays[0], &s.relays[2], now); !errors.Is(err, ErrPath) {
		t.Fatal("same family used", err)
	}
	seen := map[Fingerprint]bool{}
	dirs, err := s.OnionDirectories([32]byte{42}, now)
	if err != nil || len(dirs) != 3 {
		t.Fatal(len(dirs), err)
	}
	for _, r := range dirs {
		if seen[r.Identity()] {
			t.Fatal("duplicate HSDir")
		}
		seen[r.Identity()] = true
	}
	for i := range s.relays {
		delete(s.relays[i].status.flags, "HSDir")
	}
	if _, err = s.OnionDirectories([32]byte{42}, now); !errors.Is(err, ErrPath) {
		t.Fatal("non-HSDir selected", err)
	}
}
