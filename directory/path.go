package directory

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"time"
)

var ErrPath = errors.New("no compatible Tor path")

func eligible(r Relay) bool {
	p := r.status.protocols
	return r.HasFlag("Running") && r.HasFlag("Valid") && r.HasFlag("Fast") && !r.HasFlag("NoEdConsensus") && r.descriptor.ed25519 != ([32]byte{}) && (p.has("Link", 4) || p.has("Link", 5)) && p.has("Relay", 2)
}

type Path struct {
	Guard, Middle, Exit Relay
	// ExtraMiddle follows Middle on four-relay onion paths. Middle is the L2
	// vanguard on these paths; Exit is the onion endpoint, not an internet exit.
	ExtraMiddle *Relay
}

func (p Path) Relays() []Relay {
	if p.ExtraMiddle != nil {
		return []Relay{p.Guard, p.Middle, *p.ExtraMiddle, p.Exit}
	}
	return []Relay{p.Guard, p.Middle, p.Exit}
}

// SelectPath enforces family and subnet separation for all hops and checks the
// requested IP family's exit-port summary. Summaries do not guarantee that an
// exit permits a particular destination address. No network connection is made.
func (s *Snapshot) SelectPath(g *GuardStore, port uint16, ipv6 bool, now time.Time) (Path, error) {
	if g == nil || port == 0 {
		return Path{}, ErrPath
	}
	guard, err := g.Guard(s, now)
	if err != nil {
		return Path{}, err
	}
	return s.SelectPathWithGuard(guard, port, ipv6, now)
}

// SelectPathWithGuard completes a path for an existing GuardAttempt. It uses
// this snapshot's copy of the guard, rejecting stale or foreign identity keys.
// Callers must report the attempt outcome and check its usability separately.
func (s *Snapshot) SelectPathWithGuard(guard Relay, port uint16, ipv6 bool, now time.Time) (Path, error) {
	if !s.Valid(now) {
		return Path{}, ErrTime
	}
	if port == 0 {
		return Path{}, ErrPath
	}
	found := false
	for _, r := range s.relays {
		if r.Identity() == guard.Identity() && r.Target().Identity == guard.Target().Identity && guardEligible(r) {
			guard, found = r, true
			break
		}
	}
	if !found {
		return Path{}, ErrPath
	}
	var exits []Relay
	for _, r := range s.relays {
		p := r.descriptor.ipv4
		if ipv6 {
			p = r.descriptor.ipv6
		}
		if eligible(r) && r.HasFlag("Exit") && !r.HasFlag("BadExit") && p.allows(port) && !conflict(guard, r) {
			exits = append(exits, r)
		}
	}
	exit, err := choose(s, exits, "exit")
	if err != nil {
		return Path{}, err
	}
	var middles []Relay
	for _, r := range s.relays {
		if eligible(r) && !conflict(guard, r) && !conflict(exit, r) {
			middles = append(middles, r)
		}
	}
	middle, err := choose(s, middles, "middle")
	if err != nil {
		return Path{}, err
	}
	return Path{Guard: guard, Middle: middle, Exit: exit}, nil
}
func conflict(a, b Relay) bool {
	if a.Identity() == b.Identity() || a.descriptor.ed25519 == b.descriptor.ed25519 {
		return true
	}
	if a.descriptor.family[b.Identity()] && b.descriptor.family[a.Identity()] {
		return true
	}
	for id := range a.descriptor.familyIDs {
		if b.descriptor.familyIDs[id] {
			return true
		}
	}
	as := append([]netip.AddrPort{a.Address()}, a.status.extra...)
	bs := append([]netip.AddrPort{b.Address()}, b.status.extra...)
	for _, aa := range as {
		for _, bb := range bs {
			x, y := aa.Addr().Unmap(), bb.Addr().Unmap()
			bits := 32
			if x.Is4() {
				bits = 16
			}
			if x.BitLen() == y.BitLen() && netip.PrefixFrom(x, bits).Contains(y) {
				return true
			}
		}
	}
	return false
}
func weight(s *Snapshot, r Relay, role string) uint64 {
	guard, exit := r.HasFlag("Guard"), r.HasFlag("Exit") && !r.HasFlag("BadExit")
	var key string
	switch role {
	case "guard":
		if exit {
			key = "Wgd"
		} else {
			key = "Wgg"
		}
	case "exit":
		if guard {
			key = "Wed"
		} else {
			key = "Wee"
		}
	case "middle":
		switch {
		case guard && exit:
			key = "Wmd"
		case guard:
			key = "Wmg"
		case exit:
			key = "Wme"
		default:
			key = "Wmm"
		}
	}
	// Missing weights are allowed by the document format, but cannot be used for
	// weighted selection until the fallback weighting rules are implemented.
	return r.Bandwidth() * s.consensus.weights[key]
}
func choose(s *Snapshot, candidates []Relay, role string) (Relay, error) {
	total := new(big.Int)
	for _, r := range candidates {
		total.Add(total, new(big.Int).SetUint64(weight(s, r, role)))
	}
	if total.Sign() == 0 {
		return Relay{}, fmt.Errorf("%w: no positive %s bandwidth", ErrPath, role)
	}
	pick, err := rand.Int(rand.Reader, total)
	if err != nil {
		return Relay{}, err
	}
	for _, r := range candidates {
		w := new(big.Int).SetUint64(weight(s, r, role))
		if pick.Cmp(w) < 0 {
			return r, nil
		}
		pick.Sub(pick, w)
	}
	return Relay{}, ErrPath
}
