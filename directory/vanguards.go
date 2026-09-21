package directory

import (
	"crypto/rand"
	"math/big"
	"time"
)

type vanguardRecord struct {
	rsa     Fingerprint
	ed      [32]byte
	expires time.Time
}

func sameRelay(a, b Relay) bool {
	return a.Identity() == b.Identity() || a.descriptor.ed25519 == b.descriptor.ed25519
}

// updateVanguards runs with g.mu held. Pool membership never depends on the
// requested endpoint, chosen entry guard, circuit failures, or isolation scope.
func (g *GuardStore) updateVanguards(s *Snapshot, now time.Time) error {
	param := func(name string, fallback, maximum int64) int64 {
		if v, ok := s.consensus.params[name]; ok {
			return max(1, min(v, maximum))
		}
		return fallback
	}
	count := int(param("guard-hs-l2-number", 4, 19))
	minimum := param("guard-hs-l2-lifetime-min", 86400, 2147483647)
	maximum := param("guard-hs-l2-lifetime-max", 22*86400, 2147483647)
	if minimum > maximum {
		return ErrPath
	}
	kept := make([]vanguardRecord, 0, 19)
	for _, v := range g.vanguards {
		r, err := s.RelayByIdentity(v.rsa, v.ed)
		if err == nil && now.Before(v.expires) && r.HasFlag("Fast") && r.HasFlag("Stable") {
			kept = append(kept, v)
		}
	}
	// A lower consensus target does not prematurely evict still-live guards.
	g.vanguards = kept
	for len(g.vanguards) < count {
		var candidates []Relay
		for _, r := range s.relays {
			if !eligible(r) || !r.HasFlag("Stable") {
				continue
			}
			present := false
			for _, v := range g.vanguards {
				present = present || r.Identity() == v.rsa || r.descriptor.ed25519 == v.ed
			}
			if !present {
				candidates = append(candidates, r)
			}
		}
		if len(candidates) == 0 {
			break
		}
		r, err := choose(s, candidates, "middle")
		if err != nil {
			return err
		}
		// Current Vanguards-Lite spec: max of two uniform samples, 1–22 days
		// by default. Signed consensus lifetime parameters override the bounds.
		x, err := rand.Int(rand.Reader, big.NewInt(maximum-minimum+1))
		if err != nil {
			return err
		}
		y, err := rand.Int(rand.Reader, big.NewInt(maximum-minimum+1))
		if err != nil {
			return err
		}
		lifetime := time.Duration(minimum+max(x.Int64(), y.Int64())) * time.Second
		g.vanguards = append(g.vanguards, vanguardRecord{r.Identity(), r.descriptor.ed25519, now.Add(lifetime)})
	}
	return nil
}

// SelectVanguardPath uses the shared, memory-only L2 set. short is only for
// client rendezvous circuits; all other onion paths have an extra middle.
// Do not pre-exclude entry guards based on the endpoint's identity/family/subnet:
// a service's peer can choose the rendezvous and thereby probe guard selection.
func (g *GuardStore) SelectVanguardPath(s *Snapshot, guard Relay, target *Relay, short bool, now time.Time) (Path, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.update(s, now, false); err != nil {
		return Path{}, err
	}
	if err := g.updateVanguards(s, now); err != nil {
		return Path{}, err
	}
	entry, err := s.RelayByIdentity(guard.Identity(), guard.descriptor.ed25519)
	if err != nil || !guardEligible(entry) {
		return Path{}, ErrPath
	}
	var end Relay
	if target != nil {
		end, err = s.RelayByIdentity(target.Identity(), target.descriptor.ed25519)
		if err != nil || !eligible(end) {
			return Path{}, ErrPath
		}
	} else {
		var candidates []Relay
		for _, r := range s.relays {
			if eligible(r) && r.status.protocols.has("HSRend", 1) {
				candidates = append(candidates, r)
			}
		}
		end, err = choose(s, candidates, "middle")
		if err != nil {
			return Path{}, err
		}
	}
	if short && sameRelay(entry, end) {
		return Path{}, ErrPath // Relays forbid A-B-A subpaths.
	}
	var layer2 []Relay
	for _, v := range g.vanguards {
		r, err := s.RelayByIdentity(v.rsa, v.ed)
		if err == nil && eligible(r) && !sameRelay(entry, r) && !sameRelay(end, r) {
			layer2 = append(layer2, r)
		}
	}
	if len(layer2) == 0 {
		return Path{}, ErrPath // Never replace the set or fall back to random middles.
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(layer2))))
	if err != nil {
		return Path{}, err
	}
	p := Path{Guard: entry, Middle: layer2[n.Int64()], Exit: end}
	if !short {
		var middles []Relay
		for _, r := range s.relays {
			if eligible(r) && r.HasFlag("Stable") && !sameRelay(r, entry) && !sameRelay(r, p.Middle) && !sameRelay(r, end) {
				middles = append(middles, r)
			}
		}
		middle, err := choose(s, middles, "middle")
		if err != nil {
			return Path{}, err
		}
		p.ExtraMiddle = &middle
	}
	return p, nil
}
