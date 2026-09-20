package directory

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"sort"
	"time"
)

// OnionPeriod derives the client descriptor period from the signed consensus.
// Offset is twelve voting intervals; period length is in minutes.
func (s *Snapshot) OnionPeriod(now time.Time) (period, minutes uint64, srv [32]byte, err error) {
	if !s.Valid(now) {
		return 0, 0, srv, ErrTime
	}
	c := s.consensus
	length := int64(1440)
	if v, ok := c.params["hsdir_interval"]; ok {
		length = max(30, min(v, 14400))
	}
	vote := int64(c.freshUntil.Sub(c.validAfter) / time.Second)
	if vote < 1 || vote > 86400 || c.validAfter.Unix() < 12*vote {
		return 0, 0, srv, ErrTime
	}
	minutes = uint64(length)
	periodIndex := (c.validAfter.Unix() - 12*vote) / (length * 60)
	if periodIndex < 0 {
		return 0, 0, srv, ErrTime
	}
	period = uint64(periodIndex)
	start := periodIndex*length*60 + 12*vote
	srvLength := vote * 24
	currentStart := c.validAfter.Unix() - ((c.validAfter.Unix()/vote)%24)*vote
	var values [2][32]byte
	var starts [2]int64
	var present [2]bool
	for i, args := range c.sharedRandom {
		if len(args) == 0 {
			continue
		}
		if len(args) != 2 && len(args) != 3 {
			return 0, 0, srv, ErrDocument
		}
		if _, e := number(args[0], 32); e != nil {
			return 0, 0, srv, e
		}
		b, e := unbase64(args[1], 32)
		if e != nil {
			return 0, 0, srv, e
		}
		copy(values[i][:], b)
		starts[i] = currentStart - int64(1-i)*srvLength
		if len(args) == 3 {
			n, e := number(args[2], 63)
			if e != nil {
				return 0, 0, srv, e
			}
			if n > 9223372036854775807 {
				return 0, 0, srv, ErrDocument
			}
			starts[i] = int64(n)
		}
		present[i] = true
	}
	if len(c.sharedRandom[0]) == 3 && len(c.sharedRandom[1]) == 3 {
		srvLength = starts[1] - starts[0]
		if srvLength <= 0 || srvLength > 30*86400 {
			return 0, 0, srv, ErrDocument
		}
	}
	for i := 1; i >= 0; i-- {
		if present[i] && start >= starts[i] && start-starts[i] < srvLength {
			return period, minutes, values[i], nil
		}
	}
	b := binary.BigEndian.AppendUint64([]byte("shared-random-disaster"), minutes)
	b = binary.BigEndian.AppendUint64(b, period)
	return period, minutes, sha3.Sum256(b), nil
}

// OnionDirectories returns only the consensus-selected fetch spread for both
// replicas, never arbitrary directories. Caller randomizes download order.
func (s *Snapshot) OnionDirectories(blinded [32]byte, now time.Time) ([]Relay, error) {
	period, minutes, srv, err := s.OnionPeriod(now)
	if err != nil {
		return nil, err
	}
	type entry struct {
		index [32]byte
		relay Relay
	}
	var ring []entry
	for _, r := range s.relays {
		if !eligible(r) || !r.HasFlag("HSDir") || !r.status.protocols.has("HSDir", 2) {
			continue
		}
		ring = append(ring, entry{onionRelayIndex(r.descriptor.ed25519, srv, period, minutes), r})
	}
	if len(ring) == 0 {
		return nil, ErrPath
	}
	sort.Slice(ring, func(i, j int) bool { return bytes.Compare(ring[i].index[:], ring[j].index[:]) < 0 })
	param := func(name string, def, cap int64) int64 {
		if v, ok := s.consensus.params[name]; ok {
			return max(1, min(v, cap))
		}
		return def
	}
	replicas, spread := param("hsdir_n_replicas", 2, 16), param("hsdir_spread_fetch", 3, 128)
	seen := map[Fingerprint]bool{}
	var out []Relay
	for replica := int64(1); replica <= replicas; replica++ {
		index := onionServiceIndex(blinded, uint64(replica), period, minutes)
		pos := sort.Search(len(ring), func(i int) bool { return bytes.Compare(ring[i].index[:], index[:]) >= 0 })
		found := int64(0)
		for j := 0; j < len(ring) && found < spread; j++ {
			r := ring[(pos+j)%len(ring)].relay
			if seen[r.Identity()] {
				continue
			}
			seen[r.Identity()] = true
			found++
			out = append(out, r)
		}
	}
	return out, nil
}

func onionRelayIndex(identity, srv [32]byte, period, minutes uint64) [32]byte {
	b := append([]byte("node-idx"), identity[:]...)
	b = append(b, srv[:]...)
	b = binary.BigEndian.AppendUint64(b, period)
	b = binary.BigEndian.AppendUint64(b, minutes)
	return sha3.Sum256(b)
}

func onionServiceIndex(blinded [32]byte, replica, period, minutes uint64) [32]byte {
	b := append([]byte("store-at-idx"), blinded[:]...)
	b = binary.BigEndian.AppendUint64(b, replica)
	b = binary.BigEndian.AppendUint64(b, minutes)
	b = binary.BigEndian.AppendUint64(b, period)
	return sha3.Sum256(b)
}

func (s *Snapshot) RelayByIdentity(rsa Fingerprint, ed [32]byte) (Relay, error) {
	for _, r := range s.relays {
		if r.Identity() == rsa && r.descriptor.ed25519 == ed && eligible(r) {
			return r, nil
		}
	}
	return Relay{}, ErrPath
}

// SelectInternalPath selects a three-hop path ending at a verified relay with
// no exit-policy requirement. A nil target selects a random rendezvous relay.
func (s *Snapshot) SelectInternalPath(guard Relay, target *Relay, now time.Time) (Path, error) {
	if !s.Valid(now) {
		return Path{}, ErrTime
	}
	g, err := s.RelayByIdentity(guard.Identity(), guard.descriptor.ed25519)
	if err != nil || !guardEligible(g) {
		return Path{}, ErrPath
	}
	var ends []Relay
	for _, r := range s.relays {
		if !eligible(r) || conflict(g, r) {
			continue
		}
		if target != nil {
			if r.Identity() != target.Identity() || r.Target().Identity != target.Target().Identity {
				continue
			}
		} else if !r.status.protocols.has("HSRend", 1) {
			continue
		}
		ends = append(ends, r)
	}
	end, err := choose(s, ends, "middle")
	if err != nil {
		return Path{}, fmt.Errorf("internal path: %w", err)
	}
	var middles []Relay
	for _, r := range s.relays {
		if eligible(r) && !conflict(g, r) && !conflict(end, r) {
			middles = append(middles, r)
		}
	}
	middle, err := choose(s, middles, "middle")
	if err != nil {
		return Path{}, err
	}
	return Path{g, middle, end}, nil
}
