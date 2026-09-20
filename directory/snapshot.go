package directory

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"time"

	"veil/channel"
	"veil/ntor"
	"veil/torcert"
)

// Documents contains untrusted wire bytes, with no Tor disk-cache annotations.
type Documents struct {
	Certificates     []byte `json:"certificates"`
	Consensus        []byte `json:"consensus"`
	Microdescriptors []byte `json:"microdescriptors"`
}

// Snapshot is immutable authenticated directory data. Its zero value is invalid.
// Callers must check validity at use time; an authentic document can expire.
type Snapshot struct {
	consensus *consensus
	relays    []Relay
}

// Relay is a view of authenticated status and microdescriptor data. Keeping its
// internals private prevents callers from accidentally altering a snapshot.
type Relay struct {
	status     relayStatus
	descriptor microdescriptor
}

func (r Relay) Identity() Fingerprint    { return r.status.rsa }
func (r Relay) Nickname() string         { return r.status.nickname }
func (r Relay) Address() netip.AddrPort  { return r.status.address }
func (r Relay) HasFlag(flag string) bool { return r.status.flags[flag] }
func (r Relay) Bandwidth() uint64        { return r.status.bandwidth }
func (r Relay) Target() channel.Target {
	return channel.Target{Address: r.status.address, Identity: torcert.Identity{RSA: r.status.rsa, Ed25519: r.descriptor.ed25519}}
}
func (r Relay) NTor() ntor.Relay {
	return ntor.Relay{Identity: r.status.rsa, OnionKey: r.descriptor.ntor}
}

type Info struct {
	ValidAfter          time.Time `json:"valid_after"`
	FreshUntil          time.Time `json:"fresh_until"`
	ValidUntil          time.Time `json:"valid_until"`
	AuthoritySignatures int       `json:"authority_signatures"`
	Relays              int       `json:"relays"`
}

func (s *Snapshot) Info() Info {
	if s == nil || s.consensus == nil {
		return Info{}
	}
	c := s.consensus
	return Info{c.validAfter, c.freshUntil, c.validUntil, c.signatures, len(s.relays)}
}
func (s *Snapshot) Valid(now time.Time) bool {
	return s != nil && s.consensus != nil && !now.Before(s.consensus.validAfter) && now.Before(s.consensus.validUntil)
}
func (s *Snapshot) Fresh(now time.Time) bool {
	return s.Valid(now) && now.Before(s.consensus.freshUntil)
}
func (s *Snapshot) Relays() []Relay {
	if s == nil {
		return nil
	}
	return append([]Relay(nil), s.relays...)
}

// Verify requires a majority of all configured authorities and every referenced
// microdescriptor. A partial directory is never exposed for biased selection.
// The caller supplies time explicitly to support controlled, offline validation.
func Verify(d Documents, roots []Fingerprint, now time.Time) (*Snapshot, error) {
	set, err := authorities(d.Certificates, roots, now)
	if err != nil {
		return nil, err
	}
	c, err := verifyConsensus(d.Consensus, set, now)
	if err != nil {
		return nil, err
	}
	return complete(c, d.Microdescriptors)
}
func complete(c *consensus, raw []byte) (*Snapshot, error) {
	if len(c.relays) == 0 {
		return nil, fmt.Errorf("%w: empty consensus", ErrDocument)
	}
	parts, err := splitMicrodescriptors(raw, MaxMicrodescriptorsSize)
	if err != nil {
		return nil, err
	}
	wanted := map[[32]byte]bool{}
	for _, r := range c.relays {
		wanted[r.digest] = true
	}
	descriptors := map[[32]byte]microdescriptor{}
	for _, part := range parts {
		digest := sha256.Sum256(part)
		if !wanted[digest] {
			return nil, fmt.Errorf("%w: unrequested microdescriptor digest", ErrTrust)
		}
		if _, ok := descriptors[digest]; ok {
			return nil, fmt.Errorf("%w: duplicate microdescriptor", ErrDocument)
		}
		m, err := parseMicrodescriptor(part)
		if err != nil {
			return nil, err
		}
		descriptors[digest] = m
	}
	s := &Snapshot{consensus: c}
	for _, r := range c.relays {
		m, ok := descriptors[r.digest]
		if !ok {
			return nil, fmt.Errorf("%w: missing microdescriptor", ErrTrust)
		}
		if r.flags["NoEdConsensus"] {
			m.ed25519 = [32]byte{}
		}
		s.relays = append(s.relays, Relay{r, m})
	}
	return s, nil
}
