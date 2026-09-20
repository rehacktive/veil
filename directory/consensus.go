package directory

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- Verification-only support for Tor's legacy directory-signature algorithm; directory digests use SHA-256.
	"crypto/sha256"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type interval struct{ low, high uint16 }
type protocols map[string][]interval

func (p protocols) has(name string, v uint16) bool {
	for _, r := range p[name] {
		if v >= r.low && v <= r.high {
			return true
		}
	}
	return false
}
func parseProtocols(args []string) (protocols, error) {
	p := protocols{}
	for _, arg := range args {
		name, values, ok := strings.Cut(arg, "=")
		if !ok || name == "" || p[name] != nil {
			return nil, fmt.Errorf("%w: protocol list", ErrDocument)
		}
		for _, v := range strings.Split(values, ",") {
			a, b, ranged := strings.Cut(v, "-")
			if !ranged {
				b = a
			}
			lo, err := number16(a)
			if err != nil {
				return nil, err
			}
			hi, err := number16(b)
			if err != nil || hi < lo {
				return nil, fmt.Errorf("%w: protocol range", ErrDocument)
			}
			p[name] = append(p[name], interval{lo, hi})
			if len(p[name]) > 128 {
				return nil, fmt.Errorf("%w: protocol ranges", ErrDocument)
			}
		}
	}
	return p, nil
}

type relayStatus struct {
	rsa       Fingerprint
	nickname  string
	address   netip.AddrPort
	extra     []netip.AddrPort
	digest    [32]byte
	flags     map[string]bool
	protocols protocols
	bandwidth uint64
}
type consensus struct {
	validAfter, freshUntil, validUntil time.Time
	digest                             [32]byte
	relays                             []relayStatus
	weights                            map[string]uint64
	params                             map[string]int64
	signatures                         int
}

func verifyConsensus(raw []byte, set *authoritySet, now time.Time) (*consensus, error) {
	items, err := lex(raw, MaxConsensusSize)
	if err != nil {
		return nil, err
	}
	if items[0].key != "network-status-version" || len(items[0].args) != 2 || items[0].args[0] != "3" || items[0].args[1] != "microdesc" {
		return nil, fmt.Errorf("%w: only v3 microdescriptor consensuses are supported", ErrDocument)
	}
	c := &consensus{weights: map[string]uint64{}, params: map[string]int64{}}
	head := map[string]item{}
	i := 0
	for i < len(items) && items[i].key != "dir-source" {
		it := items[i]
		if it.key == "r" || it.key == "directory-footer" || it.key == "directory-signature" {
			return nil, fmt.Errorf("%w: missing authority section", ErrDocument)
		}
		if _, ok := head[it.key]; ok {
			return nil, fmt.Errorf("%w: duplicate header", ErrDocument)
		}
		head[it.key] = it
		i++
	}
	if v := head["vote-status"]; len(v.args) != 1 || v.args[0] != "consensus" {
		return nil, fmt.Errorf("%w: expected consensus", ErrDocument)
	}
	if c.validAfter, err = date(head["valid-after"].args); err != nil {
		return nil, err
	}
	if c.freshUntil, err = date(head["fresh-until"].args); err != nil {
		return nil, err
	}
	if c.validUntil, err = date(head["valid-until"].args); err != nil {
		return nil, err
	}
	if !c.validAfter.Before(c.freshUntil) || !c.freshUntil.Before(c.validUntil) || now.Before(c.validAfter) || !now.Before(c.validUntil) {
		return nil, ErrTime
	}
	if _, ok := head["known-flags"]; !ok {
		return nil, fmt.Errorf("%w: missing known-flags", ErrDocument)
	}
	if _, ok := head["voting-delay"]; !ok {
		return nil, fmt.Errorf("%w: missing voting-delay", ErrDocument)
	}
	if v := head["consensus-method"]; len(v.args) != 1 {
		return nil, fmt.Errorf("%w: consensus method", ErrDocument)
	} else if _, err := number(v.args[0], 16); err != nil {
		return nil, err
	}
	required, err := parseProtocols(head["required-client-protocols"].args)
	if err != nil {
		return nil, err
	}
	supported, _ := parseProtocols([]string{"Cons=1-2", "Desc=1-2,4", "DirCache=1-2", "FlowCtrl=1", "Link=4-5", "Microdesc=1-2", "Relay=2"})
	for name, ranges := range required {
		for _, r := range ranges {
			for v := r.low; ; v++ {
				if !supported.has(name, v) {
					return nil, fmt.Errorf("%w: %s=%d", ErrUnsupported, name, v)
				}
				if v == r.high {
					break // Stop before incrementing 65535 and wrapping uint16.
				}
			}
		}
	}
	if it, ok := head["params"]; ok {
		for _, arg := range it.args {
			key, value, ok := strings.Cut(arg, "=")
			if !ok {
				return nil, fmt.Errorf("%w: parameter", ErrDocument)
			}
			if _, dup := c.params[key]; dup {
				return nil, fmt.Errorf("%w: duplicate parameter", ErrDocument)
			}
			v, err := signedNumber(value, 32)
			if err != nil {
				return nil, err
			}
			c.params[key] = v
		}
	}
	seenAuthorities := map[Fingerprint]bool{}
	for i < len(items) && items[i].key != "r" && items[i].key != "directory-footer" {
		it := items[i]
		switch it.key {
		case "dir-source":
			if len(it.args) != 6 {
				return nil, fmt.Errorf("%w: authority entry", ErrDocument)
			}
			fp, err := ParseFingerprint(it.args[1])
			if err != nil || seenAuthorities[fp] {
				return nil, fmt.Errorf("%w: duplicate/bad authority source", ErrDocument)
			}
			seenAuthorities[fp] = true
		case "contact", "vote-digest":
		default:
			return nil, fmt.Errorf("%w: authority section item", ErrDocument)
		}
		i++
	}
	if len(seenAuthorities) == 0 {
		return nil, fmt.Errorf("%w: no authority sources", ErrDocument)
	}
	seenRelays := map[Fingerprint]bool{}
	for i < len(items) && items[i].key == "r" {
		start := i
		i++
		for i < len(items) && items[i].key != "r" && items[i].key != "directory-footer" {
			i++
		}
		r, err := parseStatus(items[start:i])
		if err != nil {
			return nil, err
		}
		if seenRelays[r.rsa] {
			return nil, fmt.Errorf("%w: duplicate relay identity", ErrDocument)
		}
		seenRelays[r.rsa] = true
		c.relays = append(c.relays, r)
		if len(c.relays) > MaxRelays {
			return nil, fmt.Errorf("%w: relay count", ErrDocument)
		}
	}
	if i >= len(items) || items[i].key != "directory-footer" || len(items[i].args) != 0 {
		return nil, fmt.Errorf("%w: missing directory footer", ErrDocument)
	}
	i++
	if i < len(items) && items[i].key == "bandwidth-weights" {
		scale := int64(10000)
		if v, ok := c.params["bwweightscale"]; ok {
			scale = v
		}
		if scale < 1 || scale > 1000000000 {
			return nil, fmt.Errorf("%w: bandwidth scale", ErrDocument)
		}
		for _, arg := range items[i].args {
			key, value, ok := strings.Cut(arg, "=")
			if !ok {
				return nil, fmt.Errorf("%w: bandwidth weight", ErrDocument)
			}
			if _, dup := c.weights[key]; dup {
				return nil, fmt.Errorf("%w: duplicate bandwidth weight", ErrDocument)
			}
			v, err := number(value, 32)
			if err != nil || v > uint64(scale) {
				return nil, fmt.Errorf("%w: bandwidth weight range", ErrDocument)
			}
			c.weights[key] = v
		}
		i++
		for _, key := range []string{"Wgg", "Wgd", "Wmg", "Wmd", "Wme", "Wmm", "Wee", "Wed"} {
			if _, ok := c.weights[key]; !ok {
				return nil, fmt.Errorf("%w: missing bandwidth weight %s", ErrDocument, key)
			}
		}
	}
	if i >= len(items) || !bytes.HasPrefix(raw[items[i].start:], []byte("directory-signature ")) {
		return nil, fmt.Errorf("%w: consensus signature start", ErrDocument)
	}
	signed := raw[:items[i].start+len("directory-signature ")]
	sha256Digest := sha256.Sum256(signed)
	sha1Digest := sha1.Sum(signed) // #nosec G401 -- Verify explicitly labeled/default legacy Tor signatures under the configured authority quorum; never generate SHA-1 signatures.
	c.digest = sha256Digest
	counted := map[Fingerprint]bool{}
	for ; i < len(items); i++ {
		it := items[i]
		if it.key != "directory-signature" {
			return nil, fmt.Errorf("%w: item after signatures", ErrDocument)
		}
		args := it.args
		algorithm := "sha1"
		if len(args) == 3 {
			algorithm = args[0]
			args = args[1:]
		}
		if len(args) != 2 {
			return nil, fmt.Errorf("%w: signature arguments", ErrDocument)
		}
		id, err := ParseFingerprint(args[0])
		if err != nil {
			return nil, err
		}
		signing, err := ParseFingerprint(args[1])
		if err != nil {
			return nil, err
		}
		sig, err := object(it, "SIGNATURE")
		if err != nil {
			return nil, err
		}
		cert, ok := set.certs[certKey{id, signing}]
		if !ok || !set.roots[id] || counted[id] || !seenAuthorities[id] {
			continue
		}
		if cert.published.After(c.validAfter) || cert.expires.Before(c.validUntil) {
			continue
		}
		var digest []byte
		switch algorithm {
		case "sha256":
			digest = sha256Digest[:]
		case "sha1":
			digest = sha1Digest[:]
		default:
			continue
		}
		if rsa.VerifyPKCS1v15(cert.key, crypto.Hash(0), digest, sig) == nil {
			counted[id] = true
		}
	}
	c.signatures = len(counted)
	if c.signatures < len(set.roots)/2+1 {
		return nil, fmt.Errorf("%w: %d signatures; need %d of %d pinned authorities", ErrTrust, c.signatures, len(set.roots)/2+1, len(set.roots))
	}
	return c, nil
}

func parseStatus(items []item) (relayStatus, error) {
	var r relayStatus
	it := items[0]
	if len(it.args) != 7 {
		return r, fmt.Errorf("%w: router status arguments", ErrDocument)
	}
	r.nickname = it.args[0]
	identity, err := unbase64(it.args[1], 20)
	if err != nil {
		return r, err
	}
	copy(r.rsa[:], identity)
	if _, err := date(it.args[2:4]); err != nil {
		return r, err
	}
	ip, err := netip.ParseAddr(it.args[4])
	if err != nil || !ip.Is4() {
		return r, fmt.Errorf("%w: router IPv4", ErrDocument)
	}
	port, err := number16(it.args[5])
	if err != nil || port == 0 {
		return r, fmt.Errorf("%w: OR port", ErrDocument)
	}
	r.address = netip.AddrPortFrom(ip, port)
	if _, err := number(it.args[6], 16); err != nil {
		return r, err
	}
	seen := map[string]bool{}
	for _, it := range items[1:] {
		if it.key != "a" && seen[it.key] {
			return r, fmt.Errorf("%w: duplicate router field", ErrDocument)
		}
		seen[it.key] = true
		switch it.key {
		case "a":
			if len(it.args) != 1 || len(r.extra) >= 8 {
				return r, fmt.Errorf("%w: alternate address", ErrDocument)
			}
			a, err := netip.ParseAddrPort(it.args[0])
			if err != nil || a.Port() == 0 || a.Addr().Zone() != "" {
				return r, fmt.Errorf("%w: alternate address", ErrDocument)
			}
			r.extra = append(r.extra, a)
		case "m":
			if len(it.args) != 1 {
				return r, fmt.Errorf("%w: microdescriptor digest", ErrDocument)
			}
			b, err := unbase64(it.args[0], 32)
			if err != nil {
				return r, err
			}
			copy(r.digest[:], b)
		case "s":
			r.flags = map[string]bool{}
			for _, f := range it.args {
				if r.flags[f] {
					return r, fmt.Errorf("%w: duplicate flag", ErrDocument)
				}
				r.flags[f] = true
			}
		case "pr":
			r.protocols, err = parseProtocols(it.args)
			if err != nil {
				return r, err
			}
		case "w":
			values := map[string]bool{}
			for _, arg := range it.args {
				key, value, ok := strings.Cut(arg, "=")
				if !ok || values[key] {
					return r, fmt.Errorf("%w: router bandwidth", ErrDocument)
				}
				values[key] = true
				if key == "Bandwidth" {
					r.bandwidth, err = number(value, 32)
					if err != nil {
						return r, err
					}
				}
			}
			if !values["Bandwidth"] {
				return r, fmt.Errorf("%w: missing bandwidth", ErrDocument)
			}
		case "v", "p", "id": // Version, legacy policy/identity extensions are not trust sources.
		default:
			return r, fmt.Errorf("%w: unsupported router status item %s", ErrDocument, it.key)
		}
	}
	for _, key := range []string{"m", "s", "pr", "w"} {
		if !seen[key] {
			return r, fmt.Errorf("%w: missing router %s", ErrDocument, key)
		}
	}
	return r, nil
}
