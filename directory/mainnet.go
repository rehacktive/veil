package directory

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/netip"
	"time"

	"veil/channel"
)

//go:embed data/mainnet.json
var mainnetPins []byte

// Mainnet contains only the independently bundled authority and fallback pins.
// A random subset of 64 fallback identities bounds one manager's bootstrap
// inventory. They are not guards or application paths; those require a verified
// directory and the persistent guard-selection algorithm.
func Mainnet() ([]Fingerprint, []TorSource, error) {
	roots, sources, err := parseMainnet(mainnetPins)
	if err != nil {
		return nil, nil, err
	}
	for i := len(sources) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, nil, err
		}
		j := int(n.Int64())
		sources[i], sources[j] = sources[j], sources[i]
	}
	return roots, sources[:min(64, len(sources))], nil
}
func parseMainnet(raw []byte) ([]Fingerprint, []TorSource, error) {
	var pins struct {
		Authorities []string `json:"authorities"`
		Fallbacks   []struct {
			RSA       string   `json:"rsa"`
			Ed25519   string   `json:"ed25519"`
			Addresses []string `json:"addresses"`
		} `json:"fallbacks"`
	}
	if err := json.Unmarshal(raw, &pins); err != nil {
		return nil, nil, err
	}
	if len(pins.Authorities) != 9 || len(pins.Fallbacks) < 64 || len(pins.Fallbacks) > 1024 {
		return nil, nil, errors.New("invalid bundled mainnet pin counts")
	}
	roots := make([]Fingerprint, 0, len(pins.Authorities))
	for _, s := range pins.Authorities {
		p, err := ParseFingerprint(s)
		if err != nil {
			return nil, nil, err
		}
		roots = append(roots, p)
	}
	if _, err := newAuthoritySet(roots); err != nil {
		return nil, nil, err
	}
	var sources []TorSource
	seen := map[Fingerprint]bool{}
	for _, f := range pins.Fallbacks {
		rsa, err := ParseFingerprint(f.RSA)
		if err != nil || seen[rsa] {
			return nil, nil, errors.New("invalid bundled fallback identity")
		}
		seen[rsa] = true
		ed, err := hex.DecodeString(f.Ed25519)
		if err != nil || len(ed) != 32 {
			return nil, nil, errors.New("invalid bundled Ed25519 identity")
		}
		var target channel.Target
		copy(target.Identity.RSA[:], rsa[:])
		copy(target.Identity.Ed25519[:], ed)
		if err := target.Identity.Validate(); err != nil {
			return nil, nil, err
		}
		for _, s := range f.Addresses {
			a, err := netip.ParseAddrPort(s)
			if err != nil || a.Port() == 0 || !a.Addr().IsGlobalUnicast() || a.Addr().IsPrivate() || a.Addr().IsLoopback() || a.Addr().Zone() != "" {
				return nil, nil, errors.New("invalid bundled fallback address")
			}
			// IPv4 bootstrap works on dual-stack and IPv4-only hosts. Verified paths
			// and SOCKS requests retain their separate IPv6 support.
			if target.Address.IsValid() || !a.Addr().Is4() {
				continue
			}
			target.Address = a
		}
		if !target.Address.IsValid() {
			return nil, nil, errors.New("bundled fallback lacks IPv4")
		}
		sources = append(sources, TorSource{Target: target, DirectoryOnlyFast: true, Timeout: time.Minute})
	}
	return roots, sources, nil
}
