package directory

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
)

type portPolicy struct {
	accept bool
	ports  []interval
}

func (p portPolicy) allows(port uint16) bool {
	if port == 0 || len(p.ports) == 0 {
		return false
	}
	found := false
	for _, r := range p.ports {
		if port >= r.low && port <= r.high {
			found = true
			break
		}
	}
	return found == p.accept
}
func parsePolicy(args []string) (portPolicy, error) {
	var p portPolicy
	if len(args) != 2 || (args[0] != "accept" && args[0] != "reject") {
		return p, fmt.Errorf("%w: port policy", ErrDocument)
	}
	p.accept = args[0] == "accept"
	for _, part := range strings.Split(args[1], ",") {
		a, b, ok := strings.Cut(part, "-")
		if !ok {
			b = a
		}
		lo, err := number16(a)
		if err != nil || lo == 0 {
			return p, fmt.Errorf("%w: port range", ErrDocument)
		}
		hi, err := number16(b)
		if err != nil || hi < lo {
			return p, fmt.Errorf("%w: port range", ErrDocument)
		}
		p.ports = append(p.ports, interval{lo, hi})
		if len(p.ports) > 4096 {
			return p, fmt.Errorf("%w: too many port ranges", ErrDocument)
		}
	}
	return p, nil
}

type microdescriptor struct {
	digest        [32]byte
	ntor, ed25519 [32]byte
	family        map[Fingerprint]bool
	familyIDs     map[string]bool
	ipv4, ipv6    portPolicy
}

func parseMicrodescriptor(raw []byte) (microdescriptor, error) {
	var m microdescriptor
	items, err := lex(raw, MaxMicrodescriptorSize)
	if err != nil {
		return m, err
	}
	if items[0].key != "onion-key" || len(items[0].args) != 0 {
		return m, fmt.Errorf("%w: microdescriptor start", ErrDocument)
	}
	if items[0].object != nil {
		if _, err := publicKey(items[0]); err != nil {
			return m, err
		}
	}
	seen := map[string]bool{}
	m.family = map[Fingerprint]bool{}
	m.familyIDs = map[string]bool{}
	// Omitted policies mean reject all (including IPv6).
	m.ipv4 = portPolicy{accept: true}
	m.ipv6 = portPolicy{accept: true}
	for _, it := range items[1:] {
		if seen[it.key] {
			return m, fmt.Errorf("%w: duplicate microdescriptor field", ErrDocument)
		}
		seen[it.key] = true
		if it.object != nil {
			return m, fmt.Errorf("%w: unexpected microdescriptor object", ErrDocument)
		}
		switch it.key {
		case "ntor-onion-key":
			if len(it.args) != 1 {
				return m, fmt.Errorf("%w: ntor key", ErrDocument)
			}
			b, err := unbase64(it.args[0], 32)
			if err != nil {
				return m, err
			}
			copy(m.ntor[:], b)
		case "id":
			if len(it.args) != 2 || it.args[0] != "ed25519" {
				return m, fmt.Errorf("%w: microdescriptor identity", ErrDocument)
			}
			b, err := unbase64(it.args[1], 32)
			if err != nil {
				return m, err
			}
			copy(m.ed25519[:], b)
		case "family":
			for _, entry := range it.args {
				if !strings.HasPrefix(entry, "$") {
					continue
				} // Nicknames cannot establish a trusted family.
				fp := strings.FieldsFunc(entry[1:], func(r rune) bool { return r == '=' || r == '~' })
				if len(fp) == 0 {
					return m, ErrDocument
				}
				id, err := ParseFingerprint(fp[0])
				if err != nil {
					return m, err
				}
				m.family[id] = true
			}
		case "family-ids":
			for _, id := range it.args {
				m.familyIDs[id] = true
			}
		case "p":
			m.ipv4, err = parsePolicy(it.args)
			if err != nil {
				return m, err
			}
		case "p6":
			m.ipv6, err = parsePolicy(it.args)
			if err != nil {
				return m, err
			}
		case "a": // Older microdescriptors contain addresses; consensus addresses take precedence.
		default:
			return m, fmt.Errorf("%w: unsupported microdescriptor field %s", ErrDocument, it.key)
		}
	}
	if m.ntor == ([32]byte{}) {
		return m, fmt.Errorf("%w: missing/zero ntor key", ErrDocument)
	}
	m.digest = sha256.Sum256(raw)
	return m, nil
}

// splitMicrodescriptors accepts wire documents only. Cache annotations are not
// signed and are deliberately excluded from this API.
func splitMicrodescriptors(raw []byte, limit int) ([][]byte, error) {
	if len(raw) == 0 || len(raw) > limit || !bytes.HasPrefix(raw, []byte("onion-key\n")) {
		return nil, fmt.Errorf("%w: microdescriptor batch", ErrDocument)
	}
	var parts [][]byte
	for len(raw) > 0 {
		end := bytes.Index(raw, []byte("\nonion-key\n"))
		if end < 0 {
			end = len(raw)
		} else {
			end++
		}
		if end > MaxMicrodescriptorSize {
			return nil, fmt.Errorf("%w: microdescriptor size", ErrDocument)
		}
		parts = append(parts, raw[:end])
		raw = raw[end:]
		if len(parts) > MaxRelays {
			return nil, fmt.Errorf("%w: microdescriptor count", ErrDocument)
		}
	}
	return parts, nil
}
