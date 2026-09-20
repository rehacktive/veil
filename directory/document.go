// Package directory verifies Tor microdescriptor directories and selects paths
// from authenticated data. Trust anchors are supplied explicitly by the caller.
package directory

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	MaxConsensusSize        = 16 << 20
	MaxCertificatesSize     = 2 << 20
	MaxMicrodescriptorSize  = 64 << 10
	MaxMicrodescriptorsSize = 64 << 20 // Bounded complete mainnet directory; family lists exceed the former 32 MiB budget.
	MaxMicrodescriptorBatch = 4 << 20
	MaxRelays               = 20000
)

var (
	ErrDocument    = errors.New("invalid Tor directory document")
	ErrTrust       = errors.New("Tor directory trust verification failed")
	ErrTime        = errors.New("Tor directory outside validity interval; check clock and refresh")
	ErrUnsupported = errors.New("required Tor protocol is not supported")
)

type Fingerprint [20]byte

func ParseFingerprint(s string) (Fingerprint, error) {
	var f Fingerprint
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(f) {
		return f, fmt.Errorf("%w: authority/relay fingerprint must be 40 hex characters", ErrDocument)
	}
	copy(f[:], b)
	return f, nil
}
func (f Fingerprint) String() string { return hex.EncodeToString(f[:]) }

type item struct {
	key                 string
	args                []string
	object              *pem.Block
	start, lineEnd, end int
}

// lex preserves byte offsets: signatures always cover original bytes, never a
// reconstructed or normalized representation. Objects are not interpreted as items.
func lex(raw []byte, limit int) ([]item, error) {
	if len(raw) == 0 || len(raw) > limit || raw[len(raw)-1] != '\n' || bytes.IndexByte(raw, 0) >= 0 || bytes.IndexByte(raw, '\r') >= 0 {
		return nil, fmt.Errorf("%w: size, line ending, or NUL", ErrDocument)
	}
	var out []item
	for offset := 0; offset < len(raw); {
		end := offset + bytes.IndexByte(raw[offset:], '\n') + 1
		if end <= offset || end-offset > 65536 {
			return nil, fmt.Errorf("%w: line length", ErrDocument)
		}
		line := string(raw[offset : end-1])
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return nil, fmt.Errorf("%w: empty line", ErrDocument)
		}
		if line[0] == ' ' || line[0] == '\t' || strings.HasPrefix(fields[0], "-----") || fields[0][0] == '@' {
			return nil, fmt.Errorf("%w: misplaced object or annotation", ErrDocument)
		}
		it := item{key: fields[0], args: fields[1:], start: offset, lineEnd: end, end: end}
		if bytes.HasPrefix(raw[end:], []byte("-----BEGIN ")) {
			objectEnd := bytes.Index(raw[end:], []byte("-----END "))
			if objectEnd < 0 {
				return nil, fmt.Errorf("%w: unterminated object", ErrDocument)
			}
			last := end + objectEnd
			last += bytes.IndexByte(raw[last:], '\n') + 1
			if last <= end || last-end > 16384 {
				return nil, fmt.Errorf("%w: object size", ErrDocument)
			}
			objectBytes := raw[end:last]
			if bytes.Count(objectBytes, []byte("-----BEGIN ")) != 1 {
				return nil, fmt.Errorf("%w: nested object", ErrDocument)
			}
			block, rest := pem.Decode(objectBytes)
			if block == nil || len(rest) != 0 || len(block.Headers) != 0 {
				return nil, fmt.Errorf("%w: malformed PEM", ErrDocument)
			}
			it.object = block
			it.end = last
		}
		out = append(out, it)
		if len(out) > 250000 {
			return nil, fmt.Errorf("%w: item count", ErrDocument)
		}
		offset = it.end
	}
	return out, nil
}

func object(it item, labels ...string) ([]byte, error) {
	if it.object != nil {
		for _, label := range labels {
			if it.object.Type == label {
				return it.object.Bytes, nil
			}
		}
	}
	return nil, fmt.Errorf("%w: expected object for %s", ErrDocument, it.key)
}
func publicKey(it item) (*rsa.PublicKey, error) {
	b, err := object(it, "RSA PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS1PublicKey(b)
	if err != nil || k.N.BitLen() < 1024 || k.N.BitLen() > 8192 || k.E != 65537 {
		return nil, fmt.Errorf("%w: RSA public key", ErrDocument)
	}
	return k, nil
}
func date(args []string) (time.Time, error) {
	if len(args) != 2 {
		return time.Time{}, fmt.Errorf("%w: timestamp arguments", ErrDocument)
	}
	t, err := time.Parse("2006-01-02 15:04:05", strings.Join(args, " "))
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: timestamp", ErrDocument)
	}
	return t, nil
}
func number(s string, bits int) (uint64, error) {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, fmt.Errorf("%w: unsigned integer", ErrDocument)
	}
	n, err := strconv.ParseUint(s, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("%w: integer overflow", ErrDocument)
	}
	return n, nil
}

// number16 keeps the checked wire width in the return type, so callers do not
// need to narrow a uint64 after validation in another function.
func number16(s string) (uint16, error) {
	n, err := number(s, 16)
	if err != nil {
		return 0, err
	}
	if n > 65535 {
		return 0, fmt.Errorf("%w: integer overflow", ErrDocument)
	}
	return uint16(n), nil
}

func signedNumber(s string, bits int) (int64, error) {
	digits := strings.TrimPrefix(s, "-")
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return 0, fmt.Errorf("%w: signed integer", ErrDocument)
	}
	n, err := strconv.ParseInt(s, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("%w: integer overflow", ErrDocument)
	}
	return n, nil
}
func unbase64(s string, size int) ([]byte, error) {
	encoding := base64.RawStdEncoding.Strict()
	if strings.Contains(s, "=") {
		encoding = base64.StdEncoding.Strict()
	}
	b, err := encoding.DecodeString(s)
	if err != nil || len(b) != size {
		return nil, fmt.Errorf("%w: base64 digest/key", ErrDocument)
	}
	return b, nil
}
func unique(items []item) (map[string]item, error) {
	m := make(map[string]item, len(items))
	for _, it := range items {
		if _, ok := m[it.key]; ok {
			return nil, fmt.Errorf("%w: duplicate %s", ErrDocument, it.key)
		}
		m[it.key] = it
	}
	return m, nil
}
