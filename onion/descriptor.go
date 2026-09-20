package onion

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"

	"filippo.io/edwards25519/field"
	"veil/cell"
	"veil/torcert"
)

const MaxDescriptorSize = 50000

type Introduction struct {
	Links                            []cell.LinkSpec
	OnionKey, AuthKey, EncryptionKey [32]byte
}
type Descriptor struct {
	Introductions []Introduction
	Expires       time.Time
	Revision      uint64
}
type item struct {
	key    string
	args   []string
	object []byte
	label  string
	start  int
}

func parseItems(raw []byte) ([]item, error) {
	if len(raw) == 0 || len(raw) > MaxDescriptorSize || bytes.IndexByte(raw, 0) >= 0 || bytes.IndexByte(raw, '\r') >= 0 {
		return nil, ErrDescriptor
	}
	var out []item
	for offset := 0; offset < len(raw); {
		end := bytes.IndexByte(raw[offset:], '\n')
		if end < 0 {
			end = len(raw) - offset
		} else {
			end++
		}
		end += offset
		line := string(bytes.TrimSuffix(raw[offset:end], []byte{'\n'}))
		args := strings.Fields(line)
		if len(args) == 0 || line[0] == ' ' || line[0] == '\t' || strings.HasPrefix(line, "-----") {
			return nil, ErrDescriptor
		}
		it := item{key: args[0], args: args[1:], start: offset}
		offset = end
		if bytes.HasPrefix(raw[offset:], []byte("-----BEGIN ")) {
			block, rest := pem.Decode(raw[offset:])
			if block == nil || len(block.Headers) != 0 {
				return nil, ErrDescriptor
			}
			it.object, it.label = block.Bytes, block.Type
			offset = len(raw) - len(rest)
		}
		out = append(out, it)
		if len(out) > 2048 {
			return nil, ErrDescriptor
		}
	}
	return out, nil
}
func fields(items []item) (map[string]item, error) {
	out := map[string]item{}
	for _, it := range items {
		if _, exists := out[it.key]; exists {
			return nil, ErrDescriptor
		}
		out[it.key] = it
	}
	return out, nil
}
func b64(s string, n int) ([]byte, error) {
	enc := base64.RawStdEncoding.Strict()
	if strings.Contains(s, "=") {
		enc = base64.StdEncoding.Strict()
	}
	b, e := enc.DecodeString(s)
	if e != nil || len(b) != n {
		return nil, ErrDescriptor
	}
	return b, nil
}
func cert(it item, kind byte, signer [32]byte, now time.Time) ([32]byte, time.Time, error) {
	if it.label != "ED25519 CERT" || len(it.args) != 0 {
		return [32]byte{}, time.Time{}, ErrDescriptor
	}
	return torcert.VerifyOnionCertificate(it.object, kind, signer, now)
}

// ParseDescriptor authenticates the outer signature before decrypting either
// layer, and checks every introduction certificate and key binding. No cache or
// plaintext descriptor is persisted. The caller supplies a verified period key.
func ParseDescriptor(raw []byte, blinded, subcredential [32]byte, now time.Time) (*Descriptor, error) {
	items, err := parseItems(raw)
	if err != nil {
		return nil, err
	}
	if len(items) < 6 || items[0].key != "hs-descriptor" || items[len(items)-1].key != "signature" {
		return nil, ErrDescriptor
	}
	f, err := fields(items)
	if err != nil {
		return nil, err
	}
	if a := f["hs-descriptor"].args; len(a) != 1 || a[0] != "3" {
		return nil, ErrDescriptor
	}
	lifetime := f["descriptor-lifetime"].args
	if len(lifetime) != 1 {
		return nil, ErrDescriptor
	}
	mins, err := strconv.ParseUint(lifetime[0], 10, 16)
	if err != nil || mins < 30 || mins > 720 {
		return nil, ErrDescriptor
	}
	signer, expiry, err := cert(f["descriptor-signing-key-cert"], 8, blinded, now)
	if err != nil {
		return nil, err
	}
	a := f["revision-counter"].args
	if len(a) != 1 {
		return nil, ErrDescriptor
	}
	revision, err := strconv.ParseUint(a[0], 10, 64)
	if err != nil {
		return nil, ErrDescriptor
	}
	sigitem := items[len(items)-1]
	if len(sigitem.args) != 1 || len(sigitem.object) != 0 {
		return nil, ErrDescriptor
	}
	sig, err := b64(sigitem.args[0], 64)
	if err != nil {
		return nil, err
	}
	signed := append([]byte("Tor onion service descriptor sig v3"), raw[:sigitem.start]...)
	if !ed25519.Verify(signer[:], signed, sig) {
		return nil, ErrAuthentication
	}
	if f["superencrypted"].label != "MESSAGE" || len(f["superencrypted"].args) != 0 {
		return nil, ErrDescriptor
	}
	middle, err := decryptLayer(f["superencrypted"].object, blinded, subcredential, revision, "hsdir-superencrypted-data")
	if err != nil {
		return nil, err
	}
	defer clear(middle)
	mitems, err := parseItems(bytes.TrimRight(middle, "\x00"))
	if err != nil {
		return nil, err
	}
	var encrypted []byte
	authType, ephemeral := false, false
	clients := 0
	for _, it := range mitems {
		switch it.key {
		case "desc-auth-type":
			if authType || len(it.args) != 1 || it.args[0] != "x25519" {
				return nil, ErrDescriptor
			}
			authType = true
		case "desc-auth-ephemeral-key":
			if ephemeral || len(it.args) != 1 {
				return nil, ErrDescriptor
			}
			if _, err := b64(it.args[0], 32); err != nil {
				return nil, err
			}
			ephemeral = true
		case "auth-client":
			if len(it.args) != 3 {
				return nil, ErrDescriptor
			}
			for i, n := range []int{8, 16, 16} {
				if _, err := b64(it.args[i], n); err != nil {
					return nil, err
				}
			}
			clients++
		case "encrypted":
			if encrypted != nil || it.label != "MESSAGE" || len(it.args) != 0 {
				return nil, ErrDescriptor
			}
			encrypted = it.object
		}
	}
	if !authType || !ephemeral || clients == 0 || encrypted == nil {
		return nil, ErrDescriptor
	}
	inner, err := decryptLayer(encrypted, blinded, subcredential, revision, "hsdir-encrypted-data")
	if err != nil {
		return nil, ErrRestricted
	}
	defer clear(inner)
	iitems, err := parseItems(bytes.TrimRight(inner, "\x00"))
	if err != nil {
		return nil, err
	}
	d := &Descriptor{Expires: minTime(expiry, now.Add(time.Duration(mins)*time.Minute)), Revision: revision}
	start := len(iitems)
	format := false
	for i, it := range iitems {
		if it.key == "introduction-point" {
			start = i
			break
		}
		switch it.key {
		case "create2-formats":
			if format {
				return nil, ErrDescriptor
			}
			for _, v := range it.args {
				if v == "2" {
					format = true
				}
			}
			if !format {
				return nil, ErrDescriptor
			}
		case "intro-auth-required":
			return nil, ErrRestricted
		}
	}
	if !format {
		return nil, ErrDescriptor
	}
	for start < len(iitems) {
		end := start + 1
		for end < len(iitems) && iitems[end].key != "introduction-point" {
			end++
		}
		f, err := fields(iitems[start:end])
		if err != nil {
			return nil, err
		}
		var intro Introduction
		a := f["introduction-point"].args
		if len(a) != 1 {
			return nil, ErrDescriptor
		}
		encoded, e := base64.RawStdEncoding.Strict().DecodeString(strings.TrimRight(a[0], "="))
		if e != nil {
			return nil, ErrDescriptor
		}
		intro.Links, err = parseLinks(encoded)
		if err != nil {
			return nil, err
		}
		for name, dest := range map[string]*[32]byte{"onion-key": &intro.OnionKey, "enc-key": &intro.EncryptionKey} {
			a := f[name].args
			if len(a) != 2 || a[0] != "ntor" {
				return nil, ErrDescriptor
			}
			b, e := b64(a[1], 32)
			if e != nil {
				return nil, e
			}
			copy(dest[:], b)
		}
		var exp time.Time
		intro.AuthKey, exp, err = cert(f["auth-key"], 9, signer, now)
		if err != nil {
			return nil, err
		}
		d.Expires = minTime(d.Expires, exp)
		subject, exp, err := cert(f["enc-key-cert"], 11, signer, now)
		if err != nil {
			return nil, err
		}
		d.Expires = minTime(d.Expires, exp)
		u, err := new(field.Element).SetBytes(intro.EncryptionKey[:])
		if err != nil {
			return nil, ErrDescriptor
		}
		one := new(field.Element).One()
		denom := new(field.Element).Add(u, one)
		if denom.Equal(new(field.Element).Zero()) == 1 {
			return nil, ErrDescriptor
		}
		y := new(field.Element).Multiply(new(field.Element).Subtract(u, one), new(field.Element).Invert(denom))
		if !bytes.Equal(y.Bytes(), subject[:]) {
			return nil, ErrAuthentication
		}
		d.Introductions = append(d.Introductions, intro)
		if len(d.Introductions) > 20 {
			return nil, ErrDescriptor
		}
		start = end
	}
	if len(d.Introductions) == 0 {
		return nil, ErrDescriptor
	}
	return d, nil
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func parseLinks(b []byte) ([]cell.LinkSpec, error) {
	if len(b) == 0 || b[0] == 0 || b[0] > 32 {
		return nil, ErrDescriptor
	}
	n := int(b[0])
	b = b[1:]
	var out []cell.LinkSpec
	for i := 0; i < n; i++ {
		if len(b) < 2 || int(b[1]) > len(b)-2 {
			return nil, ErrDescriptor
		}
		size := int(b[1])
		out = append(out, cell.LinkSpec{Type: b[0], Data: bytes.Clone(b[2 : 2+size])})
		b = b[2+size:]
	}
	if len(b) != 0 {
		return nil, ErrDescriptor
	}
	// Reject ambiguous or missing identity pins before the relay lookup. Unknown
	// link types are forward compatible; known types still have exact lengths.
	seen := map[byte]bool{}
	address := false
	for _, link := range out {
		switch link.Type {
		case cell.LinkRSAIdentity, cell.LinkEd25519Identity:
			if seen[link.Type] {
				return nil, ErrDescriptor
			}
			seen[link.Type] = true
		case cell.LinkIPv4, cell.LinkIPv6:
			address = true
		}
	}
	if !address || !seen[cell.LinkRSAIdentity] || !seen[cell.LinkEd25519Identity] {
		return nil, ErrDescriptor
	}
	// The codec checks the lengths of recognized link types.
	if _, err := cell.EncodeExtend2(cell.Extend2Message{Links: out, HandshakeType: 2, Handshake: make([]byte, 84)}); err != nil {
		return nil, ErrDescriptor
	}
	return out, nil
}

func decryptLayer(raw []byte, blinded, sub [32]byte, revision uint64, label string) ([]byte, error) {
	if len(raw) < 48 || len(raw) > MaxDescriptorSize {
		return nil, ErrDescriptor
	}
	input := append(append([]byte{}, blinded[:]...), sub[:]...)
	input = binary.BigEndian.AppendUint64(input, revision)
	input = append(input, raw[:16]...)
	input = append(input, label...)
	keys := sha3.SumSHAKE256(input, 80)
	defer clear(keys)
	m := binary.BigEndian.AppendUint64(nil, 32)
	m = append(m, keys[48:]...)
	m = binary.BigEndian.AppendUint64(m, 16)
	m = append(m, raw[:len(raw)-32]...)
	mac := sha3.Sum256(m)
	clear(m)
	if subtle.ConstantTimeCompare(mac[:], raw[len(raw)-32:]) != 1 {
		return nil, ErrAuthentication
	}
	block, err := aes.NewCipher(keys[:32])
	if err != nil {
		return nil, fmt.Errorf("descriptor cipher: %w", err)
	}
	plain := bytes.Clone(raw[16 : len(raw)-32])
	cipher.NewCTR(block, keys[32:48]).XORKeyStream(plain, plain)
	return plain, nil
}
