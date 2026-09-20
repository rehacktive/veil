// Package onion implements v3 onion identities, descriptors and hs-ntor.
package onion

import (
	"bytes"
	"crypto/sha3"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"strings"

	"filippo.io/edwards25519"
)

var (
	ErrAddress        = errors.New("invalid v3 onion address")
	ErrDescriptor     = errors.New("invalid onion service descriptor")
	ErrAuthentication = errors.New("onion service authentication failed")
	ErrRestricted     = errors.New("onion descriptor could not be decrypted or requires unsupported client authorization")
)

// IsAddress also recognizes malformed and legacy onion names so callers must
// reject them locally instead of handing them to an exit or DNS resolver.
func IsAddress(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	return h == "onion" || strings.HasSuffix(h, ".onion")
}

func ParseAddress(host string) (key [32]byte, err error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if len(host) != 62 || !strings.HasSuffix(host, ".onion") {
		return key, ErrAddress
	}
	b, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(host[:56]))
	if e != nil || len(b) != 35 || b[34] != 3 {
		return key, ErrAddress
	}
	copy(key[:], b[:32])
	check := sha3.Sum256(append(append([]byte(".onion checksum"), key[:]...), 3))
	if !bytes.Equal(b[32:34], check[:2]) {
		return [32]byte{}, ErrAddress
	}
	p, e := new(edwards25519.Point).SetBytes(key[:])
	if e != nil || new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 || !bytes.Equal(p.Bytes(), key[:]) {
		return [32]byte{}, ErrAddress
	}
	return key, nil
}

func Blind(key [32]byte, period, minutes uint64) (blinded, subcredential [32]byte, err error) {
	p, e := new(edwards25519.Point).SetBytes(key[:])
	if e != nil {
		return blinded, subcredential, ErrAddress
	}
	b := append([]byte("Derive temporary signing key\x00"), key[:]...)
	b = append(b, []byte("(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)key-blind")...)
	b = binary.BigEndian.AppendUint64(b, period)
	b = binary.BigEndian.AppendUint64(b, minutes)
	h := sha3.Sum256(b)
	scalar, e := new(edwards25519.Scalar).SetBytesWithClamping(h[:])
	if e != nil {
		return blinded, subcredential, e
	}
	copy(blinded[:], new(edwards25519.Point).ScalarMult(scalar, p).Bytes())
	cred := sha3.Sum256(append([]byte("credential"), key[:]...))
	subcredential = sha3.Sum256(append(append([]byte("subcredential"), cred[:]...), blinded[:]...))
	return blinded, subcredential, nil
}
