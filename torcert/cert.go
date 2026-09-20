// Package torcert authenticates Tor relay identities and their binding to a TLS
// certificate. It implements the modern Ed25519 chain and legacy RSA crosscert.
package torcert

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- Legacy Tor RSA identity fingerprints are SHA-1; the TLS binding and Ed25519 chain are verified separately.
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"veil/cell"
)

const (
	RSAIdentity     = 2
	IdentitySigning = 4
	SigningTLS      = 5
	RSAToEd25519    = 7
)

var ErrCertificate = errors.New("invalid Tor certificate chain")

// Identity contains pins obtained out of band or from a verified descriptor.
// This stage requires both pins; it never learns trust from an unverified peer.
type Identity struct {
	RSA     [20]byte
	Ed25519 [32]byte
}

func (id Identity) Validate() error {
	if id.RSA == ([20]byte{}) || id.Ed25519 == ([32]byte{}) {
		return fmt.Errorf("%w: both RSA and Ed25519 identity pins are required", ErrCertificate)
	}
	return nil
}

type Verified struct {
	Identity Identity
	Expires  time.Time // Earliest expiry of the authenticated chain.
}

// Verify binds the exact DER TLS leaf certificate to both expected relay pins.
// Ordinary Web PKI hostname/CA verification is not part of Tor authentication.
// now is supplied explicitly so validity checks can be tested deterministically.
func Verify(certs []cell.Certificate, tlsLeafDER []byte, expected Identity, now time.Time) (Verified, error) {
	if len(tlsLeafDER) == 0 {
		return Verified{}, fmt.Errorf("%w: missing TLS certificate", ErrCertificate)
	}
	return verifyDigest(certs, sha256.Sum256(tlsLeafDER), expected, now)
}

func verifyDigest(certs []cell.Certificate, tlsDigest [32]byte, expected Identity, now time.Time) (Verified, error) {
	if err := expected.Validate(); err != nil {
		return Verified{}, err
	}
	if len(certs) > 255 {
		return Verified{}, fmt.Errorf("%w: too many certificates", ErrCertificate)
	}
	byType := make(map[uint8][]byte, len(certs))
	for _, cert := range certs {
		if _, exists := byType[cert.Type]; exists || len(cert.Body) > 65535 {
			return Verified{}, fmt.Errorf("%w: duplicate type or oversized certificate", ErrCertificate)
		}
		byType[cert.Type] = cert.Body
	}
	for _, tp := range []uint8{RSAIdentity, IdentitySigning, SigningTLS, RSAToEd25519} {
		if len(byType[tp]) == 0 {
			return Verified{}, fmt.Errorf("%w: missing certificate type %d", ErrCertificate, tp)
		}
	}
	signing, err := parseEd(byType[IdentitySigning], IdentitySigning)
	if err != nil {
		return Verified{}, err
	}
	if signing.keyType != 1 || signing.signer == nil || *signing.signer != expected.Ed25519 {
		return Verified{}, fmt.Errorf("%w: identity signing key or subject mismatch", ErrCertificate)
	}
	if err := signing.verify(expected.Ed25519, now); err != nil {
		return Verified{}, err
	}
	link, err := parseEd(byType[SigningTLS], SigningTLS)
	if err != nil {
		return Verified{}, err
	}
	// Tor <=0.4.5 mislabeled the X.509 digest as an Ed25519 key (type 1).
	if (link.keyType != 3 && link.keyType != 1) || link.subject != tlsDigest {
		return Verified{}, fmt.Errorf("%w: TLS certificate binding mismatch", ErrCertificate)
	}
	if err := link.verify(signing.subject, now); err != nil {
		return Verified{}, err
	}
	identity, err := x509.ParseCertificate(byType[RSAIdentity])
	if err != nil {
		return Verified{}, fmt.Errorf("%w: RSA identity encoding: %v", ErrCertificate, err)
	}
	public, ok := identity.PublicKey.(*rsa.PublicKey)
	if !ok || public.N.BitLen() != 1024 || public.E != 65537 {
		return Verified{}, fmt.Errorf("%w: expected legacy 1024-bit RSA identity with exponent 65537", ErrCertificate)
	}
	actualRSA := sha1.Sum(x509.MarshalPKCS1PublicKey(public)) // #nosec G401 -- Tor's pinned legacy RSA identity fingerprint format.
	if actualRSA != expected.RSA {
		return Verified{}, fmt.Errorf("%w: RSA identity mismatch", ErrCertificate)
	}
	if !bytes.Equal(identity.RawIssuer, identity.RawSubject) || identity.CheckSignature(identity.SignatureAlgorithm, identity.RawTBSCertificate, identity.Signature) != nil {
		return Verified{}, fmt.Errorf("%w: RSA identity is not correctly self-signed", ErrCertificate)
	}
	if now.Before(identity.NotBefore) || !now.Before(identity.NotAfter) {
		return Verified{}, fmt.Errorf("%w: RSA identity outside validity period", ErrCertificate)
	}
	expiry, err := verifyCrosscert(byType[RSAToEd25519], public, expected.Ed25519, now)
	if err != nil {
		return Verified{}, err
	}
	for _, t := range []time.Time{signing.expires, link.expires, identity.NotAfter} {
		if t.Before(expiry) {
			expiry = t
		}
	}
	return Verified{Identity: expected, Expires: expiry}, nil
}

type edCertificate struct {
	keyType   byte
	subject   [32]byte
	signer    *[32]byte
	expires   time.Time
	signed    []byte
	signature []byte
}

func parseEd(b []byte, kind byte) (edCertificate, error) {
	var cert edCertificate
	if len(b) < 40+ed25519.SignatureSize || len(b) > 65535 || b[0] != 1 || b[1] != kind {
		return cert, fmt.Errorf("%w: Ed25519 certificate version, type, or length", ErrCertificate)
	}
	cert.expires = time.Unix(int64(binary.BigEndian.Uint32(b[2:6]))*3600, 0)
	cert.keyType = b[6]
	copy(cert.subject[:], b[7:39])
	n, offset := int(b[39]), 40
	for i := 0; i < n; i++ {
		if len(b)-offset < 4+ed25519.SignatureSize {
			return edCertificate{}, fmt.Errorf("%w: truncated extension", ErrCertificate)
		}
		size := int(binary.BigEndian.Uint16(b[offset : offset+2]))
		tp, flags := b[offset+2], b[offset+3]
		offset += 4
		if size > len(b)-offset-ed25519.SignatureSize {
			return edCertificate{}, fmt.Errorf("%w: extension size", ErrCertificate)
		}
		if tp == 4 {
			if size != 32 || cert.signer != nil {
				return edCertificate{}, fmt.Errorf("%w: invalid or duplicate signing-key extension", ErrCertificate)
			}
			cert.signer = new([32]byte)
			copy(cert.signer[:], b[offset:offset+size])
		} else if flags&1 != 0 {
			return edCertificate{}, fmt.Errorf("%w: unknown critical extension", ErrCertificate)
		}
		offset += size
	}
	if len(b)-offset != ed25519.SignatureSize {
		return edCertificate{}, fmt.Errorf("%w: Ed25519 signature length or trailing data", ErrCertificate)
	}
	cert.signed = bytes.Clone(b[:offset])
	cert.signature = bytes.Clone(b[offset:])
	return cert, nil
}

func (c edCertificate) verify(key [32]byte, now time.Time) error {
	if c.signer != nil && *c.signer != key {
		return fmt.Errorf("%w: declared signing key mismatch", ErrCertificate)
	}
	if !ed25519.Verify(ed25519.PublicKey(key[:]), c.signed, c.signature) {
		return fmt.Errorf("%w: Ed25519 signature", ErrCertificate)
	}
	if !now.Before(c.expires) {
		return fmt.Errorf("%w: expired Ed25519 certificate", ErrCertificate)
	}
	return nil
}

func verifyCrosscert(b []byte, public *rsa.PublicKey, identity [32]byte, now time.Time) (time.Time, error) {
	if len(b) < 37 || int(b[36]) != len(b)-37 || int(b[36]) != public.Size() || !bytes.Equal(b[:32], identity[:]) {
		return time.Time{}, fmt.Errorf("%w: RSA cross-certificate size or subject", ErrCertificate)
	}
	expires := time.Unix(int64(binary.BigEndian.Uint32(b[32:36]))*3600, 0)
	if !now.Before(expires) {
		return time.Time{}, fmt.Errorf("%w: expired RSA cross-certificate", ErrCertificate)
	}
	h := sha256.New()
	h.Write([]byte("Tor TLS RSA/Ed25519 cross-certificate"))
	h.Write(b[:36])
	// Tor signs the raw SHA-256 digest using PKCS#1 v1.5, with NO DigestInfo.
	if rsa.VerifyPKCS1v15(public, crypto.Hash(0), h.Sum(nil), b[37:]) != nil {
		return time.Time{}, fmt.Errorf("%w: RSA cross-certificate signature", ErrCertificate)
	}
	return expires, nil
}
