package directory

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- Tor authority certificate signatures and RSA fingerprints use SHA-1 in the specified wire format.
	"crypto/x509"
	"fmt"
	"time"
)

type certKey struct{ identity, signing Fingerprint }
type authorityCertificate struct {
	key                *rsa.PublicKey
	published, expires time.Time
}
type authoritySet struct {
	roots map[Fingerprint]bool
	certs map[certKey]authorityCertificate
}

func newAuthoritySet(roots []Fingerprint) (*authoritySet, error) {
	set := &authoritySet{roots: make(map[Fingerprint]bool), certs: make(map[certKey]authorityCertificate)}
	if len(roots) == 0 || len(roots) > 64 {
		return nil, fmt.Errorf("%w: configure 1 to 64 authority pins", ErrTrust)
	}
	for _, root := range roots {
		if root == (Fingerprint{}) || set.roots[root] {
			return nil, fmt.Errorf("%w: duplicate/zero trust anchor", ErrTrust)
		}
		set.roots[root] = true
	}
	return set, nil
}

func authorities(raw []byte, roots []Fingerprint, now time.Time) (*authoritySet, error) {
	set, err := newAuthoritySet(roots)
	if err != nil {
		return nil, err
	}
	items, err := lex(raw, MaxCertificatesSize)
	if err != nil {
		return nil, err
	}
	for start := 0; start < len(items); {
		if items[start].key != "dir-key-certificate-version" {
			return nil, fmt.Errorf("%w: authority certificate start", ErrDocument)
		}
		end := start + 1
		for end < len(items) && items[end].key != "dir-key-certificate-version" {
			end++
		}
		part := items[start:end]
		start = end
		if len(part) > 32 || part[len(part)-1].key != "dir-key-certification" {
			return nil, fmt.Errorf("%w: authority certificate ending", ErrDocument)
		}
		m, err := unique(part)
		if err != nil {
			return nil, err
		}
		for _, it := range part {
			switch it.key {
			case "dir-key-certificate-version", "fingerprint", "dir-key-published", "dir-key-expires", "dir-identity-key", "dir-signing-key", "dir-key-crosscert", "dir-key-certification", "dir-address":
			default:
				return nil, fmt.Errorf("%w: unsupported authority certificate item %s", ErrDocument, it.key)
			}
		}
		if v := m["dir-key-certificate-version"]; len(v.args) != 1 || v.args[0] != "3" {
			return nil, fmt.Errorf("%w: authority certificate version", ErrDocument)
		}
		fp := m["fingerprint"]
		if len(fp.args) != 1 {
			return nil, fmt.Errorf("%w: authority fingerprint", ErrDocument)
		}
		identity, err := ParseFingerprint(fp.args[0])
		if err != nil {
			return nil, err
		}
		if !set.roots[identity] {
			continue
		} // Never learn authorities from the document.
		pub, err := date(m["dir-key-published"].args)
		if err != nil {
			return nil, err
		}
		expires, err := date(m["dir-key-expires"].args)
		if err != nil {
			return nil, err
		}
		if !pub.Before(expires) {
			return nil, ErrTime
		}
		if now.Before(pub) || !now.Before(expires) {
			continue
		}
		idKey, err := publicKey(m["dir-identity-key"])
		if err != nil {
			return nil, err
		}
		signingKey, err := publicKey(m["dir-signing-key"])
		if err != nil {
			return nil, err
		}
		if Fingerprint(sha1.Sum(x509.MarshalPKCS1PublicKey(idKey))) != identity { // #nosec G401 -- Compare the protocol-defined SHA-1 RSA fingerprint against the configured authority pin.
			return nil, fmt.Errorf("%w: authority identity fingerprint", ErrTrust)
		}
		cross, err := object(m["dir-key-crosscert"], "ID SIGNATURE", "SIGNATURE")
		if err != nil {
			return nil, err
		}
		if rsa.VerifyPKCS1v15(signingKey, crypto.Hash(0), identity[:], cross) != nil {
			return nil, fmt.Errorf("%w: authority cross-certificate", ErrTrust)
		}
		last := m["dir-key-certification"]
		if len(last.args) != 0 {
			return nil, fmt.Errorf("%w: certification arguments", ErrDocument)
		}
		sig, err := object(last, "SIGNATURE")
		if err != nil {
			return nil, err
		}
		digest := sha1.Sum(raw[part[0].start:last.lineEnd]) // #nosec G401 -- Tor dir-key-certification signs the SHA-1 certificate digest; verify only against the pinned authority key.
		if rsa.VerifyPKCS1v15(idKey, crypto.Hash(0), digest[:], sig) != nil {
			return nil, fmt.Errorf("%w: authority certificate signature", ErrTrust)
		}
		key := certKey{identity, Fingerprint(sha1.Sum(x509.MarshalPKCS1PublicKey(signingKey)))} // #nosec G401 -- Protocol-defined signing-key fingerprint, bound by the verified authority certificate above.
		if _, exists := set.certs[key]; exists {
			return nil, fmt.Errorf("%w: duplicate authority signing certificate", ErrDocument)
		}
		set.certs[key] = authorityCertificate{signingKey, pub, expires}
	}
	return set, nil
}
