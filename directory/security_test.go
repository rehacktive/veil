package directory

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDirectoryTrustFailures(t *testing.T) {
	original, roots, now := fixture(t)
	signatures := bytes.Index(original.Consensus, []byte("directory-signature "))
	cases := []struct {
		name   string
		change func(*Documents, *[]Fingerprint)
		want   error
	}{
		{"changed signed body", func(d *Documents, _ *[]Fingerprint) {
			d.Consensus = bytes.Replace(d.Consensus, []byte("Bandwidth=208"), []byte("Bandwidth=209"), 1)
		}, ErrTrust},
		{"no roots", func(_ *Documents, r *[]Fingerprint) { *r = nil }, ErrTrust},
		{"duplicate root", func(_ *Documents, r *[]Fingerprint) { *r = append(*r, (*r)[0]) }, ErrTrust},
		{"quorum uses all roots", func(_ *Documents, r *[]Fingerprint) {
			for i := byte(1); i <= 4; i++ {
				*r = append(*r, Fingerprint{i})
			}
		}, ErrTrust},
		{"duplicate signer cannot form quorum", func(d *Documents, _ *[]Fingerprint) {
			s := d.Consensus[signatures:]
			end := bytes.Index(s[1:], []byte("directory-signature ")) + 1
			d.Consensus = append(append([]byte(nil), d.Consensus[:signatures]...), bytes.Repeat(s[:end], 4)...)
		}, ErrTrust},
		{"unknown algorithms", func(d *Documents, _ *[]Fingerprint) {
			d.Consensus = bytes.ReplaceAll(d.Consensus, []byte("directory-signature sha256"), []byte("directory-signature unknown"))
		}, ErrTrust},
		{"digest mismatch", func(d *Documents, _ *[]Fingerprint) {
			d.Microdescriptors = bytes.Replace(d.Microdescriptors, []byte("ntor-onion-key I"), []byte("ntor-onion-key J"), 1)
		}, ErrTrust},
		{"missing microdescriptor", func(d *Documents, _ *[]Fingerprint) {
			parts, _ := splitMicrodescriptors(d.Microdescriptors, MaxMicrodescriptorBatch)
			d.Microdescriptors = bytes.Join(parts[1:], nil)
		}, ErrTrust},
		{"duplicate microdescriptor", func(d *Documents, _ *[]Fingerprint) {
			parts, _ := splitMicrodescriptors(d.Microdescriptors, MaxMicrodescriptorBatch)
			d.Microdescriptors = append(append([]byte(nil), d.Microdescriptors...), parts[0]...)
		}, ErrDocument},
		{"required new protocol", func(d *Documents, _ *[]Fingerprint) {
			d.Consensus = bytes.Replace(d.Consensus, []byte("required-client-protocols Cons=2"), []byte("required-client-protocols NewProto=1 Cons=2"), 1)
		}, ErrUnsupported},
		{"CRLF", func(d *Documents, _ *[]Fingerprint) {
			d.Consensus = bytes.ReplaceAll(d.Consensus, []byte("\n"), []byte("\r\n"))
		}, ErrDocument},
		{"annotations", func(d *Documents, _ *[]Fingerprint) {
			d.Microdescriptors = append([]byte("@last-listed 2000-01-01 00:00:00\n"), d.Microdescriptors...)
		}, ErrDocument},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			d := original
			r := append([]Fingerprint(nil), roots...)
			test.change(&d, &r)
			if _, err := Verify(d, r, now); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
	for _, at := range []time.Time{now.Add(-11 * time.Second), now.Add(30 * time.Second)} {
		if _, err := Verify(original, roots, at); !errors.Is(err, ErrTime) {
			t.Fatalf("time %v: %v", at, err)
		}
	}
	s, err := Verify(original, roots, now)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Fresh(now) || s.Fresh(now.Add(10*time.Second)) || !s.Valid(now.Add(10*time.Second)) || s.Valid(now.Add(30*time.Second)) {
		t.Fatal("validity boundaries")
	}
	relays := s.Relays()
	relays[0] = Relay{}
	if s.Relays()[0].Identity() == (Fingerprint{}) {
		t.Fatal("mutable snapshot")
	}
}

// Generate independent RSA authority keys, never importing the upstream test
// network's private keys. Tor signatures use raw PKCS#1 v1.5 digests.
func signedFixture(t *testing.T) (Documents, []Fingerprint, time.Time, func([]byte) []byte) {
	t.Helper()
	d, _, now := fixture(t)
	var roots, signers []Fingerprint
	var keys []*rsa.PrivateKey
	var certs []byte
	pemBytes := func(label string, b []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: label, Bytes: b}) }
	sign := func(k *rsa.PrivateKey, b []byte) []byte {
		s, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.Hash(0), b)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for i := 0; i < 3; i++ {
		id, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		idDER := x509.MarshalPKCS1PublicKey(&id.PublicKey)
		keyDER := x509.MarshalPKCS1PublicKey(&key.PublicKey)
		fp := Fingerprint(sha1.Sum(idDER))
		roots = append(roots, fp)
		signers = append(signers, Fingerprint(sha1.Sum(keyDER)))
		keys = append(keys, key)
		b := []byte(fmt.Sprintf("dir-key-certificate-version 3\nfingerprint %s\ndir-key-published 1999-01-01 00:00:00\ndir-key-expires 2001-01-01 00:00:00\ndir-identity-key\n%sdir-signing-key\n%sdir-key-crosscert\n%sdir-key-certification\n", fp.String(), pemBytes("RSA PUBLIC KEY", idDER), pemBytes("RSA PUBLIC KEY", keyDER), pemBytes("ID SIGNATURE", sign(key, fp[:]))))
		hash := sha1.Sum(b)
		b = append(b, pemBytes("SIGNATURE", sign(id, hash[:]))...)
		certs = append(certs, b...)
	}
	base := d.Consensus[:bytes.Index(d.Consensus, []byte("directory-signature "))]
	start := bytes.Index(base, []byte("dir-source "))
	end := bytes.Index(base, []byte("\nr ")) + 1
	var sources string
	for i, fp := range roots {
		sources += fmt.Sprintf("dir-source auth%d %s localhost 127.0.0.1 7000 9000\ncontact test\nvote-digest %s\n", i, fp.String(), strings.Repeat("A", 40))
	}
	base = append(append(append([]byte(nil), base[:start]...), sources...), base[end:]...)
	signer := func(b []byte) []byte {
		signed := append(append([]byte(nil), b...), []byte("directory-signature ")...)
		hash := sha256.Sum256(signed)
		result := append([]byte(nil), b...)
		for i, k := range keys {
			result = append(result, []byte(fmt.Sprintf("directory-signature sha256 %s %s\n", roots[i], signers[i]))...)
			result = append(result, pemBytes("SIGNATURE", sign(k, hash[:]))...)
		}
		return result
	}
	d.Certificates = certs
	d.Consensus = signer(base)
	return d, roots, now, signer
}
func TestCertificateForgeryAndCacheRollback(t *testing.T) {
	d, roots, now, sign := signedFixture(t)
	if _, err := Verify(d, roots, now); err != nil {
		t.Fatal(err)
	}
	for _, keyword := range []string{"dir-key-crosscert", "dir-key-certification"} {
		altered := d
		altered.Certificates = append([]byte(nil), d.Certificates...)
		items, _ := lex(altered.Certificates, MaxCertificatesSize)
		for _, it := range items {
			if it.key == keyword {
				p := it.lineEnd
				for altered.Certificates[p] != '\n' {
					p++
				}
				p++
				altered.Certificates[p] = 'A'
				if d.Certificates[p] == 'A' {
					altered.Certificates[p] = 'B'
				}
				break
			}
		}
		if _, err := Verify(altered, roots, now); !errors.Is(err, ErrTrust) {
			t.Fatalf("%s: %v", keyword, err)
		}
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	cache, err := NewCache(dir, roots)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Store(d, now); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Load(now); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Load(now.Add(time.Minute)); !errors.Is(err, ErrTime) {
		t.Fatal(err)
	}
	base := d.Consensus[:bytes.Index(d.Consensus, []byte("directory-signature "))]
	shifted := bytes.ReplaceAll(base, []byte("00:02:"), []byte("00:04:"))
	shifted = bytes.ReplaceAll(shifted, []byte("valid-until 2000-01-01 00:03:00"), []byte("valid-until 2000-01-01 00:05:00"))
	newer := d
	newer.Consensus = sign(shifted)
	if _, err := cache.Store(newer, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Store(d, now); !errors.Is(err, ErrTrust) {
		t.Fatalf("rollback: %v", err)
	}
	conflict := newer
	conflict.Consensus = sign(bytes.Replace(shifted, []byte("Bandwidth=208"), []byte("Bandwidth=209"), 1))
	if _, err := cache.Store(conflict, now.Add(2*time.Minute)); !errors.Is(err, ErrTrust) {
		t.Fatalf("conflict: %v", err)
	}
	if err := os.WriteFile(dir+"/directory.json", []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Load(now); err == nil {
		t.Fatal("accepted corrupt cache")
	}
	if _, err := cache.Store(d, now); err == nil {
		t.Fatal("overwrote corrupt cache")
	}
	if _, err := NewCache(t.TempDir()+"/state", nil); !errors.Is(err, ErrTrust) {
		t.Fatal("accepted empty trust set", err)
	}
	os.Chmod(dir, 0755)
	if _, err := NewCache(dir, roots); err == nil {
		t.Fatal("accepted public state directory")
	}
}
func TestMicrodescriptorPolicies(t *testing.T) {
	key := strings.Repeat("A", 42) + "E"
	raw := []byte("onion-key\nntor-onion-key " + key + "\nid ed25519 " + key + "\np accept 80,443,1000-2000\np6 reject 1-442,444-65535\nfamily $" + strings.Repeat("A", 40) + "=Relay nickname\nfamily-ids group1 group2\n")
	m, err := parseMicrodescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !m.ipv4.allows(80) || m.ipv4.allows(81) || !m.ipv4.allows(1500) || !m.ipv6.allows(443) || m.ipv6.allows(80) || m.ipv4.allows(0) {
		t.Fatal("policy mismatch")
	}
	if len(m.family) != 1 || len(m.familyIDs) != 2 {
		t.Fatal("family mismatch")
	}
	for _, s := range []string{"accept 0", "accept 65536", "accept 2-1", "reject 80,,443", "other 80"} {
		if _, err := parsePolicy(strings.Fields(s)); err == nil {
			t.Fatal(s)
		}
	}
	for _, s := range []string{key + "===", key + "?", hex.EncodeToString(make([]byte, 32))} {
		if _, err := unbase64(s, 32); err == nil {
			t.Fatal(s)
		}
	}
}
func FuzzDirectoryDocuments(f *testing.F) {
	f.Add([]byte("onion-key\nntor-onion-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE\n"))
	f.Add([]byte("network-status-version 3 microdesc\n"))
	f.Add([]byte("dir-key-certificate-version 3\n"))
	for _, name := range []string{"authorities.txt", "consensus.txt", "microdescriptors.txt"} {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		items, err := lex(b, 1<<20)
		if err == nil {
			for _, it := range items {
				if it.start < 0 || it.end > len(b) || it.lineEnd > it.end {
					t.Fatal("bad offsets")
				}
			}
		}
		parseMicrodescriptor(b)
		splitMicrodescriptors(b, 1<<20)
		verifyConsensus(b, &authoritySet{roots: map[Fingerprint]bool{{1}: true}, certs: map[certKey]authorityCertificate{}}, time.Date(2000, 1, 1, 0, 2, 30, 0, time.UTC))
		authorities(b, []Fingerprint{{1}}, time.Now())
	})
}
