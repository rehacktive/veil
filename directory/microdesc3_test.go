package directory

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"
)

// Microdesc=3 makes the legacy TAP key body optional; onion-key still
// delimits descriptors, and ntor keys and authenticated digests stay required.
func TestTAPFreeDirectory(t *testing.T) {
	original, roots, now, sign := signedFixture(t)
	baseline, err := Verify(original, roots, now)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := splitMicrodescriptors(original.Microdescriptors, MaxMicrodescriptorsSize)
	if err != nil {
		t.Fatal(err)
	}
	withRequired := func(base []byte, desc, micro string) []byte {
		t.Helper()
		old := []byte("required-client-protocols Cons=2 Desc=2 FlowCtrl=1 Link=4 Microdesc=2 Relay=2")
		if bytes.Count(base, old) != 1 {
			t.Fatal("fixture must contain exactly one required-client-protocols line")
		}
		return bytes.Replace(base, old, []byte("required-client-protocols Cons=2 Desc="+desc+" FlowCtrl=1 Link=4 Microdesc="+micro+" Relay=2"), 1)
	}
	for _, test := range []struct {
		name, desc, micro string
		omitBody          func(int) bool
	}{
		{"legacy", "2", "2", func(int) bool { return false }},
		{"no TAP bodies", "3", "3", func(int) bool { return true }},
		{"mixed bodies", "1-4", "1-3", func(i int) bool { return i%2 == 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := original
			base := bytes.Clone(original.Consensus[:bytes.Index(original.Consensus, []byte("directory-signature "))])
			base = withRequired(base, test.desc, test.micro)
			d.Microdescriptors = nil
			for i, part := range parts {
				updated := part
				if test.omitBody(i) {
					block, rest := pem.Decode(part[len("onion-key\n"):])
					if block == nil || block.Type != "RSA PUBLIC KEY" {
						t.Fatal("fixture is missing its legacy TAP key body")
					}
					updated = append([]byte("onion-key\n"), rest...)
				}
				oldDigest, newDigest := sha256.Sum256(part), sha256.Sum256(updated)
				base = bytes.Replace(base, []byte("m "+base64.RawStdEncoding.EncodeToString(oldDigest[:])+"\n"),
					[]byte("m "+base64.RawStdEncoding.EncodeToString(newDigest[:])+"\n"), 1)
				d.Microdescriptors = append(d.Microdescriptors, updated...)
			}
			d.Consensus = sign(base)
			snapshot, err := Verify(d, roots, now)
			if err != nil {
				t.Fatal(err)
			}
			got, want := snapshot.Relays(), baseline.Relays()
			if len(got) != len(want) {
				t.Fatalf("relay count: got %d, want %d", len(got), len(want))
			}
			for i := range got {
				if got[i].NTor() != want[i].NTor() || got[i].Target() != want[i].Target() {
					t.Fatalf("relay %d lost its ntor key or identity", i)
				}
			}
			d.Microdescriptors = bytes.Replace(d.Microdescriptors, []byte("ntor-onion-key I"), []byte("ntor-onion-key J"), 1)
			if _, err := Verify(d, roots, now); !errors.Is(err, ErrTrust) {
				t.Fatalf("tampered descriptor: got %v, want ErrTrust", err)
			}
		})
	}
	for _, required := range []struct{ desc, micro string }{
		{"5", "3"}, {"1-5", "3"}, {"3", "4"}, {"3", "1-4"},
	} {
		d := original
		d.Consensus = withRequired(original.Consensus, required.desc, required.micro)
		if _, err := Verify(d, roots, now); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Desc=%s Microdesc=%s: got %v, want ErrUnsupported", required.desc, required.micro, err)
		}
	}
	// An accepted protocol version must not bypass consensus signatures.
	d := original
	d.Consensus = withRequired(original.Consensus, "3", "3")
	if _, err := Verify(d, roots, now); !errors.Is(err, ErrTrust) {
		t.Fatalf("tampered consensus: got %v, want ErrTrust", err)
	}
}
