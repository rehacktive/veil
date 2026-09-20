package torcert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"veil/cell"
)

func upstream(t testing.TB) ([]cell.Certificate, [32]byte, Identity, time.Time) {
	t.Helper()
	data, err := os.ReadFile("testdata/arti_certs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]string
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	unhex := func(name string) []byte {
		b, err := hex.DecodeString(fixture[name])
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	certs := []cell.Certificate{{Type: 2, Body: unhex("CERT_T2")}, {Type: 4, Body: unhex("CERT_T4")}, {Type: 5, Body: unhex("CERT_T5")}, {Type: 7, Body: unhex("CERT_T7")}}
	var digest [32]byte
	copy(digest[:], unhex("PEER_CERT_DIGEST"))
	var id Identity
	copy(id.RSA[:], unhex("PEER_RSA"))
	copy(id.Ed25519[:], unhex("PEER_ED"))
	now, err := time.Parse(time.RFC3339, fixture["valid_at"])
	if err != nil {
		t.Fatal(err)
	}
	return certs, digest, id, now
}

func TestArtiCertificateChain(t *testing.T) {
	certs, digest, id, now := upstream(t)
	verified, err := verifyDigest(certs, digest, id, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Identity != id || !verified.Expires.After(now) {
		t.Fatal("wrong verified identity or validity")
	}
	if _, err := verifyDigest(certs, digest, id, verified.Expires); !errors.Is(err, ErrCertificate) {
		t.Fatal("accepted expired certificate at boundary")
	}
}

func TestRejectChainMutations(t *testing.T) {
	certs, digest, id, now := upstream(t)
	for index := range certs {
		without := append([]cell.Certificate(nil), certs[:index]...)
		without = append(without, certs[index+1:]...)
		if _, err := verifyDigest(without, digest, id, now); err == nil {
			t.Fatalf("missing type %d accepted", certs[index].Type)
		}
		duplicated := append(append([]cell.Certificate(nil), certs...), certs[index])
		if _, err := verifyDigest(duplicated, digest, id, now); err == nil {
			t.Fatal("duplicate certificate accepted")
		}
		for offset := range certs[index].Body {
			changed := append([]cell.Certificate(nil), certs...)
			changed[index].Body = bytes.Clone(certs[index].Body)
			changed[index].Body[offset] ^= 1
			if _, err := verifyDigest(changed, digest, id, now); err == nil {
				t.Fatalf("modified type %d byte %d accepted", certs[index].Type, offset)
			}
		}
		for length := 0; length < len(certs[index].Body); length++ {
			changed := append([]cell.Certificate(nil), certs...)
			changed[index].Body = certs[index].Body[:length]
			if _, err := verifyDigest(changed, digest, id, now); err == nil {
				t.Fatalf("truncated type %d accepted", certs[index].Type)
			}
		}
	}
	wrong := id
	wrong.RSA[0] ^= 1
	if _, err := verifyDigest(certs, digest, wrong, now); err == nil {
		t.Fatal("wrong RSA pin accepted")
	}
	wrong = id
	wrong.Ed25519[0] ^= 1
	if _, err := verifyDigest(certs, digest, wrong, now); err == nil {
		t.Fatal("wrong Ed25519 pin accepted")
	}
	digest[0] ^= 1
	if _, err := verifyDigest(certs, digest, id, now); err == nil {
		t.Fatal("wrong TLS leaf accepted")
	}
	if _, err := Verify(certs, nil, id, now); err == nil {
		t.Fatal("empty leaf accepted")
	}
	for _, at := range []time.Time{now.Add(-365 * 24 * time.Hour), now.Add(365 * 24 * time.Hour)} {
		_, d, _, _ := upstream(t)
		if _, err := verifyDigest(certs, d, id, at); err == nil {
			t.Fatal("invalid validity period accepted")
		}
	}
	for _, empty := range []Identity{{}, {RSA: id.RSA}, {Ed25519: id.Ed25519}} {
		if err := empty.Validate(); err == nil {
			t.Fatal("missing identity pin accepted")
		}
	}
}

func edTestCert(t *testing.T, extensions []byte, count byte) ([]byte, [32]byte, time.Time) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(3600*500000, 0)
	b := make([]byte, 40)
	b[0], b[1], b[6], b[39] = 1, 4, 1, count
	binary.BigEndian.PutUint32(b[2:6], 500001)
	copy(b[7:39], pub)
	b = append(b, extensions...)
	b = append(b, ed25519.Sign(private, b)...)
	var key [32]byte
	copy(key[:], pub)
	return b, key, now
}

func TestEdExtensions(t *testing.T) {
	// Unknown non-critical extensions are signed but can be ignored.
	b, key, now := edTestCert(t, []byte{0, 1, 99, 0, 42}, 1)
	cert, err := parseEd(b, 4)
	if err != nil || cert.verify(key, now) != nil {
		t.Fatal("unknown optional extension rejected", err)
	}
	for _, extra := range [][]byte{{0, 1, 99, 1, 42}, {0, 1, 4, 0, 42}, {0, 32, 4, 0, 1}, {255, 255, 99, 0}} {
		b, _, _ := edTestCert(t, extra, 1)
		if _, err := parseEd(b, 4); err == nil {
			t.Fatal("malformed/critical extension accepted")
		}
	}
	ext := append([]byte{0, 32, 4, 0}, make([]byte, 32)...)
	b, key, now = edTestCert(t, ext, 1)
	cert, err = parseEd(b, 4)
	if err != nil {
		t.Fatal(err)
	}
	if cert.verify(key, now) == nil {
		t.Fatal("wrong declared signing key accepted")
	}
	b, _, _ = edTestCert(t, append(ext, ext...), 2)
	if _, err := parseEd(b, 4); err == nil {
		t.Fatal("duplicate signer extension accepted")
	}
	b, _, _ = edTestCert(t, nil, 0)
	if _, err := parseEd(append(b, 0), 4); err == nil {
		t.Fatal("trailing bytes accepted")
	}
}

func FuzzCertificateChain(f *testing.F) {
	certs, digest, id, now := upstream(f)
	for i, cert := range certs {
		f.Add(uint8(i), cert.Body)
	}
	f.Fuzz(func(t *testing.T, index uint8, body []byte) {
		mutated := append([]cell.Certificate(nil), certs...)
		mutated[int(index)%len(mutated)].Body = body
		_, _ = verifyDigest(mutated, digest, id, now)
	})
}
