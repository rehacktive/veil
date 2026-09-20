package onion

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha3"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func key(t *testing.T, s string) (k [32]byte) {
	b := decode(t, s)
	if len(b) != 32 {
		t.Fatal(len(b))
	}
	copy(k[:], b)
	return k
}

func TestBlindingVector(t *testing.T) {
	id := key(t, "833990B085C1A688C1D4C8B1F6B56AFAF5A2ECA674449E1D704F83765CCB7BC6")
	blind, sub, err := Blind(id, 1234, 1440)
	if err != nil || blind != key(t, "3A50BF210E8F9EE955AE0014F7A6917FB65EBF098A86305ABB508D1A7291B6D5") || sub != key(t, "635D55907816E8D76398A675A50B1C2F3E36B42A5CA77BA3A0441285161AE07D") {
		t.Fatal("Tor blinding vector mismatch", err)
	}
	checksum := sha3.Sum256(append(append([]byte(".onion checksum"), id[:]...), 3))
	b := append(append(id[:], checksum[:2]...), 3)
	address := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)) + ".onion"
	for _, name := range []string{address, strings.ToUpper(address), address + "."} {
		got, err := ParseAddress(name)
		if err != nil || got != id {
			t.Fatal(name, err)
		}
	}
	for _, name := range []string{"x.onion", "onion", "sub." + address, address[:55] + "a.onion", address + ".example", strings.Repeat("a", 56) + ".onion"} {
		if _, err := ParseAddress(name); err == nil {
			t.Fatal("accepted bad address", name)
		}
	}
}

func TestDescriptorArtiFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/hsdesc1.txt")
	if err != nil {
		t.Fatal(err)
	}
	blind := key(t, "43cc0d62fc6252f578705ca645a46109e265290343b1137e90189744b20b3f2d")
	sub := key(t, "78210A0D2C72BB7A0CAF606BCD938B9A3696894FDDDBC3B87D424753A7E3DF37")
	now := time.Date(2023, 1, 23, 15, 0, 0, 0, time.UTC)
	d, err := ParseDescriptor(raw, blind, sub, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Introductions) < 1 || !d.Expires.After(now) {
		t.Fatal(d)
	}
	for _, mutation := range []string{"signature", "blinded", "subcredential", "expired", "oversize"} {
		b := bytes.Clone(raw)
		id, sc, at := blind, sub, now
		switch mutation {
		case "signature":
			b[len(b)-5] ^= 1
		case "blinded":
			id[0] ^= 1
		case "subcredential":
			sc[0] ^= 1
		case "expired":
			at = now.Add(365 * 24 * time.Hour)
		case "oversize":
			b = make([]byte, MaxDescriptorSize+1)
		}
		if _, err := ParseDescriptor(b, id, sc, at); err == nil {
			t.Fatal("accepted", mutation)
		}
	}
}

func TestHsNtorTorVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/ntor.json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	makeState := func() *Handshake {
		x, e := ecdh.X25519().NewPrivateKey(decode(t, v["key_x"]))
		if e != nil {
			t.Fatal(e)
		}
		return &Handshake{x: x, B: key(t, v["kp_hss_ntor"]), auth: key(t, v["kp_hs_ipt_sid"]), sub: key(t, v["subcredential"])}
	}
	h := makeState()
	intro, err := h.Intro(decode(t, v["intro_body"]))
	if err != nil || len(intro) != 490 || !bytes.Equal(intro[:56], decode(t, v["intro_header"])) {
		t.Fatal("intro framing", err)
	}
	// The recorded C Tor vector predates 490-byte padding. Its header, X and
	// encrypted plaintext prefix must still match byte for byte; only the
	// extra padding and MAC covering that padding differ.
	expectedIntro := decode(t, v["expected_intro"])
	prefix := len(expectedIntro) - 32
	if !bytes.Equal(intro[:prefix], expectedIntro[:prefix]) {
		t.Fatal("Tor INTRODUCE1 ciphertext mismatch")
	}
	if _, err := h.Intro(nil); err == nil {
		t.Fatal("reused INTRODUCE1 encryption key")
	}
	keys, err := h.Finish(decode(t, v["expected_reply"]))
	if err != nil {
		t.Fatal(err)
	}
	seed := decode(t, "4D0C72FE8AFF35559D95ECC18EB5A36883402B28CDFD48C8A530A5A3D7D578DB")
	expected := sha3.SumSHAKE256(append(seed, []byte(proto+":hs_key_expand")...), 128)
	if !bytes.Equal(keys[:], expected) {
		t.Fatal("Tor hs-ntor key mismatch")
	}
	if _, err := h.Finish(decode(t, v["expected_reply"])); !errors.Is(err, ErrAuthentication) {
		t.Fatal("accepted reused handshake")
	}
	for _, bad := range [][]byte{nil, make([]byte, 64), append(decode(t, v["expected_reply"]), 0)} {
		if _, err := makeState().Finish(bad); err == nil {
			t.Fatal("accepted corrupt reply")
		}
	}
}

func FuzzDescriptor(f *testing.F) {
	raw, _ := os.ReadFile("testdata/hsdesc1.txt")
	f.Add(raw)
	f.Fuzz(func(t *testing.T, raw []byte) {
		blind := key(t, "43cc0d62fc6252f578705ca645a46109e265290343b1137e90189744b20b3f2d")
		sub := key(t, "78210A0D2C72BB7A0CAF606BCD938B9A3696894FDDDBC3B87D424753A7E3DF37")
		_, _ = ParseDescriptor(raw, blind, sub, time.Date(2023, 1, 23, 15, 0, 0, 0, time.UTC))
	})
}

func FuzzDescriptorItemsAndLinks(f *testing.F) {
	f.Add([]byte("create2-formats 2\n"))
	f.Add([]byte("auth-key\n-----BEGIN ED25519 CERT-----\nAA==\n-----END ED25519 CERT-----\n"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseItems(b); _, _ = parseLinks(b) })
}

func TestLinksRejectAmbiguousPins(t *testing.T) {
	good := []byte{3, 0, 6, 127, 0, 0, 1, 0x23, 0x29, 2, 20}
	good = append(good, make([]byte, 20)...)
	good = append(good, 3, 32)
	good = append(good, make([]byte, 32)...)
	if _, err := parseLinks(good); err != nil {
		t.Fatal(err)
	}
	bad := append(bytes.Clone(good), 2, 20)
	bad = append(bad, make([]byte, 20)...)
	bad[0]++
	for _, b := range [][]byte{bad, good[:len(good)-1], append(bytes.Clone(good), 0), {0}, {1, 2, 20}} {
		if _, err := parseLinks(b); err == nil {
			t.Fatal("invalid links accepted")
		}
	}
}
