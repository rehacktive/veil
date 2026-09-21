package onion

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"
	"veil/cell"
)

func testServiceIntro(t *testing.T) *ServiceIntroduction {
	t.Helper()
	links := []cell.LinkSpec{{Type: cell.LinkIPv4, Data: []byte{1, 2, 3, 4, 0, 80}}, {Type: cell.LinkRSAIdentity, Data: bytes.Repeat([]byte{1}, 20)}, {Type: cell.LinkEd25519Identity, Data: bytes.Repeat([]byte{2}, 32)}}
	intro, err := NewServiceIntroduction(links, [32]byte{3})
	if err != nil {
		t.Fatal(err)
	}
	return intro
}
func TestServiceDescriptorRoundTrip(t *testing.T) {
	var seed [32]byte
	_, _ = rand.Read(seed[:])
	key := ed25519.NewKeyFromSeed(seed[:])
	var pub [32]byte
	copy(pub[:], key[32:])
	name, err := Address(pub)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAddress(name)
	if err != nil || parsed != pub {
		t.Fatal(name, err)
	}
	intro := testServiceIntro(t)
	now := time.Now()
	raw, err := CreateDescriptor(seed, 42, 1440, 789, []Introduction{intro.Public}, now)
	if err != nil {
		t.Fatal(err)
	}
	blinded, sub, err := Blind(pub, 42, 1440)
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseDescriptor(raw, blinded, sub, now)
	if err != nil {
		t.Fatal(err)
	}
	if d.Revision != 789 || len(d.Introductions) != 1 || d.Introductions[0].AuthKey != intro.Public.AuthKey || d.Introductions[0].EncryptionKey != intro.Public.EncryptionKey {
		t.Fatal("descriptor mismatch")
	}
	if _, err := ParseDescriptor(raw, blinded, [32]byte{1}, now); err == nil {
		t.Fatal("wrong subcredential accepted")
	}
	raw[len(raw)-3] ^= 1
	if _, err := ParseDescriptor(raw, blinded, sub, now); err == nil {
		t.Fatal("bad signature accepted")
	}
}
func TestServiceHandshakeAndIntroductionAuthentication(t *testing.T) {
	intro := testServiceIntro(t)
	sub := [32]byte{9}
	h, err := NewHandshake(intro.Public, sub)
	if err != nil {
		t.Fatal(err)
	}
	plain := append(bytes.Repeat([]byte{4}, 20), 0, 1, 0, 32)
	plain = append(plain, intro.Public.OnionKey[:]...)
	plain = append(plain, 3)
	for _, l := range intro.Public.Links {
		plain = append(plain, l.Type, byte(len(l.Data)))
		plain = append(plain, l.Data...)
	}
	raw, err := h.Intro(plain)
	if err != nil {
		t.Fatal(err)
	}
	r, err := intro.Accept(raw, sub)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := h.Finish(r.Reply[:])
	if err != nil || keys != r.Keys {
		t.Fatal("hs-ntor mismatch", err)
	}
	if !bytes.Equal(r.Cookie[:], bytes.Repeat([]byte{4}, 20)) || r.OnionKey != intro.Public.OnionKey {
		t.Fatal("introduction mismatch")
	}
	for _, index := range []int{0, 20, 21, 23, 55, 60, 100, len(raw) - 1} {
		bad := bytes.Clone(raw)
		bad[index] ^= 1
		if _, err := intro.Accept(bad, sub); err == nil {
			t.Fatal("tampered introduction accepted", index)
		}
	}
	for j := 0; j < len(raw); j++ {
		if _, err := intro.Accept(raw[:j], sub); err == nil {
			t.Fatal("truncated introduction accepted", j)
		}
	}
	if _, err := intro.Accept(raw, [32]byte{}); err == nil {
		t.Fatal("wrong subcredential")
	}
	binding := [20]byte{6}
	est := intro.Establish(binding)
	tag := mac(binding[:], est[:36])
	if !bytes.Equal(tag[:], est[36:68]) || binary.BigEndian.Uint16(est[68:70]) != 64 || !ed25519.Verify(intro.Public.AuthKey[:], join([]byte("Tor establish-intro cell v1"), est[:68]), est[70:]) {
		t.Fatal("invalid ESTABLISH_INTRO")
	}
}
func FuzzServiceIntroduction(f *testing.F) {
	intro, err := NewServiceIntroduction(nil, [32]byte{3})
	if err != nil {
		f.Fatal(err)
	}
	sub := [32]byte{9}
	f.Add(make([]byte, 120))
	f.Add(append(bytes.Repeat([]byte{4}, 20), 0, 1, 0, 32))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1024 {
			return
		}
		_, _ = intro.Accept(b, sub)
		// An onion client knows the service's public keys, so also fuzz correctly
		// authenticated ciphertext containing adversarial rendezvous plaintext.
		if len(b) <= 370 {
			h, err := NewHandshake(intro.Public, sub)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := h.Intro(b)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = intro.Accept(raw, sub)
		}
	})
}
