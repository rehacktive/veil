package ntor

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
)

// From Arti's crypto/handshake/ntor.rs testvec at the revision in UPSTREAM.md.
const (
	vectorID      = "69546f6c64596f7541626f75745374616972732e"
	vectorB       = "ccbc8541904d18af08753eae967874749e6149f873de937f57f8fd903a21c471"
	vectorXSecret = "706f6461792069207075742e2e2e2e2e2e2e2e4a454c4c59206f6e2074686973"
	vectorX       = "e65dfdbef8b2635837fe2cebc086a8096eae3213e6830dc407516083d412b078"
	vectorReply   = "390480a14362761d6aec1fea840f6e9e928fb2adb7b25c670be1045e35133a371cbdf68b89923e1f85e8e18ee6e805ea333fe4849c790ffd2670bd80fec95cc8"
	vectorKeys    = "0c62dee7f48893370d0ef896758d35729867beef1a5121df80e00f79ed349af39b51cae125719182f19d932a667dae1afbf2e336e6910e7822223e763afad0a13342157969dc6b79"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func vectorRelay(t *testing.T) Relay {
	t.Helper()
	var r Relay
	copy(r.Identity[:], unhex(t, vectorID))
	copy(r.OnionKey[:], unhex(t, vectorB))
	return r
}
func vectorState(t *testing.T, r Relay) (*ClientState, [RequestSize]byte) {
	t.Helper()
	x, err := ecdh.X25519().NewPrivateKey(unhex(t, vectorXSecret))
	if err != nil {
		t.Fatal(err)
	}
	s, req, err := startWithKey(r, x)
	if err != nil {
		t.Fatal(err)
	}
	return s, req
}

func TestUpstreamVector(t *testing.T) {
	s, request := vectorState(t, vectorRelay(t))
	if !bytes.Equal(request[:], unhex(t, vectorID+vectorB+vectorX)) {
		t.Fatalf("request mismatch: %x", request)
	}
	k, err := s.Finish(unhex(t, vectorReply))
	if err != nil {
		t.Fatal(err)
	}
	got := join(k.ForwardDigest[:], k.BackwardDigest[:], k.ForwardKey[:], k.BackwardKey[:])
	if !bytes.Equal(got, unhex(t, vectorKeys)) {
		t.Fatalf("derived keys mismatch: %x", got)
	}
	if _, err := s.Finish(unhex(t, vectorReply)); !errors.Is(err, ErrConsumed) {
		t.Fatal("reused ephemeral state", err)
	}
}

func TestRejectTampering(t *testing.T) {
	reply := unhex(t, vectorReply)
	for i := range reply {
		s, _ := vectorState(t, vectorRelay(t))
		mutated := bytes.Clone(reply)
		mutated[i] ^= 1
		if k, err := s.Finish(mutated); err != ErrAuthentication || k != (KeyMaterial{}) {
			t.Fatalf("accepted modified byte %d", i)
		}
		if _, err := s.Finish(reply); err != ErrConsumed {
			t.Fatal("failed state reusable")
		}
	}
	for n := 0; n < len(reply); n++ {
		s, _ := vectorState(t, vectorRelay(t))
		if _, err := s.Finish(reply[:n]); err != ErrAuthentication {
			t.Fatalf("accepted prefix %d", n)
		}
	}
	s, _ := vectorState(t, vectorRelay(t))
	if _, err := s.Finish(append(reply, 0)); err != ErrAuthentication {
		t.Fatal("accepted trailing data")
	}
	r := vectorRelay(t)
	r.Identity[0] ^= 1
	s, _ = vectorState(t, r)
	if _, err := s.Finish(reply); err != ErrAuthentication {
		t.Fatal("accepted wrong relay identity")
	}
	other, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{42}, 32))
	copy(r.OnionKey[:], other.PublicKey().Bytes())
	s, _ = vectorState(t, r)
	if _, err := s.Finish(reply); err != ErrAuthentication {
		t.Fatal("accepted wrong relay key")
	}
}

func TestLowOrderKeys(t *testing.T) {
	for _, first := range []byte{0, 1} {
		r := vectorRelay(t)
		r.OnionKey = [32]byte{first}
		if _, _, err := Start(r); err != ErrAuthentication {
			t.Fatal("accepted low order onion key")
		}
		s, _ := vectorState(t, vectorRelay(t))
		reply := unhex(t, vectorReply)
		clear(reply[:32])
		reply[0] = first
		if _, err := s.Finish(reply); err != ErrAuthentication {
			t.Fatal("accepted low order reply")
		}
	}
}

func TestRandomEphemeralAndConsumption(t *testing.T) {
	r := vectorRelay(t)
	_, a, err := Start(r)
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := Start(r)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("repeated ephemeral key")
	}
	s, _ := vectorState(t, r)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.Finish(unhex(t, vectorReply)); results <- err }()
	}
	wg.Wait()
	close(results)
	successes, consumed := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if err == ErrConsumed {
			consumed++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || consumed != 1 {
		t.Fatal(successes, consumed)
	}
	if _, err := new(ClientState).Finish(nil); err != ErrConsumed {
		t.Fatal(err)
	}
	if _, err := (*ClientState)(nil).Finish(nil); err != ErrConsumed {
		t.Fatal(err)
	}
	for _, n := range []int{0, 72, 91, 93} {
		if _, err := ParseKeyMaterial(make([]byte, n)); err == nil {
			t.Fatal("invalid key material length")
		}
	}
}

func FuzzFinish(f *testing.F) {
	b, _ := hex.DecodeString(vectorReply)
	f.Add(b)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, reply []byte) {
		s, _ := vectorState(t, vectorRelay(t))
		_, _ = s.Finish(reply)
		if _, err := s.Finish(reply); err != ErrConsumed {
			t.Fatal("state reused")
		}
	})
}
