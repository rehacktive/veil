// Package ntor implements the client side of Tor's ntor handshake (type 2,
// ntor-curve25519-sha256-1). It does not implement ntor-v3 (handshake type 3).
package ntor

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
)

const (
	RequestSize     = 84
	ReplySize       = 64
	KeyMaterialSize = 92
	protoID         = "ntor-curve25519-sha256-1"
)

var (
	ErrAuthentication = errors.New("ntor authentication failed")
	ErrConsumed       = errors.New("ntor handshake already consumed or uninitialized")
)

// Relay identifies the target from an authenticated directory descriptor.
// The caller is responsible for establishing trust in these keys.
type Relay struct {
	Identity [20]byte // SHA-1 digest of the relay's RSA identity key.
	OnionKey [32]byte // X25519 ntor public key.
}

// KeyMaterial is Df | Db | Kf | Kb | circuit binding, in Tor KDF order.
// All fields are secrets and must not be logged. Go does not guarantee erasure.
type KeyMaterial struct {
	ForwardDigest  [20]byte
	BackwardDigest [20]byte
	ForwardKey     [16]byte
	BackwardKey    [16]byte
	Binding        [20]byte
}

// ParseKeyMaterial splits exactly 92 bytes of already derived secret material.
func ParseKeyMaterial(b []byte) (KeyMaterial, error) {
	var k KeyMaterial
	if len(b) != KeyMaterialSize {
		return k, fmt.Errorf("ntor: key material must be %d bytes", KeyMaterialSize)
	}
	copy(k.ForwardDigest[:], b[:20])
	copy(k.BackwardDigest[:], b[20:40])
	copy(k.ForwardKey[:], b[40:56])
	copy(k.BackwardKey[:], b[56:72])
	copy(k.Binding[:], b[72:92])
	return k, nil
}

// ClientState is a one-shot handshake. Do not copy it. Every Finish attempt
// consumes the ephemeral key, including failed authentication attempts.
type ClientState struct {
	mu     sync.Mutex
	relay  Relay
	secret *ecdh.PrivateKey
}

// Start generates a fresh ephemeral X25519 key and the ID | B | X request.
func Start(relay Relay) (*ClientState, [RequestSize]byte, error) {
	secret, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, [RequestSize]byte{}, fmt.Errorf("ntor ephemeral key: %w", err)
	}
	return startWithKey(relay, secret)
}

// Kept private so callers cannot accidentally reuse an ephemeral key.
func startWithKey(relay Relay, secret *ecdh.PrivateKey) (*ClientState, [RequestSize]byte, error) {
	var request [RequestSize]byte
	pub, err := ecdh.X25519().NewPublicKey(relay.OnionKey[:])
	if err != nil {
		return nil, request, ErrAuthentication
	}
	// ECDH rejects low-order public keys (including all-zero shared secrets).
	if _, err := secret.ECDH(pub); err != nil {
		return nil, request, ErrAuthentication
	}
	copy(request[:20], relay.Identity[:])
	copy(request[20:52], relay.OnionKey[:])
	copy(request[52:], secret.PublicKey().Bytes())
	return &ClientState{relay: relay, secret: secret}, request, nil
}

// Finish authenticates Y | AUTH and derives hop keys. Pass the length-delimited
// CREATED2/EXTENDED2 handshake, without channel-cell padding.
func (s *ClientState) Finish(reply []byte) (KeyMaterial, error) {
	if s == nil {
		return KeyMaterial{}, ErrConsumed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secret == nil {
		return KeyMaterial{}, ErrConsumed
	}
	secret := s.secret
	s.secret = nil
	if len(reply) != ReplySize {
		return KeyMaterial{}, ErrAuthentication
	}
	y, err := ecdh.X25519().NewPublicKey(reply[:32])
	if err != nil {
		return KeyMaterial{}, ErrAuthentication
	}
	b, err := ecdh.X25519().NewPublicKey(s.relay.OnionKey[:])
	if err != nil {
		return KeyMaterial{}, ErrAuthentication
	}
	xy, err := secret.ECDH(y)
	if err != nil {
		return KeyMaterial{}, ErrAuthentication
	}
	xb, err := secret.ECDH(b)
	if err != nil {
		return KeyMaterial{}, ErrAuthentication
	}
	x := secret.PublicKey().Bytes()
	input := join(xy, xb, s.relay.Identity[:], s.relay.OnionKey[:], x, reply[:32], []byte(protoID))
	verify := mac(protoID+":verify", input)
	authInput := join(verify, s.relay.Identity[:], s.relay.OnionKey[:], reply[:32], x, []byte(protoID), []byte("Server"))
	expected := mac(protoID+":mac", authInput)
	if !hmac.Equal(expected, reply[32:]) {
		return KeyMaterial{}, ErrAuthentication
	}
	return ParseKeyMaterial(expand(input))
}

func mac(key string, data []byte) []byte {
	h := hmac.New(sha256.New, []byte(key))
	h.Write(data)
	return h.Sum(nil)
}

// HKDF-SHA256 with ntor's extraction salt and expansion info, truncated to the
// 92 bytes used by the original Tor relay cipher and circuit binding.
func expand(secretInput []byte) []byte {
	prk := mac(protoID+":key_extract", secretInput)
	var out, previous []byte
	for counter := byte(1); len(out) < KeyMaterialSize; counter++ {
		h := hmac.New(sha256.New, prk)
		h.Write(previous)
		h.Write([]byte(protoID + ":key_expand"))
		h.Write([]byte{counter})
		previous = h.Sum(nil)
		out = append(out, previous...)
	}
	return out[:KeyMaterialSize]
}

func join(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
