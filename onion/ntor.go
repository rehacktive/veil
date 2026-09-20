package onion

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
)

const proto = "tor-hs-ntor-curve25519-sha3-256-1"

type Handshake struct {
	x            *ecdh.PrivateKey
	B, auth, sub [32]byte
	used         bool
	sent         bool
}

func NewHandshake(intro Introduction, sub [32]byte) (*Handshake, error) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Handshake{x: x, B: intro.EncryptionKey, auth: intro.AuthKey, sub: sub}, nil
}
func join(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
func mac(key, msg []byte) [32]byte {
	b := binary.BigEndian.AppendUint64(nil, uint64(len(key)))
	b = append(b, key...)
	b = append(b, msg...)
	h := sha3.Sum256(b)
	clear(b)
	return h
}
func (h *Handshake) Intro(plaintext []byte) ([]byte, error) {
	if h.used || h.sent || h.x == nil || len(plaintext) > 370 {
		return nil, ErrAuthentication
	}
	B, err := ecdh.X25519().NewPublicKey(h.B[:])
	if err != nil {
		return nil, err
	}
	bx, err := h.x.ECDH(B)
	if err != nil {
		return nil, ErrAuthentication
	}
	defer clear(bx)
	input := join(bx, h.auth[:], h.x.PublicKey().Bytes(), h.B[:], []byte(proto), []byte(proto+":hs_key_extract"), []byte(proto+":hs_key_expand"), h.sub[:])
	defer clear(input)
	keys := sha3.SumSHAKE256(input, 64)
	defer clear(keys)
	header := append(make([]byte, 20), 2, 0, 32)
	header = append(header, h.auth[:]...)
	header = append(header, 0)
	// Tor/Arti pad INTRODUCE1 to 490 bytes. The inner padding is encrypted.
	body := make([]byte, 490-len(header)-64)
	copy(body, plaintext)
	block, err := aes.NewCipher(keys[:32])
	if err != nil {
		return nil, err
	}
	cipher.NewCTR(block, make([]byte, 16)).XORKeyStream(body, body) // #nosec G407 -- hs-ntor mandates a zero IV with a fresh ephemeral-key-derived key for this single INTRODUCE1.
	result := join(header, h.x.PublicKey().Bytes(), body)
	tag := mac(keys[32:], result)
	h.sent = true
	return append(result, tag[:]...), nil
}

func (h *Handshake) Finish(reply []byte) (keys [128]byte, err error) {
	if h.used || h.x == nil {
		return keys, ErrAuthentication
	}
	h.used = true
	defer func() { h.x = nil; clear(h.sub[:]) }()
	if len(reply) != 64 {
		return keys, ErrAuthentication
	}
	Y, e := ecdh.X25519().NewPublicKey(reply[:32])
	if e != nil {
		return keys, ErrAuthentication
	}
	B, e := ecdh.X25519().NewPublicKey(h.B[:])
	if e != nil {
		return keys, ErrAuthentication
	}
	xy, e := h.x.ECDH(Y)
	if e != nil {
		return keys, ErrAuthentication
	}
	defer clear(xy)
	xb, e := h.x.ECDH(B)
	if e != nil {
		return keys, ErrAuthentication
	}
	defer clear(xb)
	X := h.x.PublicKey().Bytes()
	input := join(xy, xb, h.auth[:], h.B[:], X, reply[:32], []byte(proto))
	defer clear(input)
	seed := mac(input, []byte(proto+":hs_key_extract"))
	defer clear(seed[:])
	verify := mac(input, []byte(proto+":hs_verify"))
	authInput := join(verify[:], h.auth[:], h.B[:], reply[:32], X, []byte(proto), []byte("Server"))
	auth := mac(authInput, []byte(proto+":hs_mac"))
	if subtle.ConstantTimeCompare(auth[:], reply[32:]) != 1 {
		return keys, ErrAuthentication
	}
	kdf := append(seed[:], []byte(proto+":hs_key_expand")...)
	material := sha3.SumSHAKE256(kdf, 128)
	copy(keys[:], material)
	clear(material)
	clear(kdf)
	return keys, nil
}
