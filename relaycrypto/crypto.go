// Package relaycrypto implements Tor's AES-128-CTR/SHA-1 relay cipher and the
// AES-256-CTR/SHA3-256 onion service hop. These primitives are mandated by Tor's
// wire protocol and are not intended for use as a general encryption scheme.
package relaycrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1" // #nosec G505 -- Tor's original relay wire format requires SHA-1 running digests; not a general-purpose cryptographic choice.
	"crypto/sha3"
	"crypto/subtle"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sync"

	"veil/cell"
	"veil/ntor"
)

var (
	ErrUnrecognized = errors.New("relay cell was not authenticated by any hop")
	ErrClosed       = errors.New("relay crypto is closed or uninitialized")
)

// Tag is the first 20 running-digest bytes required by Tor1 SENDME, including
// for the SHA3-256 onion service hop.
type Tag [20]byte

type layer struct {
	stream cipher.Stream
	digest hash.Hash
}

func newLayer(key [16]byte, seed [20]byte) *layer {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	} // A fixed 16-byte key is always valid.
	d := sha1.New() // #nosec G401 -- Protocol-mandated Tor relay digest, seeded separately for each fresh ntor hop and direction.
	d.Write(seed[:])
	return &layer{stream: cipher.NewCTR(block, make([]byte, aes.BlockSize)), digest: d} // #nosec G407 -- Tor starts each AES-CTR direction at zero with a fresh independently derived hop key; counters persist across cells.
}

func (l *layer) crypt(b *cell.RelayBody) { l.stream.XORKeyStream(b[:], b[:]) }

func (l *layer) originate(b *cell.RelayBody) Tag {
	clear(b[1:3])
	clear(b[5:9])
	l.digest.Write(b[:])
	var tag Tag
	copy(tag[:], l.digest.Sum(nil))
	copy(b[5:9], tag[:4])
	return tag
}

// cloneDigest uses the SHA-1/SHA3 binary state interfaces. A failed
// recognition probe must leave the running digest completely unchanged.
func cloneDigest(d hash.Hash) hash.Hash {
	state, err := d.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		panic(err)
	}
	copy := sha1.New() // #nosec G401 -- Clone of the protocol-mandated running relay digest for non-destructive recognition probes.
	if d.Size() == 32 {
		copy = sha3.New256()
	}
	if err := copy.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		panic(err)
	}
	return copy
}

func (l *layer) recognize(b *cell.RelayBody) (Tag, bool) {
	if b[1] != 0 || b[2] != 0 {
		return Tag{}, false
	}
	var received [4]byte
	copy(received[:], b[5:9])
	clear(b[5:9])
	candidate := cloneDigest(l.digest)
	candidate.Write(b[:])
	copy(b[5:9], received[:])
	var tag Tag
	copy(tag[:], candidate.Sum(nil))
	if subtle.ConstantTimeCompare(received[:], tag[:4]) != 1 {
		return Tag{}, false
	}
	l.digest = candidate
	return tag, true
}

// Client holds one forward and backward cipher/digest per hop, ordered from
// guard to exit. Cipher streams persist across cells. Methods are serialized;
// callers must preserve the wire order of returned outgoing and incoming cells.
// Do not copy a Client. Its zero value is unusable.
type Client struct {
	mu                sync.Mutex
	forward, backward []*layer
	closed            bool
	onionHop          bool
}

func NewClient(keys ...ntor.KeyMaterial) (*Client, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("relay crypto: at least one hop is required")
	}
	c := &Client{}
	for _, key := range keys {
		c.appendHop(key)
	}
	return c, nil
}

func (c *Client) appendHop(k ntor.KeyMaterial) {
	c.forward = append(c.forward, newLayer(k.ForwardKey, k.ForwardDigest))
	c.backward = append(c.backward, newLayer(k.BackwardKey, k.BackwardDigest))
}

// AddHop appends keys AFTER a new hop's ntor handshake authenticates. Existing
// cipher and digest states are preserved when a circuit is extended.
func (c *Client) AddHop(k ntor.KeyMaterial) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.onionHop || len(c.forward) == 0 {
		return ErrClosed
	}
	c.appendHop(k)
	return nil
}

// AddOnionHop adds the virtual service hop only after hs-ntor authenticates it.
// Its AES-256/SHA3-256 state is independent of the physical relay hops. Tor1 SENDME
// tags retain the first 20 bytes of the running digest, including for HSv3.
func (c *Client) AddOnionHop(k [128]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.onionHop || (len(c.forward) != 3 && len(c.forward) != 4) {
		return ErrClosed
	}
	makeLayer := func(key, seed []byte) (*layer, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		h := sha3.New256()
		if _, err := h.Write(seed); err != nil {
			return nil, err
		}
		return &layer{stream: cipher.NewCTR(block, make([]byte, aes.BlockSize)), digest: h}, nil // #nosec G407 -- Tor v3 service-hop CTR starts at zero with fresh hs-ntor keys; counters persist across cells.
	}
	f, err := makeLayer(k[64:96], k[:32])
	if err != nil {
		return err
	}
	b, err := makeLayer(k[96:128], k[32:64])
	if err != nil {
		return err
	}
	c.forward = append(c.forward, f)
	c.backward = append(c.backward, b)
	c.onionHop = true
	return nil
}

// Encrypt authenticates a plaintext for targetHop (zero-based), then encrypts
// it from that hop back to the guard. Hops beyond the target do not advance.
func (c *Client) Encrypt(targetHop int, body cell.RelayBody) (cell.RelayBody, Tag, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || len(c.forward) == 0 {
		return cell.RelayBody{}, Tag{}, ErrClosed
	}
	if targetHop < 0 || targetHop >= len(c.forward) {
		return cell.RelayBody{}, Tag{}, fmt.Errorf("relay crypto: invalid target hop %d", targetHop)
	}
	if binary.BigEndian.Uint16(body[9:11]) > cell.RelayDataSize {
		return cell.RelayBody{}, Tag{}, fmt.Errorf("%w: relay length exceeds body", cell.ErrInvalid)
	}
	tag := c.forward[targetHop].originate(&body)
	for i := targetHop; i >= 0; i-- {
		c.forward[i].crypt(&body)
	}
	return body, tag, nil
}

// Decrypt removes layers from guard to exit, stopping at the authenticated hop.
// An unauthenticated or malformed cell permanently closes this crypto state:
// consumed cipher streams cannot be rolled back. No plaintext is returned on
// failure. Circuit teardown and DESTROY signaling belong to the caller.
func (c *Client) Decrypt(body cell.RelayBody) (plaintext cell.RelayBody, hop int, tag Tag, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || len(c.backward) == 0 {
		return cell.RelayBody{}, -1, Tag{}, ErrClosed
	}
	for i, l := range c.backward {
		l.crypt(&body)
		if tag, ok := l.recognize(&body); ok {
			if binary.BigEndian.Uint16(body[9:11]) > cell.RelayDataSize {
				c.close()
				return cell.RelayBody{}, -1, Tag{}, fmt.Errorf("%w: relay length exceeds body", cell.ErrInvalid)
			}
			return body, i, tag, nil
		}
	}
	c.close()
	return cell.RelayBody{}, -1, Tag{}, ErrUnrecognized
}

// Close releases state and prevents reuse. Go cannot guarantee secret erasure.
func (c *Client) Close() { c.mu.Lock(); defer c.mu.Unlock(); c.close() }
func (c *Client) close() { c.closed = true; c.forward = nil; c.backward = nil }
