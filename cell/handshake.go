package cell

import (
	"encoding/binary"
	"fmt"
)

const HandshakeNtor uint16 = 2

// EncodeCreate2 returns a CREATE2 payload; Codec.Write adds channel padding.
func EncodeCreate2(kind uint16, handshake []byte) ([]byte, error) {
	n := len(handshake)
	if n > PayloadSize-4 {
		return nil, fmt.Errorf("%w: CREATE2 handshake too large", ErrInvalid)
	}
	out := make([]byte, 4+len(handshake))
	binary.BigEndian.PutUint16(out[:2], kind)
	binary.BigEndian.PutUint16(out[2:4], uint16(n))
	copy(out[4:], handshake)
	return out, nil
}

// DecodeCreate2 accepts a payload with optional channel padding.
func DecodeCreate2(b []byte) (kind uint16, handshake []byte, err error) {
	if len(b) < 4 || len(b) > PayloadSize {
		return 0, nil, fmt.Errorf("%w: CREATE2 size", ErrInvalid)
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if n > len(b)-4 {
		return 0, nil, fmt.Errorf("%w: truncated CREATE2", ErrInvalid)
	}
	return binary.BigEndian.Uint16(b[:2]), append([]byte(nil), b[4:4+n]...), nil
}

func EncodeCreated2(handshake []byte) ([]byte, error) {
	n := len(handshake)
	if n > PayloadSize-2 {
		return nil, fmt.Errorf("%w: CREATED2 handshake too large", ErrInvalid)
	}
	out := make([]byte, 2+len(handshake))
	binary.BigEndian.PutUint16(out[:2], uint16(n))
	copy(out[2:], handshake)
	return out, nil
}

// DecodeCreated2 also decodes the handshake body in an EXTENDED2 message.
// Trailing bytes are treated as padding.
func DecodeCreated2(b []byte) ([]byte, error) {
	if len(b) < 2 || len(b) > PayloadSize {
		return nil, fmt.Errorf("%w: CREATED2 size", ErrInvalid)
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if n > len(b)-2 {
		return nil, fmt.Errorf("%w: truncated CREATED2", ErrInvalid)
	}
	return append([]byte(nil), b[2:2+n]...), nil
}

const (
	LinkIPv4 uint8 = iota
	LinkIPv6
	LinkRSAIdentity
	LinkEd25519Identity
)

// LinkSpec carries an EXTEND2 link specifier. Address data is network-byte-order
// IP followed by a two-byte port. Identity data contains the raw identity bytes.
// Unknown types are retained for forward compatibility.
type LinkSpec struct {
	Type uint8
	Data []byte
}

func (s LinkSpec) validate() error {
	want := -1
	switch s.Type {
	case LinkIPv4:
		want = 6
	case LinkIPv6:
		want = 18
	case LinkRSAIdentity:
		want = 20
	case LinkEd25519Identity:
		want = 32
	}
	if len(s.Data) > 255 || (want >= 0 && len(s.Data) != want) {
		return fmt.Errorf("%w: link specifier length", ErrInvalid)
	}
	return nil
}

type Extend2Message struct {
	Links         []LinkSpec
	HandshakeType uint16
	Handshake     []byte
}

func EncodeExtend2(m Extend2Message) ([]byte, error) {
	count := len(m.Links)
	if count > 255 {
		return nil, fmt.Errorf("%w: too many link specifiers", ErrInvalid)
	}
	h, err := EncodeCreate2(m.HandshakeType, m.Handshake)
	if err != nil {
		return nil, err
	}
	out := []byte{byte(count)}
	for _, s := range m.Links {
		if err := s.validate(); err != nil {
			return nil, err
		}
		size := len(s.Data)
		if size > 255 {
			return nil, fmt.Errorf("%w: link specifier length", ErrInvalid)
		}
		out = append(out, s.Type, byte(size))
		out = append(out, s.Data...)
	}
	out = append(out, h...)
	if len(out) > RelayDataSize {
		return nil, fmt.Errorf("%w: EXTEND2 exceeds relay payload", ErrInvalid)
	}
	return out, nil
}

func DecodeExtend2(b []byte) (Extend2Message, error) {
	var out Extend2Message
	if len(b) < 1 || len(b) > RelayDataSize {
		return out, fmt.Errorf("%w: EXTEND2 size", ErrInvalid)
	}
	n := int(b[0])
	b = b[1:]
	for i := 0; i < n; i++ {
		if len(b) < 2 || int(b[1]) > len(b)-2 {
			return Extend2Message{}, fmt.Errorf("%w: truncated link specifier", ErrInvalid)
		}
		size := int(b[1])
		s := LinkSpec{Type: b[0], Data: append([]byte(nil), b[2:2+size]...)}
		if err := s.validate(); err != nil {
			return Extend2Message{}, err
		}
		out.Links = append(out.Links, s)
		b = b[2+size:]
	}
	kind, handshake, err := DecodeCreate2(b)
	if err != nil {
		return Extend2Message{}, err
	}
	// A relay message's length already excludes padding.
	if len(b) != 4+len(handshake) {
		return Extend2Message{}, fmt.Errorf("%w: trailing EXTEND2 bytes", ErrInvalid)
	}
	out.HandshakeType, out.Handshake = kind, handshake
	return out, nil
}
