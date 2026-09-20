package cell

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Certificate is an entry in a CERTS cell, not an authenticated certificate.
type Certificate struct {
	Type uint8
	Body []byte
}

func EncodeCerts(certs []Certificate) ([]byte, error) {
	count := len(certs)
	if count > 255 {
		return nil, fmt.Errorf("%w: too many certificates", ErrInvalid)
	}
	b := []byte{byte(count)}
	seen := [256]bool{}
	for _, cert := range certs {
		size := len(cert.Body)
		if seen[cert.Type] || size > 65535 || len(b)+3+size > 65535 {
			return nil, fmt.Errorf("%w: duplicate certificate type or oversized CERTS", ErrInvalid)
		}
		seen[cert.Type] = true
		b = append(b, cert.Type)
		b = binary.BigEndian.AppendUint16(b, uint16(size))
		b = append(b, cert.Body...)
	}
	return b, nil
}

// DecodeCerts rejects duplicate types. Trailing bytes are ignored as required
// by the Tor protocol. Returned certificate bodies do not alias the input.
func DecodeCerts(b []byte) ([]Certificate, error) {
	if len(b) < 1 || len(b) > 65535 {
		return nil, fmt.Errorf("%w: CERTS size", ErrInvalid)
	}
	n := int(b[0])
	b = b[1:]
	certs := make([]Certificate, 0, n)
	seen := [256]bool{}
	for i := 0; i < n; i++ {
		if len(b) < 3 {
			return nil, fmt.Errorf("%w: truncated certificate header", ErrInvalid)
		}
		tp, size := b[0], int(binary.BigEndian.Uint16(b[1:3]))
		b = b[3:]
		if seen[tp] || len(b) < size {
			return nil, fmt.Errorf("%w: duplicate or truncated certificate", ErrInvalid)
		}
		seen[tp] = true
		certs = append(certs, Certificate{Type: tp, Body: append([]byte(nil), b[:size]...)})
		b = b[size:]
	}
	return certs, nil
}

type AuthChallengeMessage struct {
	Challenge [32]byte
	Methods   []uint16
}

func EncodeAuthChallenge(m AuthChallengeMessage) ([]byte, error) {
	count := len(m.Methods)
	if count > (65535-34)/2 {
		return nil, fmt.Errorf("%w: too many authentication methods", ErrInvalid)
	}
	b := make([]byte, 34+2*len(m.Methods))
	copy(b, m.Challenge[:])
	binary.BigEndian.PutUint16(b[32:34], uint16(count))
	for i, method := range m.Methods {
		binary.BigEndian.PutUint16(b[34+2*i:], method)
	}
	return b, nil
}

// DecodeAuthChallenge ignores trailing bytes. Clients parse this message but
// do not authenticate themselves or send AUTHENTICATE in response.
func DecodeAuthChallenge(b []byte) (AuthChallengeMessage, error) {
	var m AuthChallengeMessage
	if len(b) < 34 || len(b) > 65535 {
		return m, fmt.Errorf("%w: AUTH_CHALLENGE size", ErrInvalid)
	}
	n := int(binary.BigEndian.Uint16(b[32:34]))
	if n > (len(b)-34)/2 {
		return m, fmt.Errorf("%w: truncated authentication methods", ErrInvalid)
	}
	copy(m.Challenge[:], b[:32])
	m.Methods = make([]uint16, n)
	for i := range m.Methods {
		m.Methods[i] = binary.BigEndian.Uint16(b[34+2*i:])
	}
	return m, nil
}

// NetInfoMessage records the sender's time and view of endpoint addresses.
// Unknown address types are skipped on decode. An invalid OtherAddress means
// unavailable; clients send timestamp zero and an empty MyAddresses list.
type NetInfoMessage struct {
	Timestamp    uint32
	OtherAddress netip.Addr
	MyAddresses  []netip.Addr
}

func EncodeNetInfo(m NetInfoMessage) ([]byte, error) {
	count := len(m.MyAddresses)
	if count > 255 {
		return nil, fmt.Errorf("%w: too many NETINFO addresses", ErrInvalid)
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, m.Timestamp)
	other := m.OtherAddress
	if !other.IsValid() {
		other = netip.IPv4Unspecified()
	}
	var err error
	if b, err = appendNetAddress(b, other); err != nil {
		return nil, err
	}
	b = append(b, byte(count))
	for _, addr := range m.MyAddresses {
		if b, err = appendNetAddress(b, addr); err != nil {
			return nil, err
		}
	}
	if len(b) > PayloadSize {
		return nil, fmt.Errorf("%w: NETINFO exceeds payload", ErrInvalid)
	}
	return b, nil
}

func appendNetAddress(b []byte, addr netip.Addr) ([]byte, error) {
	if !addr.IsValid() || addr.Zone() != "" {
		return nil, fmt.Errorf("%w: invalid NETINFO IP", ErrInvalid)
	}
	addr = addr.Unmap()
	if addr.Is4() {
		a := addr.As4()
		b = append(b, 4, 4)
		return append(b, a[:]...), nil
	}
	a := addr.As16()
	b = append(b, 6, 16)
	return append(b, a[:]...), nil
}

func DecodeNetInfo(b []byte) (NetInfoMessage, error) {
	var m NetInfoMessage
	if len(b) < 7 || len(b) > PayloadSize {
		return m, fmt.Errorf("%w: NETINFO size", ErrInvalid)
	}
	m.Timestamp = binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	var err error
	m.OtherAddress, b, err = takeNetAddress(b)
	if err != nil {
		return NetInfoMessage{}, err
	}
	if m.OtherAddress.IsUnspecified() {
		m.OtherAddress = netip.Addr{}
	}
	if len(b) == 0 {
		return NetInfoMessage{}, fmt.Errorf("%w: missing NETINFO address count", ErrInvalid)
	}
	n := int(b[0])
	b = b[1:]
	for i := 0; i < n; i++ {
		var addr netip.Addr
		addr, b, err = takeNetAddress(b)
		if err != nil {
			return NetInfoMessage{}, err
		}
		if addr.IsValid() {
			m.MyAddresses = append(m.MyAddresses, addr)
		}
	}
	return m, nil // Remaining fixed-cell padding is ignored.
}

func takeNetAddress(b []byte) (netip.Addr, []byte, error) {
	if len(b) < 2 || int(b[1]) > len(b)-2 {
		return netip.Addr{}, nil, fmt.Errorf("%w: truncated NETINFO address", ErrInvalid)
	}
	tp, n := b[0], int(b[1])
	addrBytes, rest := b[2:2+n], b[2+n:]
	switch tp {
	case 4:
		if n != 4 {
			return netip.Addr{}, nil, fmt.Errorf("%w: IPv4 address length", ErrInvalid)
		}
		var a [4]byte
		copy(a[:], addrBytes)
		return netip.AddrFrom4(a), rest, nil
	case 6:
		if n != 16 {
			return netip.Addr{}, nil, fmt.Errorf("%w: IPv6 address length", ErrInvalid)
		}
		var a [16]byte
		copy(a[:], addrBytes)
		return netip.AddrFrom16(a), rest, nil
	default:
		return netip.Addr{}, rest, nil
	}
}
