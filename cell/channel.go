// Package cell implements Tor channel cells and the original relay cell format.
// It only handles wire formats: callers must enforce channel and circuit state.
package cell

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const PayloadSize = 509

// Command identifies a channel cell. Unknown commands are preserved.
type Command uint8

const (
	Padding Command = iota
	Create
	Created
	Relay
	Destroy
	CreateFast
	CreatedFast
	Versions
	NetInfo
	RelayEarly
	Create2
	Created2
	PaddingNegotiate
	VPadding      Command = 128
	Certs         Command = 129
	AuthChallenge Command = 130
	Authenticate  Command = 131
	Authorize     Command = 132
)

var ErrInvalid = errors.New("invalid Tor cell")

func (c Command) Variable() bool { return c == Versions || c >= 128 }

func (c Command) String() string {
	names := map[Command]string{
		Padding: "PADDING", Create: "CREATE", Created: "CREATED", Relay: "RELAY",
		Destroy: "DESTROY", CreateFast: "CREATE_FAST", CreatedFast: "CREATED_FAST",
		Versions: "VERSIONS", NetInfo: "NETINFO", RelayEarly: "RELAY_EARLY",
		Create2: "CREATE2", Created2: "CREATED2", PaddingNegotiate: "PADDING_NEGOTIATE",
		VPadding: "VPADDING", Certs: "CERTS", AuthChallenge: "AUTH_CHALLENGE",
		Authenticate: "AUTHENTICATE", Authorize: "AUTHORIZE",
	}
	if s, ok := names[c]; ok {
		return s
	}
	return fmt.Sprintf("UNKNOWN(%d)", uint8(c))
}

// Cell is a channel frame. For fixed cells, Read returns all 509 payload bytes,
// including padding; Write pads shorter payloads with zeroes.
type Cell struct {
	CircuitID uint32
	Command   Command
	Payload   []byte
}

func (c Cell) validate() error {
	switch c.Command {
	case Padding, Versions, NetInfo, PaddingNegotiate, VPadding, Certs, AuthChallenge, Authenticate:
		if c.CircuitID != 0 {
			return fmt.Errorf("%w: %s requires circuit ID zero", ErrInvalid, c.Command)
		}
	case Create, Created, Relay, Destroy, CreateFast, CreatedFast, RelayEarly, Create2, Created2:
		if c.CircuitID == 0 {
			return fmt.Errorf("%w: %s requires a circuit ID", ErrInvalid, c.Command)
		}
	}
	return nil
}

// Codec handles negotiated link protocols 4 and 5. The zero value is unusable.
// Initial VERSIONS negotiation uses ReadVersions and WriteVersions separately.
// Subsequent VERSIONS cells use the negotiated four-byte ID and must be ignored
// by the channel state machine, as required by the protocol.
type Codec struct{ version uint16 }

func NewCodec(version uint16) (*Codec, error) {
	if version != 4 && version != 5 {
		return nil, fmt.Errorf("%w: unsupported link protocol %d", ErrInvalid, version)
	}
	return &Codec{version: version}, nil
}

func (c *Codec) valid() bool { return c != nil && (c.version == 4 || c.version == 5) }

// Read consumes exactly one frame, without reading ahead. EOF means a clean
// frame boundary; any truncated frame returns io.ErrUnexpectedEOF. On any other
// error the caller must discard the channel rather than attempt to resynchronize.
func (c *Codec) Read(r io.Reader) (Cell, error) {
	if !c.valid() {
		return Cell{}, fmt.Errorf("%w: uninitialized codec", ErrInvalid)
	}
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Cell{}, err
	}
	out := Cell{CircuitID: binary.BigEndian.Uint32(h[:4]), Command: Command(h[4])}
	if err := out.validate(); err != nil {
		return Cell{}, err
	}
	n := PayloadSize
	if out.Command.Variable() {
		var size [2]byte
		if err := readRest(r, size[:]); err != nil {
			return Cell{}, err
		}
		n = int(binary.BigEndian.Uint16(size[:]))
	}
	out.Payload = make([]byte, n)
	if err := readRest(r, out.Payload); err != nil {
		return Cell{}, err
	}
	return out, nil
}

// Write validates a frame before writing it. A write error makes the channel
// unusable because the peer may have received a partial frame.
func (c *Codec) Write(w io.Writer, frame Cell) error {
	if !c.valid() {
		return fmt.Errorf("%w: uninitialized codec", ErrInvalid)
	}
	if err := frame.validate(); err != nil {
		return err
	}
	n, header := PayloadSize, 5
	if frame.Command.Variable() {
		n, header = len(frame.Payload), 7
	}
	if len(frame.Payload) > n || n > 65535 {
		return fmt.Errorf("%w: payload too large", ErrInvalid)
	}
	b := make([]byte, header+n)
	binary.BigEndian.PutUint32(b[:4], frame.CircuitID)
	b[4] = byte(frame.Command)
	if header == 7 {
		binary.BigEndian.PutUint16(b[5:7], uint16(n))
	}
	copy(b[header:], frame.Payload)
	return writeAll(w, b)
}

// WriteVersions writes the initial handshake frame, using a two-byte circuit ID.
func WriteVersions(w io.Writer, versions []uint16) error {
	count := len(versions)
	if count == 0 || count > 32767 {
		return fmt.Errorf("%w: invalid versions length", ErrInvalid)
	}
	b := make([]byte, 5+2*len(versions))
	b[2] = byte(Versions)
	binary.BigEndian.PutUint16(b[3:5], 2*uint16(count))
	for i, v := range versions {
		binary.BigEndian.PutUint16(b[5+2*i:], v)
	}
	return writeAll(w, b)
}

func ReadVersions(r io.Reader) ([]uint16, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	if h[0] != 0 || h[1] != 0 || Command(h[2]) != Versions {
		return nil, fmt.Errorf("%w: expected VERSIONS", ErrInvalid)
	}
	n := int(binary.BigEndian.Uint16(h[3:5]))
	if n == 0 || n%2 != 0 {
		return nil, fmt.Errorf("%w: invalid versions length", ErrInvalid)
	}
	b := make([]byte, n)
	if err := readRest(r, b); err != nil {
		return nil, err
	}
	versions := make([]uint16, n/2)
	for i := range versions {
		versions[i] = binary.BigEndian.Uint16(b[2*i:])
	}
	return versions, nil
}

// NegotiateVersion chooses the highest nonzero version in both lists.
// The caller's supported list must only contain implemented protocols.
func NegotiateVersion(peer, supported []uint16) (uint16, error) {
	var best uint16
	for _, p := range peer {
		for _, s := range supported {
			if p == s && p > best {
				best = p
			}
		}
	}
	if best == 0 {
		return 0, fmt.Errorf("%w: no shared link protocol", ErrInvalid)
	}
	return best, nil
}

func readRest(r io.Reader, b []byte) error {
	_, err := io.ReadFull(r, b)
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
