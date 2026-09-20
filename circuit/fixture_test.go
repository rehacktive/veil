package circuit

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"encoding"
	"errors"
	"fmt"
	"hash"
	"net/netip"
	"sync"
	"testing"
	"time"

	"veil/cell"
	"veil/channel"
	"veil/directory"
	"veil/ntor"
)

// A server-side ntor and onion-cipher fixture, independent of the production
// client implementation. Every extension checks its pins/address and every
// forward cell is decrypted and digest-verified at the receiving test relay.
type testLayer struct {
	forward, backward cipher.Stream
	fd, bd            hash.Hash
}

func serverHandshake(private *ecdh.PrivateKey, identity [20]byte, request []byte) ([]byte, testLayer, error) {
	const proto = "ntor-curve25519-sha256-1"
	var layer testLayer
	if len(request) != ntor.RequestSize || !bytes.Equal(request[:20], identity[:]) || !bytes.Equal(request[20:52], private.PublicKey().Bytes()) {
		return nil, layer, errors.New("fixture: wrong ntor request")
	}
	x, err := ecdh.X25519().NewPublicKey(request[52:])
	if err != nil {
		return nil, layer, err
	}
	y, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, layer, err
	}
	xy, err := y.ECDH(x)
	if err != nil {
		return nil, layer, err
	}
	xb, err := private.ECDH(x)
	if err != nil {
		return nil, layer, err
	}
	input := bytes.Join([][]byte{xy, xb, identity[:], private.PublicKey().Bytes(), x.Bytes(), y.PublicKey().Bytes(), []byte(proto)}, nil)
	mac := func(suffix string, data []byte) []byte {
		h := hmac.New(sha256.New, []byte(proto+suffix))
		h.Write(data)
		return h.Sum(nil)
	}
	authInput := bytes.Join([][]byte{mac(":verify", input), identity[:], private.PublicKey().Bytes(), y.PublicKey().Bytes(), x.Bytes(), []byte(proto), []byte("Server")}, nil)
	reply := append(y.PublicKey().Bytes(), mac(":mac", authInput)...)
	material, err := hkdf.Key(sha256.New, input, []byte(proto+":key_extract"), proto+":key_expand", 92)
	if err != nil {
		return nil, layer, err
	}
	f, _ := aes.NewCipher(material[40:56])
	b, _ := aes.NewCipher(material[56:72])
	layer.forward = cipher.NewCTR(f, make([]byte, 16))
	layer.backward = cipher.NewCTR(b, make([]byte, 16))
	layer.fd = sha1.New()
	layer.fd.Write(material[:20])
	layer.bd = sha1.New()
	layer.bd.Write(material[20:40])
	return reply, layer, nil
}

type testNetwork struct {
	mu      sync.Mutex
	hops    [3]hop
	secrets [3]*ecdh.PrivateKey
	layers  []testLayer
	frames  chan cell.Cell
	done    chan struct{}
	closed  bool
	id      uint32
	writes  []cell.Cell
	// Called with mu held. Tests configure before building, never concurrently.
	modify            func(int, *cell.Cell)
	extension         func(int, *Message)
	stall             int // 1,2,3 stalls that handshake; zero disables.
	streamDataLengths []int
	stream            func(cell.RelayMessage, int) error
	blockWrites       bool
}

func network(t *testing.T) *testNetwork {
	t.Helper()
	n := &testNetwork{frames: make(chan cell.Cell, 1024), done: make(chan struct{}), id: 0x80000042}
	for i := range n.hops {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		n.secrets[i] = key
		h := &n.hops[i]
		h.target.Address = netip.MustParseAddrPort(fmt.Sprintf("%d.1.2.3:9001", i+1))
		h.target.Identity.RSA[0] = byte(i + 1)
		h.target.Identity.Ed25519[0] = byte(i + 1)
		h.ntor.Identity = h.target.Identity.RSA
		copy(h.ntor.OnionKey[:], key.PublicKey().Bytes())
	}
	return n
}

func (n *testNetwork) AllocateCircuitID() (uint32, error) { return n.id, nil }
func (n *testNetwork) Done() <-chan struct{}              { return n.done }
func (n *testNetwork) Err() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return ErrClosed
	}
	return nil
}
func (n *testNetwork) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.closed {
		n.closed = true
		close(n.done)
	}
	return nil
}
func (n *testNetwork) Receive(ctx context.Context) (cell.Cell, error) {
	select {
	case <-ctx.Done():
		return cell.Cell{}, ctx.Err()
	case <-n.done:
		return cell.Cell{}, ErrClosed
	case f := <-n.frames:
		return f, nil
	}
}
func (n *testNetwork) dial(ctx context.Context, target channel.Target, _ channel.Options) (transport, error) {
	if target != n.hops[0].target {
		return nil, errors.New("wrong guard target")
	}
	return n, nil
}
func (n *testNetwork) Send(ctx context.Context, f cell.Cell) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return ErrClosed
	}
	if n.blockWrites {
		n.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-n.done:
		}
		n.mu.Lock()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrClosed
	}
	f.Payload = bytes.Clone(f.Payload)
	n.writes = append(n.writes, f)
	if f.CircuitID != n.id {
		return errors.New("wrong circuit ID")
	}
	if f.Command == cell.Destroy {
		return nil
	}
	if f.Command == cell.Create2 {
		if len(n.layers) != 0 {
			return errors.New("duplicate CREATE2")
		}
		kind, request, err := cell.DecodeCreate2(f.Payload)
		if err != nil || kind != cell.HandshakeNtor {
			return errors.New("bad CREATE2")
		}
		return n.handshake(0, request)
	}
	if f.Command != cell.Relay && f.Command != cell.RelayEarly {
		return errors.New("bad channel command")
	}
	m, target, err := n.decrypt(f.Payload)
	if err != nil {
		return err
	}
	if m.Command == cell.RelayExtend2 {
		if f.Command != cell.RelayEarly || m.StreamID != 0 || target != len(n.layers)-1 {
			return errors.New("bad extension target/framing")
		}
		i := len(n.layers)
		if i >= 3 {
			return errors.New("extra extension")
		}
		ext, err := cell.DecodeExtend2(m.Data)
		if err != nil || ext.HandshakeType != cell.HandshakeNtor {
			return errors.New("bad EXTEND2")
		}
		// Assert the on-wire link specs explicitly, including both identity pins.
		if len(ext.Links) != 3 || ext.Links[0].Type != cell.LinkIPv4 || !bytes.Equal(ext.Links[0].Data, []byte{byte(i + 1), 1, 2, 3, 0x23, 0x29}) || ext.Links[1].Type != cell.LinkRSAIdentity || !bytes.Equal(ext.Links[1].Data, n.hops[i].target.Identity.RSA[:]) || ext.Links[2].Type != cell.LinkEd25519Identity || !bytes.Equal(ext.Links[2].Data, n.hops[i].target.Identity.Ed25519[:]) {
			return errors.New("wrong extension link specs")
		}
		return n.handshake(i, ext.Handshake)
	}
	if n.stream != nil {
		if m.Command == cell.RelayData {
			n.streamDataLengths = append(n.streamDataLengths, len(m.Data))
		}
		return n.stream(m, target)
	}
	if m.Command == cell.RelayData {
		return n.emit(target, cell.RelayMessage{Command: cell.RelayData, StreamID: m.StreamID, Data: m.Data})
	}
	return nil
}

func (n *testNetwork) handshake(i int, request []byte) error {
	if n.stall == i+1 {
		return nil
	}
	reply, layer, err := serverHandshake(n.secrets[i], n.hops[i].ntor.Identity, request)
	if err != nil {
		return err
	}
	body, _ := cell.EncodeCreated2(reply)
	if i == 0 {
		f := cell.Cell{CircuitID: n.id, Command: cell.Created2, Payload: body}
		if n.modify != nil {
			n.modify(i, &f)
		}
		n.frames <- f
	} else {
		m := Message{Hop: i - 1, RelayMessage: cell.RelayMessage{Command: cell.RelayExtended2, Data: body}}
		if n.extension != nil {
			n.extension(i, &m)
		}
		f, err := n.encrypted(m.Hop, m.RelayMessage)
		if err != nil {
			return err
		}
		if n.modify != nil {
			n.modify(i, &f)
		}
		n.frames <- f
	}
	n.layers = append(n.layers, layer)
	return nil
}

func (n *testNetwork) decrypt(raw []byte) (cell.RelayMessage, int, error) {
	if len(raw) != cell.PayloadSize {
		return cell.RelayMessage{}, 0, errors.New("bad encrypted size")
	}
	var body cell.RelayBody
	copy(body[:], raw)
	for i := range n.layers {
		l := &n.layers[i]
		l.forward.XORKeyStream(body[:], body[:])
		if body[1] != 0 || body[2] != 0 {
			continue
		}
		received := bytes.Clone(body[5:9])
		clear(body[5:9])
		state, _ := l.fd.(encoding.BinaryMarshaler).MarshalBinary()
		candidate := sha1.New()
		if l.fd.Size() == 32 {
			candidate = sha3.New256()
		}
		candidate.(encoding.BinaryUnmarshaler).UnmarshalBinary(state)
		candidate.Write(body[:])
		copy(body[5:9], received)
		if !bytes.Equal(candidate.Sum(nil)[:4], received) {
			continue
		}
		l.fd = candidate
		m, err := cell.DecodeRelay(body)
		return m, i, err
	}
	return cell.RelayMessage{}, 0, errors.New("fixture: no matching forward digest")
}

func (n *testNetwork) encrypted(hop int, m cell.RelayMessage) (cell.Cell, error) {
	body, err := cell.EncodeRelay(m)
	if err != nil {
		return cell.Cell{}, err
	}
	n.layers[hop].bd.Write(body[:])
	copy(body[5:9], n.layers[hop].bd.Sum(nil)[:4])
	for i := hop; i >= 0; i-- {
		n.layers[i].backward.XORKeyStream(body[:], body[:])
	}
	return cell.Cell{CircuitID: n.id, Command: cell.Relay, Payload: body[:]}, nil
}
func (n *testNetwork) emit(hop int, m cell.RelayMessage) error {
	f, err := n.encrypted(hop, m)
	if err == nil {
		n.frames <- f
	}
	return err
}

type testAttempt struct {
	success, failure, closed int
	usable                   directory.GuardUsability
	err                      error
}

func (a *testAttempt) Success(time.Time) error                      { a.success++; return a.err }
func (a *testAttempt) Failure(time.Time, bool) error                { a.failure++; return nil }
func (a *testAttempt) Close()                                       { a.closed++ }
func (a *testAttempt) Usability(time.Time) directory.GuardUsability { return a.usable }

func built(t *testing.T) (*Circuit, *testNetwork) {
	t.Helper()
	n := network(t)
	a := &testAttempt{usable: directory.GuardUsable}
	c, err := build(context.Background(), n.hops, a, time.Second, n.dial, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if a.success != 1 || a.failure != 0 || a.closed != 1 {
		t.Fatalf("attempt: %+v", a)
	}
	t.Cleanup(func() { c.Close() })
	return c, n
}
