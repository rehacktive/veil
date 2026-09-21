package circuit

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"veil/cell"
)

// EstablishIntroduction authenticates a fresh service introduction circuit.
// sign receives the circuit binding, which must never be persisted or logged.
func (c *Circuit) EstablishIntroduction(ctx context.Context, sign func([20]byte) []byte) error {
	c.mu.Lock()
	if c.hs == nil || c.hs.purpose != OnionServiceIntroduction || c.hs.stage != 0 || sign == nil {
		c.mu.Unlock()
		return ErrProtocol
	}
	c.hs.stage = 1
	binding := c.binding
	c.mu.Unlock()
	payload := sign(binding)
	clear(binding[:])
	if _, err := c.Send(ctx, c.relayEnd, cell.RelayMessage{Command: cell.RelayEstablishIntro, Data: payload}); err != nil {
		return err
	}
	m, err := c.Receive(ctx)
	if err != nil {
		return err
	}
	if m.Command != cell.RelayIntroEstablished {
		return ErrProtocol
	}
	return nil
}

// JoinService installs the reverse-direction virtual hop before sending
// RENDEZVOUS1, so an immediate client BEGIN cannot race key installation.
func (c *Circuit) JoinService(ctx context.Context, cookie [20]byte, reply [64]byte, keys [128]byte, port uint16) error {
	c.mu.Lock()
	if c.hs == nil || c.hs.purpose != OnionServiceRendezvous || c.hs.stage != 0 || c.mode != 0 || port == 0 {
		c.mu.Unlock()
		return ErrProtocol
	}
	var reverse [128]byte
	copy(reverse[:32], keys[32:64])
	copy(reverse[32:64], keys[:32])
	copy(reverse[64:96], keys[96:])
	copy(reverse[96:], keys[64:96])
	clear(keys[:])
	err := c.crypto.AddOnionHop(reverse)
	clear(reverse[:])
	if err != nil {
		c.mu.Unlock()
		return err
	}
	c.hs.stage = 1
	c.port = port
	c.endHop.Add(1)
	c.mode = 2
	c.streams = newStreamMux(c)
	c.streams.service = true
	c.streams.accepted = make(chan *IncomingStream, maxStreams)
	go c.streams.run()
	c.mu.Unlock()
	payload := append(cookie[:0:0], cookie[:]...)
	payload = append(payload, reply[:]...)
	_, err = c.send(ctx, c.relayEnd, cell.RelayMessage{Command: cell.RelayRendezvous1, Data: payload}, nil, nil)
	if err != nil {
		c.shutdown(err)
	}
	return err
}

// IncomingStream is a pending request for the single configured virtual port.
// Call Accept when admitting the stream to a listener or after connecting to the
// configured local backend; call Close to reject it. No client-supplied hostname
// is ever resolved or dialed.
type IncomingStream struct{ stream *streamConn }

func (s *IncomingStream) Close() error { return s.stream.Close() }
func (s *IncomingStream) Accept(ctx context.Context) (net.Conn, error) {
	m := s.stream.mux
	_, err := m.c.send(ctx, m.c.relayEnd+1, cell.RelayMessage{Command: cell.RelayConnected, StreamID: s.stream.id}, func(_ *cell.RelayMessage) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		if s.stream.connected || s.stream.closed || s.stream.err != nil {
			return net.ErrClosed
		}
		s.stream.connected = true
		return nil
	}, nil)
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	return s.stream, nil
}
func (c *Circuit) AcceptService(ctx context.Context) (*IncomingStream, error) {
	c.mu.Lock()
	m := c.streams
	c.mu.Unlock()
	if m == nil || !m.service {
		return nil, ErrAPIMode
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, c.Err()
	case s := <-m.accepted:
		return s, nil
	}
}

// Called only by the stream reader with m.mu held. Reject reused IDs and bound
// both active requests and retained replay/late-data state by the 16-bit ID space.
func (m *streamMux) incomingBegin(msg Message) error {
	if !m.service || msg.Hop != m.c.relayEnd+1 || msg.StreamID == 0 || m.streams[msg.StreamID] != nil {
		return ErrProtocol
	}
	if _, old := m.retired[msg.StreamID]; old {
		return ErrProtocol
	}
	end := bytes.IndexByte(msg.Data, 0)
	allowed := false
	if end > 1 && msg.Data[0] == ':' && (len(msg.Data) == end+1 || len(msg.Data) == end+5 && bytes.Equal(msg.Data[end+1:], []byte{0, 0, 0, 0})) {
		p, err := strconv.ParseUint(string(msg.Data[1:end]), 10, 16)
		allowed = err == nil && p == uint64(m.c.port)
	}
	if !allowed || m.held >= maxStreams {
		m.retired[msg.StreamID] = 0
		return m.control(cell.RelayEnd, msg.StreamID, []byte{4})
	}
	s := &streamConn{mux: m, id: msg.StreamID, address: streamAddr("onion-client"), begun: true, packageWindow: 500, deliverWindow: 500, writeGate: make(chan struct{}, 1)}
	m.streams[s.id] = s
	m.held++
	select {
	case m.accepted <- &IncomingStream{stream: s}:
		return nil
	default:
		return errors.New("incoming onion stream queue full")
	}
}
