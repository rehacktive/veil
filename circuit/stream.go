package circuit

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"veil/cell"
	"veil/relaycrypto"
)

var (
	ErrAPIMode     = errors.New("cannot mix raw relay and managed stream APIs on one circuit")
	ErrStreamLimit = errors.New("circuit stream limit reached; build another circuit")
	errCredit      = errors.New("waiting for SENDME")
)

const maxStreams = 32

// StreamError is an exit's END reason. It is diagnostic only and never echoed.
// Reason 2 means DNS resolution failed; 4 means exit policy; 5 means refused.
type StreamError struct{ Reason byte }

func (e *StreamError) Error() string { return fmt.Sprintf("Tor stream ended (reason %d)", e.Reason) }

type streamAddr string

func (a streamAddr) Network() string { return "tcp" }
func (a streamAddr) String() string  { return string(a) }

// DialContext opens a TCP stream on this circuit's selected port and IP family.
// Hostnames are sent to the exit in BEGIN, never resolved locally. The context
// governs establishment only; Build's context continues to own circuit lifetime.
// At most 32 streams may be open, and IDs are never reused on a circuit.
// The first Send/Receive or DialContext call selects an exclusive API mode.
func (c *Circuit) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	begin, err := c.begin(network, address)
	if err != nil {
		return nil, err
	}
	return c.dialStream(ctx, address, begin, cell.RelayBegin)
}

func (c *Circuit) dialStream(ctx context.Context, address string, begin []byte, command cell.RelayCommand) (net.Conn, error) {
	var err error
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.err != nil {
		err = c.err
	} else if c.mode == 1 {
		err = ErrAPIMode
	}
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if c.streams == nil {
		c.mode = 2
		c.streams = newStreamMux(c)
		go c.streams.run()
	}
	m := c.streams
	c.mu.Unlock()
	return m.dial(ctx, address, begin, command)
}

func (c *Circuit) begin(network, address string) ([]byte, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("Tor streams support tcp, tcp4, or tcp6")
	}
	if network == "tcp4" && c.ipv6 || network == "tcp6" && !c.ipv6 {
		return nil, errors.New("stream IP family differs from circuit selection")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 || c.port == 0 || p != uint64(c.port) {
		return nil, errors.New("stream port must match circuit selection")
	}
	host = strings.ToLower(host)
	if c.endHop.Load() == 3 {
		c.mu.Lock()
		ok := c.hs != nil && c.hs.stage == 3 && strings.TrimSuffix(host, ".") == c.hs.host
		c.mu.Unlock()
		if !ok {
			return nil, errors.New("stream does not match authenticated onion service")
		}
		return append([]byte(":"+strconv.FormatUint(p, 10)), 0), nil
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		ip = ip.Unmap()
		if ip.Zone() != "" || ip.Is6() != c.ipv6 {
			return nil, errors.New("invalid destination IP family or zone")
		}
		host = ip.String()
	} else {
		name := strings.TrimSuffix(host, ".")
		if len(name) == 0 || len(name) > 253 || strings.HasSuffix(name, ".onion") || name == "onion" {
			return nil, errors.New("unsupported destination hostname")
		}
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, errors.New("invalid destination hostname")
			}
			for _, b := range []byte(label) {
				if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
					return nil, errors.New("destination hostname must use ASCII DNS labels")
				}
			}
		}
	}
	body := append([]byte(net.JoinHostPort(host, strconv.FormatUint(p, 10))), 0)
	if c.ipv6 {
		body = binary.BigEndian.AppendUint32(body, 3)
	} // IPv6 permitted; IPv4 forbidden.
	return body, nil
}

type streamMux struct {
	c       *Circuit
	mu      sync.Mutex
	wake    chan struct{}
	held    int
	streams map[uint16]*streamConn
	// Closed IDs retain only remaining receive credit; application buffers are
	// not retained. Late in-flight DATA is charged to the circuit and discarded.
	retired                      map[uint16]int
	next                         uint16
	exhausted                    bool
	packageWindow, deliverWindow int
	sent                         int
	tags                         []relaycrypto.Tag
	randomAfter                  int
	randomSeen                   bool
	accepted                     chan *IncomingStream
	service                      bool
	controls                     chan cell.RelayMessage
	done                         chan struct{}
}

func newStreamMux(c *Circuit) *streamMux {
	return &streamMux{c: c, wake: make(chan struct{}), streams: make(map[uint16]*streamConn), retired: make(map[uint16]int), next: 1, packageWindow: c.window, deliverWindow: 1000, controls: make(chan cell.RelayMessage, maxStreams*12+16), done: make(chan struct{})}
}
func (m *streamMux) signal() { close(m.wake); m.wake = make(chan struct{}) }
func (m *streamMux) control(cmd cell.RelayCommand, id uint16, data []byte) error {
	select {
	case m.controls <- cell.RelayMessage{Command: cmd, StreamID: id, Data: data}:
		return nil
	default:
		return fmt.Errorf("%w: control queue full", ErrProtocol)
	}
}
func (m *streamMux) run() {
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-m.c.done:
				return
			case msg := <-m.controls:
				ctx, cancel := context.WithTimeout(m.c.ctx, 30*time.Second)
				_, err := m.c.send(ctx, int(m.c.endHop.Load()), msg, func(_ *cell.RelayMessage) error {
					if msg.Command != cell.RelaySendme || msg.StreamID == 0 {
						return nil
					}
					m.mu.Lock()
					defer m.mu.Unlock()
					if m.streams[msg.StreamID] == nil {
						return net.ErrClosed
					}
					return nil
				}, nil)
				cancel()
				if errors.Is(err, net.ErrClosed) {
					continue
				}
				if err != nil {
					m.c.shutdown(err)
					return
				}
			}
		}
	}()
	defer func() {
		m.mu.Lock()
		for _, s := range m.streams {
			s.err = m.c.Err()
			s.queue = nil
			s.buffered = 0
			s.stopWrite(s.err)
		}
		m.signal()
		m.mu.Unlock()
		<-writerDone
		close(m.done)
	}()
	for {
		msg, err := m.c.receive(m.c.ctx)
		if err == nil {
			m.mu.Lock()
			err = m.handle(msg)
			m.mu.Unlock()
		}
		if err != nil {
			m.c.shutdown(err)
			return
		}
	}
}

func (m *streamMux) dial(ctx context.Context, address string, begin []byte, command cell.RelayCommand) (net.Conn, error) {
	m.mu.Lock()
	if m.held >= maxStreams || m.exhausted {
		m.mu.Unlock()
		return nil, ErrStreamLimit
	}
	id := m.next
	if id == 65535 {
		m.exhausted = true
	} else {
		m.next++
	}
	s := &streamConn{mux: m, id: id, address: streamAddr(address), packageWindow: 500, deliverWindow: 500, writeGate: make(chan struct{}, 1)}
	m.streams[id] = s
	m.held++
	m.mu.Unlock()
	// Mark BEGIN before transmission, so a prompt reply cannot race publication.
	_, err := m.c.send(ctx, int(m.c.endHop.Load()), cell.RelayMessage{Command: command, StreamID: id, Data: begin}, func(_ *cell.RelayMessage) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		s.begun = true
		return nil
	}, nil)
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	m.mu.Lock()
	for !s.connected && s.err == nil {
		wake := m.wake
		m.mu.Unlock()
		err = waitStream(ctx, m.c.done, wake, time.Time{})
		m.mu.Lock()
		if err != nil {
			if errors.Is(err, ErrClosed) {
				err = m.c.Err()
			}
			break
		}
	}
	if err == nil {
		err = s.err
	}
	if err == nil {
		err = ctx.Err()
	}
	m.mu.Unlock()
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func sendme(tag relaycrypto.Tag) []byte {
	return append([]byte{1, 0, 20}, tag[:]...)
}
func (m *streamMux) handle(msg Message) error {
	fail := func() error { return fmt.Errorf("%w: invalid stream state or SENDME", ErrProtocol) }
	if msg.Command == cell.RelaySendme && msg.StreamID == 0 {
		b := msg.Data
		if msg.Hop != int(m.c.endHop.Load()) || len(b) < 23 || b[0] != 1 {
			return fail()
		}
		n := int(binary.BigEndian.Uint16(b[1:3]))
		if n < 20 || n > len(b)-3 || len(m.tags) == 0 || subtle.ConstantTimeCompare(b[3:23], m.tags[0][:]) != 1 || m.packageWindow+100 > m.c.window {
			return fail()
		}
		m.tags = m.tags[1:]
		m.packageWindow += 100
		m.signal()
		return nil
	}
	if msg.Command == cell.RelayBegin {
		return m.incomingBegin(msg)
	}
	s := m.streams[msg.StreamID]
	late, retired := m.retired[msg.StreamID]
	if s == nil && !retired {
		return fail()
	}
	if msg.Command == cell.RelayData {
		m.deliverWindow--
		if m.deliverWindow < 0 {
			return fail()
		}
		if m.deliverWindow <= 900 {
			if err := m.control(cell.RelaySendme, 0, sendme(msg.Tag)); err != nil {
				return err
			}
			m.deliverWindow += 100
		}
	}
	if retired {
		switch msg.Command {
		case cell.RelayData:
			if late <= 0 {
				return fail()
			}
			m.retired[msg.StreamID] = late - 1
		case cell.RelayConnected, cell.RelayEnd, cell.RelaySendme:
		default:
			return fail()
		}
		return nil
	}
	if !s.begun {
		return fail()
	}
	switch msg.Command {
	case cell.RelayConnected:
		if s.connected || !(len(msg.Data) == 0 || len(msg.Data) == 8 || len(msg.Data) == 25 && binary.BigEndian.Uint32(msg.Data[:4]) == 0 && msg.Data[4] == 6) {
			return fail()
		}
		s.connected = true
	case cell.RelayData:
		if !s.connected || s.deliverWindow <= 0 {
			return fail()
		}
		s.deliverWindow--
		if len(msg.Data) != 0 {
			s.queue = append(s.queue, msg.Data)
			s.buffered += len(msg.Data)
		}
		// Empty DATA still consumes credit, but has nothing for Read to drain.
		if err := m.ackStream(s); err != nil {
			return err
		}
	case cell.RelaySendme:
		if !s.connected || s.unacked < 50 || s.packageWindow > 450 {
			return fail()
		}
		s.unacked -= 50
		s.packageWindow += 50
	case cell.RelayEnd:
		reason := byte(1)
		if len(msg.Data) != 0 {
			reason = msg.Data[0]
		}
		s.err = &StreamError{Reason: reason}
		if reason == 6 && s.connected {
			s.err = io.EOF
		}
		s.stopWrite(s.err)
		m.retire(s)
		if s.buffered == 0 {
			m.release(s)
		}
	default:
		return fail()
	}
	m.signal()
	return nil
}
func (m *streamMux) ackStream(s *streamConn) error {
	if s.buffered >= 10*cell.RelayDataSize || s.err != nil {
		return nil
	}
	for s.deliverWindow <= 450 {
		if err := m.control(cell.RelaySendme, s.id, nil); err != nil {
			return err
		}
		s.deliverWindow += 50
	}
	return nil
}
func (m *streamMux) release(s *streamConn) {
	if !s.released {
		s.released = true
		m.held--
	}
}
func (m *streamMux) retire(s *streamConn) {
	delete(m.streams, s.id)
	m.retired[s.id] = s.deliverWindow
}

// streamConn implements net.Conn. Tor END closes both directions; there is no
// CloseWrite. An indeterminate encrypted wire write fails the entire circuit.
type streamConn struct {
	released                              bool
	mux                                   *streamMux
	id                                    uint16
	address                               streamAddr
	begun, connected, closed              bool
	err                                   error
	packageWindow, deliverWindow, unacked int
	queue                                 [][]byte
	offset, buffered                      int
	readDeadline, writeDeadline           time.Time
	writeGate                             chan struct{}
	readMu                                sync.Mutex
	writeCancel                           context.CancelCauseFunc
	writeTimer                            *time.Timer
}

var _ net.Conn = (*streamConn)(nil)

func (s *streamConn) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	m := s.mux
	m.mu.Lock()
	defer m.mu.Unlock()
	for {
		if s.closed {
			return 0, net.ErrClosed
		}
		if !s.readDeadline.IsZero() && !time.Now().Before(s.readDeadline) {
			return 0, os.ErrDeadlineExceeded
		}
		if len(p) == 0 {
			return 0, nil
		}
		if len(s.queue) != 0 {
			n := copy(p, s.queue[0][s.offset:])
			s.offset += n
			s.buffered -= n
			if s.buffered == 0 && s.err != nil {
				m.release(s)
			}
			if s.offset == len(s.queue[0]) {
				s.queue[0] = nil
				s.queue = s.queue[1:]
				s.offset = 0
			}
			if err := m.ackStream(s); err != nil {
				m.mu.Unlock()
				m.c.shutdown(err)
				m.mu.Lock()
				return n, err
			}
			return n, nil
		}
		if s.err != nil {
			return 0, s.err
		}
		wake, deadline := m.wake, s.readDeadline
		m.mu.Unlock()
		err := waitStream(context.Background(), m.c.done, wake, deadline)
		m.mu.Lock()
		if err != nil && errors.Is(err, ErrClosed) {
			return 0, m.c.Err()
		}
		// Recheck a deadline after waking: SetReadDeadline may have extended it.
	}
}

func (s *streamConn) Write(p []byte) (int, error) {
	m := s.mux
	// Gate acquisition also observes changes to deadlines and Close.
	for {
		m.mu.Lock()
		err := s.writeError()
		wake, deadline := m.wake, s.writeDeadline
		m.mu.Unlock()
		if err != nil {
			return 0, err
		}
		select {
		case s.writeGate <- struct{}{}:
			goto acquired
		default:
		}
		if err := waitStream(context.Background(), m.c.done, wake, deadline); errors.Is(err, ErrClosed) {
			return 0, m.c.Err()
		}
	}
acquired:
	defer func() { <-s.writeGate; m.mu.Lock(); m.signal(); m.mu.Unlock() }()
	ctx, cancel := context.WithCancelCause(m.c.ctx)
	m.mu.Lock()
	s.writeCancel = cancel
	s.armWriteTimer()
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		if s.writeTimer != nil {
			s.writeTimer.Stop()
		}
		s.writeCancel = nil
		m.mu.Unlock()
		cancel(nil)
	}()
	written := 0
	for written < len(p) {
		m.mu.Lock()
		err := s.writeError()
		ready := m.packageWindow > 0 && s.packageWindow > 0
		wake := m.wake
		m.mu.Unlock()
		if err != nil {
			return written, err
		}
		if !ready {
			if err = waitStream(ctx, m.c.done, wake, time.Time{}); err != nil {
				return written, contextOrCircuit(ctx, m.c)
			}
			continue
		}
		n := min(len(p)-written, cell.RelayDataSize)
		_, err = m.c.send(ctx, int(m.c.endHop.Load()), cell.RelayMessage{Command: cell.RelayData, StreamID: s.id, Data: p[written : written+n]}, func(msg *cell.RelayMessage) error {
			m.mu.Lock()
			defer m.mu.Unlock()
			if err := s.writeError(); err != nil {
				return err
			}
			if m.packageWindow == 0 || s.packageWindow == 0 {
				return errCredit
			}
			// Each 100-cell SENDME batch contains unpredictable padding.
			// Randomize the forced position in its latter half, and avoid
			// shortening when an earlier partial DATA cell provided entropy.
			if m.sent == 0 {
				r, err := rand.Int(rand.Reader, big.NewInt(50))
				if err != nil {
					return err
				}
				m.randomAfter = 50 + int(r.Int64())
				m.randomSeen = false
			}
			if m.sent == m.randomAfter && !m.randomSeen {
				n = min(n, cell.RelayDataSize-20)
				msg.Data = msg.Data[:n]
			}
			if n <= cell.RelayDataSize-20 {
				m.randomSeen = true
			}
			m.packageWindow--
			s.packageWindow--
			s.unacked++
			return nil
		}, func(tag relaycrypto.Tag) {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.sent++
			if m.sent == 100 {
				m.tags = append(m.tags, tag)
				m.sent = 0
			}
		})
		if errors.Is(err, errCredit) {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				err = contextOrCircuit(ctx, m.c)
			}
			return written, err
		}
		written += n
	}
	return written, nil
}
func (s *streamConn) writeError() error {
	if s.closed {
		return net.ErrClosed
	}
	if s.err != nil {
		return s.err
	}
	if !s.writeDeadline.IsZero() && !time.Now().Before(s.writeDeadline) {
		return os.ErrDeadlineExceeded
	}
	return nil
}
func (s *streamConn) stopWrite(err error) {
	if s.writeCancel != nil {
		s.writeCancel(err)
	}
}
func (s *streamConn) armWriteTimer() {
	if s.writeTimer != nil {
		s.writeTimer.Stop()
	}
	if s.writeCancel == nil || s.writeDeadline.IsZero() {
		return
	}
	cancel := s.writeCancel
	s.writeTimer = time.AfterFunc(max(0, time.Until(s.writeDeadline)), func() {
		s.mux.mu.Lock()
		defer s.mux.mu.Unlock()
		if !s.writeDeadline.IsZero() && !time.Now().Before(s.writeDeadline) {
			cancel(os.ErrDeadlineExceeded)
		}
	})
}
func (s *streamConn) Close() error {
	m := s.mux
	m.mu.Lock()
	if s.closed {
		m.mu.Unlock()
		return nil
	}
	s.closed = true
	m.release(s)
	s.queue = nil
	s.buffered = 0
	s.stopWrite(net.ErrClosed)
	var err error
	if m.streams[s.id] != nil {
		m.retire(s)
		if s.begun {
			err = m.control(cell.RelayEnd, s.id, []byte{1})
		}
	}
	m.signal()
	m.mu.Unlock()
	if err != nil {
		m.c.shutdown(err)
	}
	return nil
}
func (s *streamConn) LocalAddr() net.Addr                { return streamAddr("tor:0") }
func (s *streamConn) RemoteAddr() net.Addr               { return s.address }
func (s *streamConn) SetDeadline(t time.Time) error      { return s.deadline(t, true, true) }
func (s *streamConn) SetReadDeadline(t time.Time) error  { return s.deadline(t, true, false) }
func (s *streamConn) SetWriteDeadline(t time.Time) error { return s.deadline(t, false, true) }
func (s *streamConn) deadline(t time.Time, read, write bool) error {
	m := s.mux
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if read {
		s.readDeadline = t
	}
	if write {
		s.writeDeadline = t
		s.armWriteTimer()
	}
	m.signal()
	return nil
}
func waitStream(ctx context.Context, done, wake <-chan struct{}, deadline time.Time) error {
	var timer *time.Timer
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		timer = time.NewTimer(max(0, time.Until(deadline)))
		timeout = timer.C
		defer timer.Stop()
	}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-done:
		return ErrClosed
	case <-wake:
		return nil
	case <-timeout:
		return os.ErrDeadlineExceeded
	}
}
func contextOrCircuit(ctx context.Context, c *Circuit) error {
	cause := context.Cause(ctx)
	if cause != nil && !errors.Is(cause, context.Canceled) {
		return cause
	}
	// The circuit's internal context is canceled for every teardown. Preserve
	// the authenticated remote/protocol error rather than hiding it behind that
	// implementation detail when a writer was waiting for credit or the gate.
	if err := c.Err(); err != nil {
		return err
	}
	return cause
}
