package circuit

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"veil/cell"
	"veil/directory"
	"veil/relaycrypto"
)

// A peer that authenticates DATA using the independent fixture cipher and
// validates client SENDMEs against its own running backward digest.
type streamPeer struct {
	echoed                  int
	received                int
	perStream               map[uint16]int
	expected                [][]byte
	begins                  [][]byte
	circuitACKs, streamACKs int
	stallBegin              bool
	stallACKs               bool
	badACK                  bool
}

func streamCircuit(t *testing.T, configure func(*streamPeer)) (*Circuit, *testNetwork, *streamPeer) {
	return streamCircuitHops(t, configure, 3)
}

func streamCircuitHops(t *testing.T, configure func(*streamPeer), count int) (*Circuit, *testNetwork, *streamPeer) {
	t.Helper()
	n := network(t, count)
	peer := &streamPeer{perStream: make(map[uint16]int)}
	if configure != nil {
		configure(peer)
	}
	n.stream = func(msg cell.RelayMessage, hop int) error {
		if hop != len(n.layers)-1 {
			return errors.New("wrong stream hop")
		}
		switch msg.Command {
		case cell.RelayBegin:
			peer.begins = append(peer.begins, bytes.Clone(msg.Data))
			if peer.stallBegin {
				return nil
			}
			return n.emit(hop, cell.RelayMessage{Command: cell.RelayConnected, StreamID: msg.StreamID})
		case cell.RelayData:
			peer.received++
			peer.perStream[msg.StreamID]++
			if !peer.stallACKs {
				if peer.received%100 == 0 {
					tag := n.layers[hop].fd.Sum(nil)
					data := append([]byte{1, 0, 20}, tag[:20]...)
					if peer.badACK {
						data[3] ^= 1
					}
					if err := n.emit(hop, cell.RelayMessage{Command: cell.RelaySendme, Data: data}); err != nil {
						return err
					}
				}
				if peer.perStream[msg.StreamID]%50 == 0 {
					if err := n.emit(hop, cell.RelayMessage{Command: cell.RelaySendme, StreamID: msg.StreamID}); err != nil {
						return err
					}
				}
			}
			if err := n.emit(hop, cell.RelayMessage{Command: cell.RelayData, StreamID: msg.StreamID, Data: msg.Data}); err != nil {
				return err
			}
			peer.echoed++
			if peer.echoed%100 == 0 {
				peer.expected = append(peer.expected, bytes.Clone(n.layers[hop].bd.Sum(nil)[:20]))
			}
		case cell.RelaySendme:
			if msg.StreamID == 0 {
				if len(msg.Data) != 23 || msg.Data[0] != 1 || binary.BigEndian.Uint16(msg.Data[1:3]) != 20 || len(peer.expected) == 0 || !bytes.Equal(msg.Data[3:], peer.expected[0]) {
					return errors.New("client sent invalid circuit SENDME")
				}
				peer.expected = peer.expected[1:]
				peer.circuitACKs++
			} else {
				peer.streamACKs++
			}
		case cell.RelayEnd:
			if !bytes.Equal(msg.Data, []byte{1}) {
				return errors.New("client leaked END reason")
			}
		default:
			return errors.New("unexpected client command")
		}
		return nil
	}
	c, err := buildHops(context.Background(), n.hops, &testAttempt{usable: directory.GuardUsable}, time.Second, n.dial, func() bool { return true }, false)
	if err != nil {
		t.Fatal(err)
	}
	c.port = 80
	t.Cleanup(func() { c.Close() })
	return c, n, peer
}
func dialStream(t *testing.T, c *Circuit) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s, err := c.DialContext(ctx, "tcp", "example.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func inject(t *testing.T, n *testNetwork, msg cell.RelayMessage) {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.emit(2, msg); err != nil {
		t.Fatal(err)
	}
}
func TestStreamsLargeConcurrent(t *testing.T) {
	c, n, peer := streamCircuit(t, nil)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		s := dialStream(t, c)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.SetDeadline(time.Now().Add(10 * time.Second))
			data := bytes.Repeat([]byte{byte(i + 1)}, 1024*1024)
			done := make(chan error, 1)
			go func() { _, err := s.Write(data); done <- err }()
			got := make([]byte, len(data))
			_, err := io.ReadFull(s, got)
			if err != nil {
				t.Error(err)
			} else if !bytes.Equal(got, data) {
				t.Error("cross-stream data corruption")
			}
			if err := <-done; err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	n.mu.Lock()
	defer n.mu.Unlock()
	if peer.received < 8000 || peer.circuitACKs < 80 || peer.streamACKs < 160 {
		t.Fatalf("insufficient flow-control exercise: %+v", peer)
	}
	for _, begin := range peer.begins {
		if string(begin) != "example.invalid:80\x00" {
			t.Fatalf("hostname not forwarded: %q", begin)
		}
	}
}
func TestStreamDeadlineChangesAndCancellation(t *testing.T) {
	c, _, _ := streamCircuit(t, nil)
	s := dialStream(t, c)
	read := make(chan error, 1)
	go func() { _, err := s.Read(make([]byte, 1)); read <- err }()
	s.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if err := <-read; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	s.SetReadDeadline(time.Time{})
	if _, err := s.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(s, buf); err != nil || string(buf) != "hello" {
		t.Fatal(string(buf), err)
	}
	// Context cancellation after establishment must not close the connection.
	ctx, cancel := context.WithCancel(context.Background())
	other, err := c.DialContext(ctx, "tcp4", "other.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	cancel()
	if _, err = other.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
}
func TestStreamCreditDeadlineDoesNotDestroyCircuit(t *testing.T) {
	c, _, _ := streamCircuit(t, func(p *streamPeer) { p.stallACKs = true })
	s := dialStream(t, c)
	done := make(chan error, 1)
	// Drain echoes, so only the missing peer SENDMEs block the writer.
	go func() { _, _ = io.Copy(io.Discard, s) }()
	go func() { _, err := s.Write(make([]byte, 600*498)); done <- err }()
	time.Sleep(30 * time.Millisecond)
	s.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	if err := <-done; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	if c.Err() != nil {
		t.Fatal("credit wait killed circuit", c.Err())
	}
	other := dialStream(t, c)
	if _, err := other.Write([]byte("independent")); err != nil {
		t.Fatal(err)
	}
}
func TestStreamCanceledDialAndLateCells(t *testing.T) {
	c, n, peer := streamCircuit(t, func(p *streamPeer) { p.stallBegin = true })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.DialContext(ctx, "tcp", "example.invalid:80"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	inject(t, n, cell.RelayMessage{Command: cell.RelayConnected, StreamID: 1})
	inject(t, n, cell.RelayMessage{Command: cell.RelayData, StreamID: 1, Data: []byte("late")})
	n.mu.Lock()
	peer.stallBegin = false
	n.mu.Unlock()
	s := dialStream(t, c)
	if s.(*streamConn).id == 1 {
		t.Fatal("reused canceled ID")
	}
	if _, err := s.Write([]byte("yes")); err != nil {
		t.Fatal(err)
	}
}
func TestStreamEOFAndErrors(t *testing.T) {
	for _, reason := range []byte{6, 2, 5} {
		t.Run(string(rune('A'+reason)), func(t *testing.T) {
			c, n, _ := streamCircuit(t, nil)
			s := dialStream(t, c)
			inject(t, n, cell.RelayMessage{Command: cell.RelayData, StreamID: 1, Data: []byte("tail")})
			inject(t, n, cell.RelayMessage{Command: cell.RelayEnd, StreamID: 1, Data: []byte{reason}})
			got, err := io.ReadAll(s)
			if string(got) != "tail" {
				t.Fatal(string(got))
			}
			var remote *StreamError
			if reason == 6 && err != nil || reason != 6 && (!errors.As(err, &remote) || remote.Reason != reason) {
				t.Fatal(err)
			}
			if c.Err() != nil {
				t.Fatal(c.Err())
			}
		})
	}
}
func TestInvalidStreamCellsCloseCircuit(t *testing.T) {
	for _, msg := range []cell.RelayMessage{
		{Command: cell.RelaySendme, Data: []byte{0}},
		{Command: cell.RelaySendme, Data: make([]byte, 23)},
		{Command: cell.RelaySendme, StreamID: 1},
		{Command: cell.RelayData, StreamID: 99},
		{Command: cell.RelayConnected, StreamID: 1},
	} {
		c, n, _ := streamCircuit(t, nil)
		_ = dialStream(t, c)
		inject(t, n, msg)
		select {
		case <-c.Done():
			if !errors.Is(c.Err(), ErrProtocol) {
				t.Fatal(c.Err())
			}
		case <-time.After(time.Second):
			t.Fatal("accepted invalid cell", msg)
		}
	}
}
func TestForgedAuthenticatedSendme(t *testing.T) {
	c, _, _ := streamCircuit(t, func(p *streamPeer) { p.badACK = true })
	s := dialStream(t, c)
	s.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := s.Write(make([]byte, 101*498)); err == nil {
		select {
		case <-c.Done():
		case <-time.After(time.Second):
			t.Fatal("accepted forged SENDME")
		}
	}
	if !errors.Is(c.Err(), ErrProtocol) {
		t.Fatal(c.Err())
	}
}
func TestSlowReaderIsBounded(t *testing.T) {
	c, n, peer := streamCircuit(t, nil)
	s := dialStream(t, c)
	for i := 0; i < 500; i++ {
		n.mu.Lock()
		err := n.emit(2, cell.RelayMessage{Command: cell.RelayData, StreamID: 1, Data: make([]byte, 498)})
		peer.echoed++
		if peer.echoed%100 == 0 {
			peer.expected = append(peer.expected, bytes.Clone(n.layers[2].bd.Sum(nil)))
		}
		n.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	other := dialStream(t, c) // CONNECTED acts as a barrier after the injected DATA.
	m := c.streams
	m.mu.Lock()
	buffered, credit := s.(*streamConn).buffered, s.(*streamConn).deliverWindow
	m.mu.Unlock()
	n.mu.Lock()
	acks := peer.streamACKs
	n.mu.Unlock()
	if buffered != 500*498 || credit != 0 || acks != 0 {
		t.Fatal(buffered, credit, acks)
	}
	if _, err := other.Write([]byte("independent")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 11)
	if _, err := io.ReadFull(other, b); err != nil {
		t.Fatal(err)
	}
	// A 501st DATA cell on the unread stream exceeds its credit.
	inject(t, n, cell.RelayMessage{Command: cell.RelayData, StreamID: 1, Data: []byte{1}})
	select {
	case <-c.Done():
		if !errors.Is(c.Err(), ErrProtocol) {
			t.Fatal(c.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("accepted stream window overflow")
	}
}
func TestStreamAddressValidationAndAPIMode(t *testing.T) {
	c, _, _ := streamCircuit(t, nil)
	for _, address := range []string{"host:443", "host:0", "bad\x00host:80", "x.onion:80", "[::1]:80", ":80", strings.Repeat("a", 64) + ".test:80"} {
		if _, err := c.DialContext(context.Background(), "tcp", address); err == nil {
			t.Fatal("accepted", address)
		}
	}
	_ = dialStream(t, c)
	if _, err := c.Send(context.Background(), 2, cell.RelayMessage{Command: cell.RelayData, StreamID: 1}); !errors.Is(err, ErrAPIMode) {
		t.Fatal(err)
	}
	if _, err := c.Receive(context.Background()); !errors.Is(err, ErrAPIMode) {
		t.Fatal(err)
	}
	raw, _ := built(t)
	raw.port = 80
	if _, err := raw.Send(context.Background(), 2, cell.RelayMessage{Command: cell.RelayDrop}); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.DialContext(context.Background(), "tcp", "host:80"); !errors.Is(err, ErrAPIMode) {
		t.Fatal(err)
	}
}
func TestSendmeLedgerRejectsReplayAndWrongHop(t *testing.T) {
	for _, hop := range []int{0, 1, 2} {
		c, n, _ := streamCircuit(t, nil)
		s := dialStream(t, c)
		c.streams.mu.Lock()
		var tag relaycrypto.Tag
		tag[0] = 42
		c.streams.tags = append(c.streams.tags, tag)
		c.streams.packageWindow -= 100
		c.streams.mu.Unlock()
		n.mu.Lock()
		err := n.emit(hop, cell.RelayMessage{Command: cell.RelaySendme, Data: sendme(tag)})
		n.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if hop == 2 {
			inject(t, n, cell.RelayMessage{Command: cell.RelaySendme, Data: sendme(tag)})
		}
		select {
		case <-c.Done():
		case <-time.After(time.Second):
			t.Fatal("accepted wrong-hop/replayed SENDME")
		}
		_ = s
	}
}

func TestStreamLimitsIncludeUnreadEndedStreams(t *testing.T) {
	c, n, _ := streamCircuit(t, nil)
	var streams []net.Conn
	for i := 0; i < maxStreams; i++ {
		s := dialStream(t, c)
		streams = append(streams, s)
		id := s.(*streamConn).id
		inject(t, n, cell.RelayMessage{Command: cell.RelayData, StreamID: id, Data: []byte("tail")})
		inject(t, n, cell.RelayMessage{Command: cell.RelayEnd, StreamID: id, Data: []byte{6}})
	}
	if _, err := c.DialContext(context.Background(), "tcp", "host:80"); !errors.Is(err, ErrStreamLimit) {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(streams[0]); err != nil || string(b) != "tail" {
		t.Fatal(string(b), err)
	}
	_ = dialStream(t, c)
	streams[1].Close()
	c.streams.mu.Lock()
	c.streams.next = 65535
	c.streams.mu.Unlock()
	last := dialStream(t, c)
	if last.(*streamConn).id != 65535 {
		t.Fatal("wrong final ID")
	}
	last.Close()
	if _, err := c.DialContext(context.Background(), "tcp", "host:80"); !errors.Is(err, ErrStreamLimit) {
		t.Fatal("ID wraparound", err)
	}
}

func TestStreamWireTimeoutAndChannelFailure(t *testing.T) {
	for _, wire := range []bool{true, false} {
		c, n, _ := streamCircuit(t, nil)
		s := dialStream(t, c)
		read := make(chan error, 1)
		go func() { _, err := s.Read(make([]byte, 1)); read <- err }()
		if wire {
			n.mu.Lock()
			n.blockWrites = true
			n.mu.Unlock()
			s.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
			if _, err := s.Write([]byte("ambiguous")); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal(err)
			}
		} else {
			n.Close()
		}
		select {
		case err := <-read:
			if err == nil {
				t.Fatal("missing failure")
			}
		case <-time.After(time.Second):
			t.Fatal("blocked reader")
		}
		c.Close()
	}
}

func TestStreamNondefaultWindowAndPaddingEntropy(t *testing.T) {
	c, n, _ := streamCircuit(t, nil)
	c.window = 200
	s := dialStream(t, c)
	s.SetDeadline(time.Now().Add(3 * time.Second))
	data := make([]byte, 500*498)
	done := make(chan error, 1)
	go func() { _, err := s.Write(data); done <- err }()
	if _, err := io.CopyN(io.Discard, s, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if c.Err() != nil {
		t.Fatal(c.Err())
	}
	// Record plaintext lengths at the independent peer and verify each complete
	// 100-DATA batch contains room for at least 16 unpredictable padding bytes.
	n.mu.Lock()
	lengths := append([]int(nil), n.streamDataLengths...)
	n.mu.Unlock()
	for start := 0; start+100 <= len(lengths); start += 100 {
		padded := false
		for _, length := range lengths[start : start+100] {
			padded = padded || length <= cell.RelayDataSize-20
		}
		if !padded {
			t.Fatal("predictable SENDME batch", start)
		}
	}
}

func TestStreamBeginIPv6Flags(t *testing.T) {
	c := &Circuit{port: 443, ipv6: true}
	for _, address := range []string{"[2001:db8::1]:443", "EXAMPLE.TEST:443"} {
		b, err := c.begin("tcp6", address)
		if err != nil {
			t.Fatal(err)
		}
		if binary.BigEndian.Uint32(b[len(b)-4:]) != 3 || b[len(b)-5] != 0 {
			t.Fatal("wrong BEGIN flags", b)
		}
	}
	for _, address := range []string{"127.0.0.1:443", "[fe80::1%en0]:443", "[::ffff:127.0.0.1]:443"} {
		if _, err := c.begin("tcp6", address); err == nil {
			t.Fatal("accepted", address)
		}
	}
}

func FuzzStreamControl(f *testing.F) {
	f.Add(byte(cell.RelaySendme), byte(0), []byte{1, 0, 20})
	f.Add(byte(cell.RelayConnected), byte(1), []byte{})
	f.Add(byte(cell.RelayData), byte(1), []byte("data"))
	f.Add(byte(cell.RelayEnd), byte(1), []byte{6})
	f.Fuzz(func(t *testing.T, command, id byte, data []byte) {
		if len(data) > cell.RelayDataSize {
			return
		}
		c := newCircuit(nil)
		defer c.cancel()
		m := newStreamMux(c)
		s := &streamConn{mux: m, id: 1, begun: true, connected: true, packageWindow: 400, deliverWindow: 500, unacked: 100}
		m.streams[1] = s
		m.held = 1
		var tag relaycrypto.Tag
		m.tags = []relaycrypto.Tag{tag}
		m.packageWindow = 900
		msg := Message{Hop: 2, RelayMessage: cell.RelayMessage{Command: cell.RelayCommand(command), StreamID: uint16(id), Data: data}}
		if m.handle(msg) == nil {
			_ = m.handle(msg)
		}
	})
}
