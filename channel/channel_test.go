package channel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"veil/cell"
)

func runtimePair(t *testing.T, queue int) (*Channel, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	codec, _ := cell.NewCodec(5)
	ch := newChannel(context.Background(), a, a, codec, Info{LinkVersion: 5}, queue)
	t.Cleanup(func() { ch.Close(); b.Close() })
	return ch, b
}

func waitClosed(t *testing.T, ch *Channel) {
	t.Helper()
	select {
	case <-ch.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("channel did not close")
	}
	ch.Close() // Also verifies that every loop can terminate.
}

func TestConcurrentSendAndIDAllocation(t *testing.T) {
	ch, peer := runtimePair(t, 2)
	codec, _ := cell.NewCodec(5)
	const n = 50
	seen := make(chan uint32, n)
	readErr := make(chan error, 1)
	go func() {
		for i := 0; i < n; i++ {
			frame, err := codec.Read(peer)
			if err != nil {
				readErr <- err
				return
			}
			seen <- frame.CircuitID
		}
		readErr <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	sendErr := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := ch.AllocateCircuitID()
			if err == nil {
				err = ch.Send(ctx, cell.Cell{CircuitID: id, Command: cell.Destroy, Payload: []byte{0}})
			}
			sendErr <- err
		}()
	}
	wg.Wait()
	close(sendErr)
	for err := range sendErr {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := <-readErr; err != nil {
		t.Fatal(err)
	}
	close(seen)
	ids := map[uint32]bool{}
	for id := range seen {
		if ids[id] || id&0x80000000 == 0 {
			t.Fatal("bad circuit ID", id)
		}
		ids[id] = true
	}
	if len(ids) != n {
		t.Fatal("missing cells")
	}
	ch.Close()
	if _, err := ch.AllocateCircuitID(); err != ErrClosed {
		t.Fatal(err)
	}
}

func TestCircuitIDBoundariesAndCollisions(t *testing.T) {
	ch, _ := runtimePair(t, 1)
	if id, err := ch.allocateCircuitID(bytes.NewReader([]byte{0, 0, 0, 0})); err != nil || id != 0x80000000 {
		t.Fatal(id, err)
	}
	if id, err := ch.allocateCircuitID(bytes.NewReader([]byte{255, 255, 255, 255})); err != nil || id != 0xffffffff {
		t.Fatal(id, err)
	}
	if _, err := ch.allocateCircuitID(bytes.NewReader(make([]byte, 4*64))); err != ErrCircuitIDsExhausted {
		t.Fatal(err)
	}
	if _, err := ch.allocateCircuitID(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	ch.mu.Lock()
	for i := uint32(0); i < 65536; i++ {
		ch.usedIDs[0x80000000|i] = struct{}{}
	}
	ch.mu.Unlock()
	if _, err := ch.AllocateCircuitID(); err != ErrCircuitIDsExhausted {
		t.Fatal(err)
	}
}

func TestCancellationSemantics(t *testing.T) {
	ch, _ := runtimePair(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ch.Send(ctx, cell.Cell{Command: cell.Padding}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := ch.Receive(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if ch.Err() != nil {
		t.Fatal("pre-canceled operation closed channel")
	}
	// No peer reader: an accepted send blocks in the writer until canceled.
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := ch.Send(ctx, cell.Cell{Command: cell.Padding}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	waitClosed(t, ch)
	if !errors.Is(ch.Err(), context.DeadlineExceeded) {
		t.Fatal(ch.Err())
	}
}

func TestReceiveBackpressureAndClose(t *testing.T) {
	ch, peer := runtimePair(t, 1)
	codec, _ := cell.NewCodec(5)
	second := make(chan struct{})
	third := make(chan error, 1)
	go func() {
		for i := 0; i < 2; i++ {
			if err := codec.Write(peer, cell.Cell{CircuitID: 0x80000001, Command: cell.Destroy}); err != nil {
				third <- err
				return
			}
		}
		close(second)
		third <- codec.Write(peer, cell.Cell{CircuitID: 0x80000001, Command: cell.Destroy})
	}()
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("reader did not consume initial cells")
	}
	// One cell queued and one in the reader: the third cannot be read yet.
	select {
	case err := <-third:
		t.Fatal("receive queue failed to apply backpressure", err)
	case <-time.After(20 * time.Millisecond):
	}
	ch.Close()
	select {
	case err := <-third:
		if err == nil {
			t.Fatal("write unexpectedly completed")
		}
	case <-time.After(time.Second):
		t.Fatal("peer writer remained blocked")
	}
	if _, err := ch.Receive(context.Background()); err != ErrClosed {
		t.Fatal(err)
	}
}

func TestReceiveCancellationDoesNotClose(t *testing.T) {
	ch, peer := runtimePair(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := ch.Receive(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	codec, _ := cell.NewCodec(5)
	result := make(chan error, 1)
	go func() { result <- codec.Write(peer, cell.Cell{CircuitID: 0x80000001, Command: cell.Destroy}) }()
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if _, err := ch.Receive(ctx2); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestRejectOpenChannelMessages(t *testing.T) {
	for _, frame := range []cell.Cell{
		{Command: cell.Certs}, {Command: cell.AuthChallenge}, {Command: cell.NetInfo},
		{Command: cell.Create2, CircuitID: 0x80000001}, {Command: cell.Relay, CircuitID: 1},
		{Command: 222},
	} {
		ch, peer := runtimePair(t, 1)
		codec, _ := cell.NewCodec(5)
		if err := codec.Write(peer, frame); err != nil {
			t.Fatal(err)
		}
		waitClosed(t, ch)
		if !errors.Is(ch.Err(), ErrProtocol) {
			t.Fatal(ch.Err())
		}
	}
	ch, peer := runtimePair(t, 1)
	ch.info.LinkVersion = 4
	codec, _ := cell.NewCodec(4)
	if err := codec.Write(peer, cell.Cell{Command: cell.PaddingNegotiate}); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, ch)
	if !errors.Is(ch.Err(), ErrProtocol) {
		t.Fatal(ch.Err())
	}
}

func TestOutgoingValidationDoesNotClose(t *testing.T) {
	ch, _ := runtimePair(t, 1)
	id, _ := ch.AllocateCircuitID()
	for _, frame := range []cell.Cell{
		{Command: cell.Certs}, {Command: cell.Relay, CircuitID: id, Payload: []byte{1}},
		{Command: cell.Destroy, CircuitID: id + 1}, {Command: cell.Destroy, CircuitID: 1},
		{Command: cell.Padding, CircuitID: id}, {Command: cell.VPadding, Payload: make([]byte, 65536)},
	} {
		if err := ch.Send(context.Background(), frame); err == nil {
			t.Fatal("invalid outgoing cell accepted")
		}
	}
	if ch.Err() != nil {
		t.Fatal("invalid outbound input closed channel")
	}
}

type brokenConn struct{ net.Conn }

func (c brokenConn) Write(b []byte) (int, error) { return len(b) / 2, io.ErrUnexpectedEOF }

func TestWriteFailureClosesChannel(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	codec, _ := cell.NewCodec(4)
	ch := newChannel(context.Background(), a, brokenConn{a}, codec, Info{LinkVersion: 4}, 1)
	defer ch.Close()
	if err := ch.Send(context.Background(), cell.Cell{Command: cell.Padding}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	waitClosed(t, ch)
}

func TestTruncatedReadClosesChannel(t *testing.T) {
	ch, peer := runtimePair(t, 1)
	go func() { peer.Write([]byte{0x80, 0, 0, 1, byte(cell.Relay), 1, 2}); peer.Close() }()
	waitClosed(t, ch)
	if !errors.Is(ch.Err(), io.ErrUnexpectedEOF) {
		t.Fatal(ch.Err())
	}
}

type limitedWriter struct {
	b    []byte
	size int
}

func (w *limitedWriter) Write(b []byte) (int, error) {
	n := min(len(b), w.size)
	w.b = append(w.b, b[:n]...)
	return n, nil
}
func TestWriteFull(t *testing.T) {
	w := &limitedWriter{size: 2}
	if err := writeFull(w, []byte{1, 2, 3, 4, 5}); err != nil || len(w.b) != 5 {
		t.Fatal(err)
	}
	if err := writeFull(&limitedWriter{}, []byte{1}); err != io.ErrShortWrite {
		t.Fatal(err)
	}
}

func TestDirectoryFastChannelFrames(t *testing.T) {
	ch, peer := runtimePair(t, 1)
	id, err := ch.AllocateCircuitID()
	if err != nil {
		t.Fatal(err)
	}
	codec, _ := cell.NewCodec(5)
	done := make(chan error, 1)
	go func() {
		f, err := codec.Read(peer)
		if err == nil && (f.Command != cell.CreateFast || f.CircuitID != id) {
			err = errors.New("wrong CREATE_FAST")
		}
		if err == nil {
			err = codec.Write(peer, cell.Cell{Command: cell.CreatedFast, CircuitID: id, Payload: make([]byte, 40)})
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := ch.Send(ctx, cell.Cell{Command: cell.CreateFast, CircuitID: id, Payload: make([]byte, 20)}); err != nil {
		t.Fatal(err)
	}
	f, err := ch.Receive(ctx)
	if err != nil || f.Command != cell.CreatedFast {
		t.Fatal(f.Command, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
