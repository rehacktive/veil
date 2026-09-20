package channel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"veil/cell"
)

var (
	ErrClosed              = errors.New("Tor channel closed")
	ErrCircuitIDsExhausted = errors.New("Tor channel circuit IDs exhausted")
)

type writeRequest struct {
	data   []byte
	result chan error
}

// Channel is an authenticated, bounded cell transport. It is safe for concurrent
// use, but callers must serialize cells that require circuit-specific ordering.
// Circuit message routing and circuit state validation belong to the next layer.
// Only Dial constructs a usable Channel; do not copy it.
type Channel struct {
	raw     net.Conn
	conn    io.ReadWriter
	codec   *cell.Codec
	info    Info
	send    chan writeRequest
	receive chan cell.Cell
	done    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
	mu      sync.Mutex
	err     error
	usedIDs map[uint32]struct{}
}

func newChannel(ctx context.Context, raw net.Conn, conn io.ReadWriter, codec *cell.Codec, info Info, queue int) *Channel {
	c := &Channel{raw: raw, conn: conn, codec: codec, info: info,
		send: make(chan writeRequest, queue), receive: make(chan cell.Cell, queue),
		done: make(chan struct{}), usedIDs: make(map[uint32]struct{})}
	c.wg.Add(3)
	go c.readLoop()
	go c.writeLoop()
	go func() {
		defer c.wg.Done()
		select {
		case <-ctx.Done():
			c.shutdown(ctx.Err())
		case <-c.done:
		}
	}()
	return c
}

// Info returns a snapshot; modifying its address slice does not affect Channel.
func (c *Channel) Info() Info {
	info := c.info
	info.PeerNetInfo.MyAddresses = append(info.PeerNetInfo.MyAddresses[:0:0], info.PeerNetInfo.MyAddresses...)
	return info
}

// Done closes when channel teardown starts. Close also waits for all loops.
func (c *Channel) Done() <-chan struct{} { return c.done }

// Err returns nil while open, otherwise the first teardown reason.
func (c *Channel) Err() error { c.mu.Lock(); defer c.mu.Unlock(); return c.err }

// AllocateCircuitID randomly reserves an initiator-owned ID (high bit set).
// IDs are never reused on this channel, avoiding stale replies. After 65536
// allocations or 64 random collisions callers must open a new channel; the
// lifetime allocation cap bounds memory retained for non-reuse tracking.
func (c *Channel) AllocateCircuitID() (uint32, error) {
	return c.allocateCircuitID(rand.Reader)
}

func (c *Channel) allocateCircuitID(random io.Reader) (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return 0, c.err
	}
	if len(c.usedIDs) >= 65536 {
		return 0, ErrCircuitIDsExhausted
	}
	for attempt := 0; attempt < 64; attempt++ {
		var b [4]byte
		if _, err := io.ReadFull(random, b[:]); err != nil {
			return 0, fmt.Errorf("circuit ID randomness: %w", err)
		}
		id := binary.BigEndian.Uint32(b[:]) | 0x80000000
		if _, exists := c.usedIDs[id]; !exists {
			c.usedIDs[id] = struct{}{}
			return id, nil
		}
	}
	return 0, ErrCircuitIDsExhausted
}

// Send copies and queues a cell and waits until its bytes have been written.
// Cancellation before queueing leaves the channel open. Cancellation after
// queueing closes the channel because delivery can no longer be determined;
// callers must not retry on the same channel. Successful writing is not a relay
// acknowledgement. TLS/circuit state must be handled by the higher layers.
func (c *Channel) Send(ctx context.Context, frame cell.Cell) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	err := c.err
	_, allocated := c.usedIDs[frame.CircuitID]
	c.mu.Unlock()
	if err != nil {
		return err
	}
	switch frame.Command {
	case cell.Create2, cell.CreateFast, cell.Relay, cell.RelayEarly, cell.Destroy:
		if !allocated {
			return fmt.Errorf("%w: circuit ID was not allocated on this channel", ErrProtocol)
		}
	case cell.Padding, cell.VPadding:
	default:
		return fmt.Errorf("%w: client cannot send %s on an open channel", ErrProtocol, frame.Command)
	}
	if (frame.Command == cell.Relay || frame.Command == cell.RelayEarly) && len(frame.Payload) != cell.PayloadSize {
		return fmt.Errorf("%w: encrypted relay body must be exactly 509 bytes", ErrProtocol)
	}
	var wire bytes.Buffer
	if err := c.codec.Write(&wire, frame); err != nil {
		return err
	}
	req := writeRequest{data: wire.Bytes(), result: make(chan error, 1)}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return c.Err()
	case c.send <- req:
	}
	select {
	case err := <-req.result:
		return err
	case <-ctx.Done():
		c.shutdown(ctx.Err())
		return ctx.Err()
	case <-c.done:
		return c.Err()
	}
}

// Receive returns the next non-padding cell. A canceled receive leaves the
// channel open. An unread full queue applies backpressure to the TLS reader.
func (c *Channel) Receive(ctx context.Context) (cell.Cell, error) {
	if err := ctx.Err(); err != nil {
		return cell.Cell{}, err
	}
	select {
	case <-ctx.Done():
		return cell.Cell{}, ctx.Err()
	case <-c.done:
		return cell.Cell{}, c.Err()
	case frame := <-c.receive:
		if err := c.Err(); err != nil {
			return cell.Cell{}, err
		}
		return frame, nil
	}
}

// Close is idempotent and waits for blocked reads/writes and all loops to exit.
func (c *Channel) Close() error { c.shutdown(ErrClosed); c.wg.Wait(); return nil }

func (c *Channel) shutdown(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		c.usedIDs = nil
		c.mu.Unlock()
		close(c.done)
		// Close TCP directly: a TLS close_notify write could block on an
		// unresponsive peer while teardown must unblock both directions.
		_ = c.raw.Close() // Best-effort teardown; preserve the original failure.
	})
}

func (c *Channel) readLoop() {
	defer c.wg.Done()
	for {
		frame, err := c.codec.Read(c.conn)
		if err != nil {
			c.shutdown(err)
			return
		}
		switch frame.Command {
		case cell.Padding, cell.VPadding, cell.Versions:
			continue
		case cell.Created2, cell.CreatedFast, cell.Relay, cell.Destroy:
			if frame.CircuitID&0x80000000 == 0 {
				c.shutdown(fmt.Errorf("%w: peer used a responder circuit ID", ErrProtocol))
				return
			}
		case cell.PaddingNegotiate:
			if c.info.LinkVersion < 5 {
				c.shutdown(fmt.Errorf("%w: padding negotiation requires link 5", ErrProtocol))
				return
			}
		default:
			c.shutdown(fmt.Errorf("%w: unexpected %s after handshake", ErrProtocol, frame.Command))
			return
		}
		select {
		case c.receive <- frame:
		case <-c.done:
			return
		}
	}
}

func (c *Channel) writeLoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.done:
			return
		case req := <-c.send:
			err := writeFull(c.conn, req.data)
			req.result <- err
			if err != nil {
				c.shutdown(err)
				return
			}
		}
	}
}

func writeFull(w io.Writer, b []byte) error {
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
