package circuit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"veil/cell"
	"veil/directory"
	"veil/relaycrypto"
)

var (
	ErrClosed   = errors.New("Tor circuit closed")
	ErrProtocol = errors.New("Tor circuit protocol violation")
)

// RemoteError preserves a peer's teardown reason for diagnostics only. It is
// never reflected onto the wire. Hop is -1 for a channel-level DESTROY.
type RemoteError struct {
	Hop    int
	Reason byte
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("Tor circuit destroyed (hop %d, reason %d)", e.Hop, e.Reason)
}

// Message identifies the authenticating hop and retains the full digest for
// future authenticated SENDME processing. Hop indices are guard=0, middle=1,
// exit=2. Tags and relay contents must not be logged as routine diagnostics.
type Message struct {
	cell.RelayMessage
	Hop int
	Tag relaycrypto.Tag
}

// Circuit owns one authenticated channel exclusively. It is safe for concurrent
// use; outgoing encryption/write order and incoming decryption order are
// serialized. Never read from its underlying channel or copy a Circuit.
type Circuit struct {
	ch       transport
	id       uint32
	path     directory.Path
	crypto   *relaycrypto.Client
	early    int
	sendGate chan struct{}
	incoming chan Message
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	once     sync.Once
	wg       sync.WaitGroup
	mu       sync.Mutex
	err      error
	mode     byte // 1: raw relay API; 2: managed streams
	streams  *streamMux
	port     uint16
	ipv6     bool
	window   int
	endHop   atomic.Int32
	hs       *onionCircuit // Access under mu; purpose and endpoint are immutable after construction.
}

func newCircuit(ch transport) *Circuit {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Circuit{ch: ch, early: 8, window: 1000, sendGate: make(chan struct{}, 1), incoming: make(chan Message, 32), ctx: ctx, cancel: cancel, done: make(chan struct{})}
	c.endHop.Store(2)
	return c
}

func (c *Circuit) Path() directory.Path  { return c.path }
func (c *Circuit) Done() <-chan struct{} { return c.done }
func (c *Circuit) Err() error            { c.mu.Lock(); defer c.mu.Unlock(); return c.err }

func (c *Circuit) start(lifetime context.Context) {
	c.wg.Add(2)
	go func() {
		defer c.wg.Done()
		for {
			m, err := c.receiveRelay(c.ctx)
			if err == nil && (m.Command == cell.RelayRendezvous2 || m.Command == cell.RelayRendezvousEstablished || m.Command == cell.RelayIntroduceAck) {
				err = c.acceptOnionControl(m)
			}
			if err == nil && m.Command == cell.RelayExtended2 {
				err = fmt.Errorf("%w: unsolicited EXTENDED2", ErrProtocol)
			}
			if err != nil {
				c.shutdown(err)
				return
			}
			select {
			case c.incoming <- m:
			case <-c.done:
				return
			}
		}
	}()
	go func() {
		defer c.wg.Done()
		select {
		case <-lifetime.Done():
			c.shutdown(lifetime.Err())
		case <-c.ch.Done():
			c.shutdown(c.ch.Err())
		case <-c.done:
		}
	}()
}

// Send writes a low-level relay message. Stream messages can target only the
// exit; callers are responsible for stream state and SENDME flow control.
// Circuit extension/truncation is not exposed. This is not a stream API.
// Cancellation while waiting for the send gate leaves the circuit usable;
// failure after encryption closes it because cipher state cannot be rolled back.
func (c *Circuit) Send(ctx context.Context, hop int, m cell.RelayMessage) (tag relaycrypto.Tag, err error) {
	if err = c.claimRaw(); err != nil {
		return tag, err
	}
	return c.send(ctx, hop, m, nil, nil)
}

func (c *Circuit) claimRaw() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mode == 2 {
		return ErrAPIMode
	}
	c.mode = 1
	return nil
}

// prepare runs under the send gate before encryption. tagged records SENDME
// expectations before the peer can possibly acknowledge this cell.
func (c *Circuit) send(ctx context.Context, hop int, m cell.RelayMessage, prepare func(*cell.RelayMessage) error, tagged func(relaycrypto.Tag)) (tag relaycrypto.Tag, err error) {
	if err := ctx.Err(); err != nil {
		return tag, err
	}
	if hop < 0 || hop > int(c.endHop.Load()) || len(m.Data) > cell.RelayDataSize {
		return tag, fmt.Errorf("%w: invalid target or payload size", ErrProtocol)
	}
	switch m.Command {
	case cell.RelayDrop:
		if m.StreamID != 0 {
			return tag, fmt.Errorf("%w: DROP requires stream zero", ErrProtocol)
		}
	case cell.RelaySendme:
		if m.StreamID != 0 && hop != int(c.endHop.Load()) {
			return tag, fmt.Errorf("%w: stream message must target exit", ErrProtocol)
		}
	case cell.RelayBegin, cell.RelayBeginDir, cell.RelayData, cell.RelayEnd, cell.RelayResolve:
		if hop != int(c.endHop.Load()) || m.StreamID == 0 {
			return tag, fmt.Errorf("%w: stream message must target exit with nonzero ID", ErrProtocol)
		}
	case cell.RelayEstablishRendezvous, cell.RelayIntroduce1:
		if err := c.checkOnionSend(hop, m); err != nil {
			return tag, err
		}
	default:
		return tag, fmt.Errorf("%w: unsupported outgoing relay command", ErrProtocol)
	}
	select {
	case <-ctx.Done():
		return tag, ctx.Err()
	case <-c.done:
		return tag, c.Err()
	case c.sendGate <- struct{}{}:
	}
	started := false
	defer func() {
		<-c.sendGate
		if err != nil && started {
			c.shutdown(err)
		}
	}()
	if err = c.Err(); err != nil {
		return tag, err
	}
	// Recheck before consuming crypto state; queued cancellation is harmless.
	if e := ctx.Err(); e != nil {
		return tag, e
	}
	if prepare != nil {
		if err = prepare(&m); err != nil {
			return tag, err
		}
	}
	started = true
	return c.sendRelayTagged(ctx, hop, m, tagged)
}

func (c *Circuit) sendRelay(ctx context.Context, hop int, m cell.RelayMessage) (relaycrypto.Tag, error) {
	return c.sendRelayTagged(ctx, hop, m, nil)
}

func (c *Circuit) sendRelayTagged(ctx context.Context, hop int, m cell.RelayMessage, tagged func(relaycrypto.Tag)) (relaycrypto.Tag, error) {
	body, err := cell.EncodeRelay(m)
	if err != nil {
		return relaycrypto.Tag{}, err
	}
	command := cell.Relay
	if m.Command == cell.RelayExtend2 || (hop > 0 && c.early > 0) {
		if c.early == 0 {
			return relaycrypto.Tag{}, fmt.Errorf("%w: RELAY_EARLY budget exhausted", ErrProtocol)
		}
		c.early--
		command = cell.RelayEarly
	}
	body, tag, err := c.crypto.Encrypt(hop, body)
	if err != nil {
		return relaycrypto.Tag{}, err
	}
	if tagged != nil {
		tagged(tag)
	}
	if err := c.ch.Send(ctx, cell.Cell{CircuitID: c.id, Command: command, Payload: body[:]}); err != nil {
		return relaycrypto.Tag{}, err
	}
	return tag, nil
}

// Receive returns authenticated relay messages from a bounded queue. Canceling
// only this call leaves the circuit usable. Circuit failure takes precedence
// over buffered messages; Close or lifetime cancellation unblocks all readers.
func (c *Circuit) Receive(ctx context.Context) (Message, error) {
	if err := c.claimRaw(); err != nil {
		return Message{}, err
	}
	return c.receive(ctx)
}

func (c *Circuit) receive(ctx context.Context) (Message, error) {
	if err := ctx.Err(); err != nil {
		return Message{}, err
	}
	select {
	case <-ctx.Done():
		return Message{}, ctx.Err()
	case <-c.done:
		return Message{}, c.Err()
	case m := <-c.incoming:
		if err := c.Err(); err != nil {
			return Message{}, err
		}
		return m, nil
	}
}

func (c *Circuit) receiveFrame(ctx context.Context) (cell.Cell, error) {
	for i := 0; i < 128; i++ {
		f, err := c.ch.Receive(ctx)
		if err != nil {
			return cell.Cell{}, err
		}
		if f.Command == cell.PaddingNegotiate && f.CircuitID == 0 {
			continue
		}
		if f.CircuitID != c.id {
			return cell.Cell{}, fmt.Errorf("%w: unexpected circuit ID", ErrProtocol)
		}
		if f.Command == cell.Destroy {
			if len(f.Payload) < 1 {
				return cell.Cell{}, fmt.Errorf("%w: empty DESTROY", ErrProtocol)
			}
			return cell.Cell{}, &RemoteError{Hop: -1, Reason: f.Payload[0]}
		}
		return f, nil
	}
	return cell.Cell{}, fmt.Errorf("%w: excess channel control cells", ErrProtocol)
}

func (c *Circuit) receiveRelay(ctx context.Context) (Message, error) {
	for i := 0; i < 128; i++ {
		f, err := c.receiveFrame(ctx)
		if err != nil {
			return Message{}, err
		}
		if f.Command != cell.Relay || len(f.Payload) != cell.PayloadSize {
			return Message{}, fmt.Errorf("%w: expected RELAY", ErrProtocol)
		}
		var body cell.RelayBody
		copy(body[:], f.Payload)
		body, hop, tag, err := c.crypto.Decrypt(body)
		if err != nil {
			return Message{}, err
		}
		m, err := cell.DecodeRelay(body)
		if err != nil {
			return Message{}, err
		}
		switch m.Command {
		case cell.RelayDrop, cell.RelayExtended2, cell.RelayTruncated:
			if m.StreamID != 0 {
				return Message{}, fmt.Errorf("%w: control message on a stream", ErrProtocol)
			}
			if m.Command == cell.RelayTruncated {
				if len(m.Data) != 1 {
					return Message{}, fmt.Errorf("%w: malformed TRUNCATED", ErrProtocol)
				}
				return Message{}, &RemoteError{Hop: hop, Reason: m.Data[0]}
			}
			if m.Command == cell.RelayDrop {
				continue
			}
		case cell.RelayConnected, cell.RelayData, cell.RelayEnd, cell.RelayResolved:
			if hop != int(c.endHop.Load()) || m.StreamID == 0 {
				return Message{}, fmt.Errorf("%w: stream reply from wrong hop or stream zero", ErrProtocol)
			}
		case cell.RelaySendme:
			if m.StreamID != 0 && hop != int(c.endHop.Load()) {
				return Message{}, fmt.Errorf("%w: stream SENDME from wrong hop", ErrProtocol)
			}
		case cell.RelayBegin, cell.RelayBeginDir, cell.RelayExtend, cell.RelayExtended, cell.RelayExtend2, cell.RelayTruncate, cell.RelayResolve:
			return Message{}, fmt.Errorf("%w: unexpected inbound relay command", ErrProtocol)
		case cell.RelayRendezvous2, cell.RelayRendezvousEstablished, cell.RelayIntroduceAck:
			if hop != 2 || m.StreamID != 0 {
				return Message{}, ErrProtocol
			}
		default:
			// Unknown commands are ignored after authentication, with a bound on
			// consecutive ignored cells to prevent endless build-time floods.
			continue
		}
		return Message{RelayMessage: m, Hop: hop, Tag: tag}, nil
	}
	return Message{}, fmt.Errorf("%w: excess ignored relay cells", ErrProtocol)
}

// Close is idempotent, destroys the circuit, closes its dedicated channel, and
// joins the receive/lifetime loops. Teardown never waits indefinitely to write.
func (c *Circuit) Close() error {
	c.shutdown(ErrClosed)
	c.wg.Wait()
	c.mu.Lock()
	m := c.streams
	c.mu.Unlock()
	if m != nil {
		<-m.done
	}
	return nil
}

func (c *Circuit) shutdown(err error) {
	c.once.Do(func() {
		if err == nil {
			err = ErrClosed
		}
		c.mu.Lock()
		c.err = err
		c.mu.Unlock()
		close(c.done)
		c.cancel()
		var remote *RemoteError
		reflectDestroy := errors.As(err, &remote) && remote.Hop == -1
		// Never interleave DESTROY with an in-flight encrypted write. Closing
		// the dedicated channel tears down the circuit when writing is blocked.
		select {
		case c.sendGate <- struct{}{}:
			if c.id != 0 && !reflectDestroy {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				_ = c.ch.Send(ctx, cell.Cell{CircuitID: c.id, Command: cell.Destroy, Payload: []byte{0}})
				cancel()
			}
			<-c.sendGate
		default:
		}
		_ = c.ch.Close()
		if c.crypto != nil {
			c.crypto.Close()
		}
	})
}
