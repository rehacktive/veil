package circuit

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"veil/cell"
)

type paddingPolicy interface {
	Enabled() bool
	NonPadding()
	TryPadding() bool
}

// PaddingStats is a local, cumulative view of this circuit's setup padding.
// It contains no relay identities, destinations, payloads or timestamps.
type PaddingStats struct {
	Started, Negotiated, Stopped, Rejected bool
	Sent, Received                         uint8
}

type circuitPadding struct {
	PaddingStats
	machine byte // C Tor registration order: introduction=0, rendezvous=1.
}

func (c *Circuit) PaddingStats() PaddingStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.padding.PaddingStats
}

// startPadding runs once at INTRODUCE1 sent / RENDEZVOUS_ESTABLISHED received.
// It negotiates only with the second physical relay, whose authenticated
// consensus entry must advertise Padding=2. No alternative path is sampled.
func (c *Circuit) startPadding(ctx context.Context) error {
	select {
	case c.sendGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return c.Err()
	}
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		<-c.sendGate
		return err
	}
	if c.hs == nil || !c.paddingSupported || c.paddingBudget == nil || !c.paddingBudget.Enabled() {
		c.mu.Unlock()
		<-c.sendGate
		return nil
	}
	if c.padding.Started || (c.hs.purpose != OnionIntroduction && c.hs.purpose != OnionRendezvous) {
		c.mu.Unlock()
		<-c.sendGate
		return ErrProtocol
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		<-c.sendGate
		return err
	}
	machine := byte(0)
	if c.hs.purpose == OnionRendezvous {
		machine = 1
	}
	// Install before writing: a relay may reply before Send returns.
	c.padding = circuitPadding{PaddingStats: PaddingStats{Started: true}, machine: machine}
	c.mu.Unlock()
	_, err := c.sendRelay(ctx, 1, cell.RelayMessage{Command: cell.RelayPaddingNegotiate, Data: []byte{0, 2, machine, 0, 0, 0, 0, 1}})
	<-c.sendGate
	if err != nil {
		c.shutdown(err)
		return err
	}
	if machine == 0 {
		return nil
	} // The introduction client never sends DROP.

	// The rendezvous client sends at most one DROP, after 0..999 microseconds.
	// Sending before the acknowledgment is explicitly allowed by the protocol.
	n, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		c.shutdown(err)
		return err
	}
	timer := time.NewTimer(time.Duration(n.Int64()) * time.Microsecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return c.Err()
	}
	return c.sendPaddingDrop(ctx)
}

func (c *Circuit) sendPaddingDrop(ctx context.Context) error {
	// There is no circuit output queue: each writer owns this gate through the
	// channel flush. Skip cover traffic when busy instead of delaying real data.
	select {
	case c.sendGate <- struct{}{}:
	default:
		return nil
	}
	c.mu.Lock()
	p := &c.padding
	if c.err != nil || ctx.Err() != nil || !p.Started || p.machine != 1 || p.Sent != 0 || p.Received != 0 || p.Stopped || p.Rejected || c.paddingBudget == nil || !c.paddingBudget.TryPadding() {
		c.mu.Unlock()
		<-c.sendGate
		return nil
	}
	p.Sent++
	c.mu.Unlock()
	_, err := c.sendRelay(ctx, 1, cell.RelayMessage{Command: cell.RelayDrop})
	<-c.sendGate
	if err != nil {
		c.shutdown(err)
	}
	return err
}

// acceptPadding runs in the sole reader, after hop authentication. DROP bodies
// are opaque; only the negotiated hop, stream, state and count authorize them.
func (c *Circuit) acceptPadding(hop int, m cell.RelayMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := &c.padding
	bad := func() error { return fmt.Errorf("%w: invalid circuit padding", ErrProtocol) }
	if hop != 1 || m.StreamID != 0 || !p.Started {
		return bad()
	}
	if m.Command == cell.RelayDrop {
		limit := uint8(10)
		if p.machine == 1 {
			limit = 1
		}
		if p.Stopped || p.Rejected || p.Received >= limit {
			return bad()
		}
		p.Received++
		return nil
	}
	b := m.Data
	if m.Command != cell.RelayPaddingNegotiated || len(b) != 8 || b[0] != 0 {
		return bad()
	}
	// Replies for obsolete negotiations are ignored, with the reader's existing
	// bound on consecutive ignored cells. This client uses one counter per circuit.
	if binary.BigEndian.Uint32(b[4:]) != 1 {
		return nil
	}
	if b[3] != p.machine || (b[2] != 1 && b[2] != 2) {
		return bad()
	}
	switch b[1] {
	case 2: // START acknowledgment; ERR can reflect consensus/version drift.
		if p.Negotiated || p.Rejected || p.Stopped {
			return bad()
		}
		if b[2] == 2 {
			p.Rejected = true
		} else {
			p.Negotiated = true
		}
	case 1: // C Tor normally sends this only for introduction; either may stop.
		if !p.Negotiated || p.Stopped || p.Rejected || b[2] != 1 {
			return bad()
		}
		p.Stopped = true
	default:
		return bad()
	}
	return nil
}
