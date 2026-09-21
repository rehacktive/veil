package circuit

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"veil/cell"
	"veil/channel"
	"veil/directory"
)

type OnionPurpose byte

const (
	OnionDirectory OnionPurpose = iota + 1
	OnionIntroduction
	OnionRendezvous
	OnionServiceIntroduction
	OnionServiceRendezvous
)

type onionCircuit struct {
	purpose OnionPurpose
	stage   byte
	host    string
	finish  func([]byte) ([128]byte, error)
}

// BuildInternal uses the verified selector and persistent guard accounting for
// an onion protocol circuit, without treating its final relay as an exit.
func BuildInternal(ctx context.Context, s *directory.Snapshot, guards *directory.GuardStore, target *directory.Relay, purpose OnionPurpose, timeout time.Duration, pools ...*channel.Pool) (*Circuit, error) {
	if guards == nil || purpose < OnionDirectory || purpose > OnionServiceRendezvous || timeout < 0 || (target == nil && purpose != OnionRendezvous && purpose != OnionServiceIntroduction) {
		return nil, ErrProtocol
	}
	if !s.Valid(time.Now()) {
		return nil, directory.ErrTime
	}
	window, err := s.CircuitWindow()
	if err != nil {
		return nil, err
	}
	a, err := guards.Select(s, false, nil, time.Now())
	if err != nil {
		return nil, err
	}
	p, err := guards.SelectVanguardPath(s, a.Relay(), target, purpose == OnionRendezvous, time.Now())
	if err != nil {
		a.Close()
		return nil, err
	}
	hops := make([]hop, len(p.Relays()))
	for i, r := range p.Relays() {
		hops[i] = hop{r.Target(), r.NTor()}
	}
	padding, err := s.LinkPadding()
	if err != nil {
		a.Close()
		return nil, err
	}
	c, err := buildHops(ctx, hops, a, timeout, func(ctx context.Context, t channel.Target, o channel.Options) (transport, error) {
		o.Padding = &padding
		o.PaddingPolicy = guards.LinkPaddingPolicy()
		if len(pools) > 0 && pools[0] != nil {
			return pools[0].Acquire(ctx, t, o)
		}
		return channel.Dial(ctx, t, o)
	}, func() bool { return s.Valid(time.Now()) }, true, guards.PaddingBudget())
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.path = p
	c.window = window
	c.hs = &onionCircuit{purpose: purpose}
	c.paddingSupported = p.Middle.SupportsCircuitPadding()
	c.mu.Unlock()
	return c, nil
}

func (c *Circuit) checkOnionSend(hop int, m cell.RelayMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hs == nil || hop != c.relayEnd || m.StreamID != 0 || c.hs.stage != 1 {
		return ErrProtocol
	}
	if m.Command == cell.RelayEstablishIntro && c.hs.purpose == OnionServiceIntroduction && len(m.Data) >= 134 {
		return nil
	}
	if m.Command == cell.RelayRendezvous1 && c.hs.purpose == OnionServiceRendezvous && len(m.Data) == 84 {
		return nil
	}
	if m.Command == cell.RelayEstablishRendezvous && c.hs.purpose == OnionRendezvous && len(m.Data) == 20 {
		return nil
	}
	if m.Command == cell.RelayIntroduce1 && c.hs.purpose == OnionIntroduction && len(m.Data) >= 120 {
		return nil
	}
	return ErrProtocol
}

// acceptOnionControl runs in the sole reader. Install service keys before it
// reads another cell, so a prompt service response cannot race key installation.
func (c *Circuit) acceptOnionControl(m Message) (result error) {
	defer func() {
		if result != nil {
			result = fmt.Errorf("onion control command %d, length %d: %w", m.Command, len(m.Data), result)
		}
	}()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hs == nil || m.Hop != c.relayEnd || m.StreamID != 0 {
		return ErrProtocol
	}
	h := c.hs
	switch m.Command {
	case cell.RelayIntroEstablished:
		if h.purpose != OnionServiceIntroduction || h.stage != 1 {
			return ErrProtocol
		}
		if len(m.Data) > 0 {
			b := m.Data[1:]
			for j := 0; j < int(m.Data[0]); j++ {
				if len(b) < 2 || int(b[1]) > len(b)-2 {
					return ErrProtocol
				}
				b = b[2+int(b[1]):]
			}
			if len(b) != 0 {
				return ErrProtocol
			}
		}
		h.stage = 2
	case cell.RelayIntroduce2:
		if h.purpose != OnionServiceIntroduction || h.stage != 2 || len(m.Data) < 120 || len(m.Data) > 490 {
			return ErrProtocol
		}

	case cell.RelayRendezvousEstablished:
		if h.purpose != OnionRendezvous || h.stage != 1 || len(m.Data) != 0 {
			return ErrProtocol
		}
		h.stage = 2
	case cell.RelayRendezvous2:
		if h.purpose != OnionRendezvous || h.stage != 2 || h.finish == nil || len(m.Data) < 64 {
			return ErrProtocol
		}
		// C Tor may pad RENDEZVOUS2 to the legacy 148-byte length.
		// hs-ntor authenticates its 64-byte reply; trailing relay-bounded padding is ignored.
		keys, err := h.finish(m.Data[:64])
		h.finish = nil
		if err != nil {
			return err
		}
		defer clear(keys[:])
		if err := c.crypto.AddOnionHop(keys); err != nil {
			return err
		}
		h.stage = 3
		c.endHop.Add(1)
	case cell.RelayIntroduceAck:
		if h.purpose != OnionIntroduction || h.stage != 1 || len(m.Data) < 3 {
			return ErrProtocol
		}
		b := m.Data[3:]
		for i := 0; i < int(m.Data[2]); i++ {
			if len(b) < 2 || int(b[1]) > len(b)-2 {
				return ErrProtocol
			}
			b = b[2+int(b[1]):]
		}
		if len(b) != 0 {
			return ErrProtocol
		}
		h.stage = 2
	default:
		return ErrProtocol
	}
	return nil
}

func (c *Circuit) PrepareRendezvous(ctx context.Context, cookie [20]byte, host string, port uint16, finish func([]byte) ([128]byte, error)) error {
	c.mu.Lock()
	if c.hs == nil || c.hs.purpose != OnionRendezvous || c.hs.stage != 0 || finish == nil || port == 0 {
		c.mu.Unlock()
		return ErrProtocol
	}
	c.hs.stage = 1
	c.hs.finish = finish
	c.hs.host = strings.TrimSuffix(strings.ToLower(host), ".")
	c.port = port
	c.mu.Unlock()
	if _, err := c.Send(ctx, c.relayEnd, cell.RelayMessage{Command: cell.RelayEstablishRendezvous, Data: cookie[:]}); err != nil {
		return err
	}
	m, err := c.Receive(ctx)
	if err != nil {
		return err
	}
	if m.Command != cell.RelayRendezvousEstablished {
		return ErrProtocol
	}
	return c.startPadding(ctx)
}

func (c *Circuit) Introduce(ctx context.Context, payload []byte) error {
	c.mu.Lock()
	if c.hs == nil || c.hs.purpose != OnionIntroduction || c.hs.stage != 0 {
		c.mu.Unlock()
		return ErrProtocol
	}
	c.hs.stage = 1
	c.mu.Unlock()
	if _, err := c.Send(ctx, c.relayEnd, cell.RelayMessage{Command: cell.RelayIntroduce1, Data: payload}); err != nil {
		return err
	}
	if err := c.startPadding(ctx); err != nil {
		return err
	}
	m, err := c.Receive(ctx)
	if err != nil {
		return err
	}
	if m.Command != cell.RelayIntroduceAck || len(m.Data) < 3 {
		return ErrProtocol
	}
	if binary.BigEndian.Uint16(m.Data[:2]) != 0 {
		return errors.New("onion introduction was rejected")
	}
	return nil
}

// FinishRendezvous switches from the private handshake to managed service
// streams. No caller can mix raw traffic with streams on an ordinary circuit.
func (c *Circuit) FinishRendezvous(ctx context.Context) error {
	m, err := c.Receive(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if m.Command != cell.RelayRendezvous2 || c.hs == nil || c.hs.stage != 3 || c.mode != 1 || c.streams != nil {
		return ErrProtocol
	}
	c.mode = 0
	return nil
}

func (c *Circuit) DialDirectory(ctx context.Context) (net.Conn, error) {
	c.mu.Lock()
	ok := c.hs != nil && c.hs.purpose == OnionDirectory
	c.mu.Unlock()
	if !ok {
		return nil, ErrProtocol
	}
	return c.dialStream(ctx, "onion-directory", nil, cell.RelayBeginDir)
}
