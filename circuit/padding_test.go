package circuit

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"veil/cell"
	"veil/directory"
)

type testPaddingPolicy struct {
	enabled, allow atomic.Bool
	other, padding atomic.Int32
}

func (p *testPaddingPolicy) Enabled() bool { return p.enabled.Load() }
func (p *testPaddingPolicy) NonPadding()   { p.other.Add(1) }
func (p *testPaddingPolicy) TryPadding() bool {
	if !p.Enabled() || !p.allow.Load() {
		return false
	}
	p.padding.Add(1)
	return true
}

func paddingCircuit(t *testing.T, purpose OnionPurpose) (*Circuit, *testNetwork, *testPaddingPolicy) {
	t.Helper()
	size := 3
	if purpose == OnionIntroduction {
		size = 4
	}
	n := network(t, size)
	c, err := buildHops(context.Background(), n.hops, &testAttempt{usable: directory.GuardUsable}, time.Second, n.dial, func() bool { return true }, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	p := &testPaddingPolicy{}
	p.enabled.Store(true)
	p.allow.Store(true)
	c.mu.Lock()
	c.hs = &onionCircuit{purpose: purpose}
	c.paddingSupported = true
	c.paddingBudget = p
	c.mu.Unlock()
	return c, n, p
}

func TestIntroductionPaddingWireAndLifetime(t *testing.T) {
	c, n, p := paddingCircuit(t, OnionIntroduction)
	var sequence []cell.RelayCommand
	n.stream = func(m cell.RelayMessage, hop int) error {
		sequence = append(sequence, m.Command)
		switch m.Command {
		case cell.RelayIntroduce1:
			if hop != 3 {
				return ErrProtocol
			}
			return n.emit(3, cell.RelayMessage{Command: cell.RelayIntroduceAck, Data: []byte{0, 0, 0}})
		case cell.RelayPaddingNegotiate:
			// Golden bytes from Tor's trunnel format and machine registration order.
			if hop != 1 || m.StreamID != 0 || !bytes.Equal(m.Data, []byte{0, 2, 0, 0, 0, 0, 0, 1}) {
				return ErrProtocol
			}
			if err := n.emit(1, cell.RelayMessage{Command: cell.RelayPaddingNegotiated, Data: []byte{0, 2, 1, 0, 0, 0, 0, 1}}); err != nil {
				return err
			}
			for j := 0; j < 9; j++ {
				if err := n.emit(1, cell.RelayMessage{Command: cell.RelayDrop, Data: []byte("opaque")}); err != nil {
					return err
				}
			}
			if err := n.emit(1, cell.RelayMessage{Command: cell.RelayPaddingNegotiated, Data: []byte{0, 1, 1, 0, 0, 0, 0, 1}}); err != nil {
				return err
			}
			return n.emit(3, cell.RelayMessage{Command: cell.RelaySendme}) // Reader barrier.
		default:
			return ErrProtocol
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Introduce(ctx, make([]byte, 120)); err != nil {
		t.Fatal(err)
	}
	if m, err := c.Receive(ctx); err != nil || m.Command != cell.RelaySendme {
		t.Fatal(m, err)
	}
	s := c.PaddingStats()
	if !s.Started || !s.Negotiated || !s.Stopped || s.Rejected || s.Received != 9 || s.Sent != 0 || c.Err() != nil {
		t.Fatal(s, c.Err())
	}
	if len(sequence) != 2 || sequence[0] != cell.RelayIntroduce1 || sequence[1] != cell.RelayPaddingNegotiate || p.other.Load() != 2 || p.padding.Load() != 0 {
		t.Fatal(sequence, p.other.Load())
	}
}

func TestRendezvousPaddingWireAndBudget(t *testing.T) {
	for _, allow := range []bool{true, false} {
		t.Run(map[bool]string{true: "allowed", false: "budget exhausted"}[allow], func(t *testing.T) {
			c, n, p := paddingCircuit(t, OnionRendezvous)
			p.allow.Store(allow)
			var sequence []cell.RelayCommand
			n.stream = func(m cell.RelayMessage, hop int) error {
				sequence = append(sequence, m.Command)
				switch m.Command {
				case cell.RelayEstablishRendezvous:
					if hop != 2 {
						return ErrProtocol
					}
					return n.emit(2, cell.RelayMessage{Command: cell.RelayRendezvousEstablished})
				case cell.RelayPaddingNegotiate:
					if hop != 1 || !bytes.Equal(m.Data, []byte{0, 2, 1, 0, 0, 0, 0, 1}) {
						return ErrProtocol
					}
					return nil // Reply after the client timer to exercise pre-ACK padding.
				case cell.RelayDrop:
					if hop != 1 || m.StreamID != 0 || len(m.Data) != 0 {
						return ErrProtocol
					}
					return nil
				default:
					return ErrProtocol
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := c.PrepareRendezvous(ctx, [20]byte{1}, serviceName, 80, func([]byte) ([128]byte, error) { return [128]byte{}, nil }); err != nil {
				t.Fatal(err)
			}
			want := uint8(0)
			if allow {
				want = 1
			}
			if c.PaddingStats().Sent != want || len(sequence) != 2+int(want) {
				t.Fatal(c.PaddingStats(), sequence)
			}
			n.mu.Lock()
			for _, m := range []cell.RelayMessage{
				{Command: cell.RelayPaddingNegotiated, Data: []byte{0, 2, 1, 1, 0, 0, 0, 1}},
				{Command: cell.RelayDrop}, {Command: cell.RelaySendme},
			} {
				if err := n.emit(1, m); err != nil {
					t.Fatal(err)
				}
			}
			n.mu.Unlock()
			if _, err := c.Receive(ctx); err != nil {
				t.Fatal(err)
			}
			s := c.PaddingStats()
			if !s.Negotiated || s.Received != 1 || s.Stopped || p.padding.Load() != int32(want) {
				t.Fatal(s)
			}
		})
	}
}

func TestPaddingRequiresPolicyAndProtocolSupport(t *testing.T) {
	for _, name := range []string{"unsupported", "disabled", "bootstrap"} {
		t.Run(name, func(t *testing.T) {
			c, n, p := paddingCircuit(t, OnionIntroduction)
			switch name {
			case "unsupported":
				c.paddingSupported = false
			case "disabled":
				p.enabled.Store(false)
			case "bootstrap":
				c.paddingBudget = nil
			}
			before := len(n.writes)
			if err := c.startPadding(context.Background()); err != nil || c.PaddingStats().Started || len(n.writes) != before {
				t.Fatal(err, c.PaddingStats())
			}
		})
	}
}

func TestPaddingStrictPeerValidation(t *testing.T) {
	for _, name := range []string{"wrong hop", "wrong stream", "unsolicited", "short", "version", "machine", "response", "duplicate ack", "stop before ack", "stop error", "excess intro", "excess rend", "after stop", "after rejection"} {
		t.Run(name, func(t *testing.T) {
			c := newCircuit(nil)
			defer c.cancel()
			c.padding = circuitPadding{PaddingStats: PaddingStats{Started: true}}
			m := cell.RelayMessage{Command: cell.RelayPaddingNegotiated, Data: []byte{0, 2, 1, 0, 0, 0, 0, 1}}
			hop := 1
			switch name {
			case "wrong hop":
				hop = 2
			case "wrong stream":
				m.StreamID = 1
			case "unsolicited":
				c.padding.Started = false
			case "short":
				m.Data = m.Data[:7]
			case "version":
				m.Data[0] = 1
			case "machine":
				m.Data[3] = 1
			case "response":
				m.Data[2] = 3
			case "duplicate ack":
				c.padding.Negotiated = true
			case "stop before ack":
				m.Data[1] = 1
			case "stop error":
				c.padding.Negotiated = true
				m.Data[1] = 1
				m.Data[2] = 2
			case "excess intro":
				c.padding.Received = 10
				m.Command = cell.RelayDrop
			case "excess rend":
				c.padding.machine = 1
				c.padding.Received = 1
				m.Command = cell.RelayDrop
			case "after stop":
				c.padding.Stopped = true
				m.Command = cell.RelayDrop
			case "after rejection":
				c.padding.Rejected = true
				m.Command = cell.RelayDrop
			}
			if err := c.acceptPadding(hop, m); !errors.Is(err, ErrProtocol) {
				t.Fatal("invalid padding accepted", err)
			}
		})
	}
	c := newCircuit(nil)
	defer c.cancel()
	c.padding.Started = true
	if err := c.acceptPadding(1, cell.RelayMessage{Command: cell.RelayPaddingNegotiated, Data: []byte{0, 2, 1, 0, 0, 0, 0, 2}}); err != nil || c.PaddingStats().Negotiated {
		t.Fatal("old counter not ignored", err)
	}
	if err := c.acceptPadding(1, cell.RelayMessage{Command: cell.RelayPaddingNegotiated, Data: []byte{0, 2, 2, 0, 0, 0, 0, 1}}); err != nil || !c.PaddingStats().Rejected {
		t.Fatal("legitimate rejection", err)
	}
	c.padding = circuitPadding{PaddingStats: PaddingStats{Started: true, Negotiated: true}, machine: 1}
	if err := c.acceptPadding(1, cell.RelayMessage{Command: cell.RelayPaddingNegotiated, Data: []byte{0, 1, 1, 1, 0, 0, 0, 1}}); err != nil || !c.PaddingStats().Stopped {
		t.Fatal("legitimate rendezvous stop", err)
	}
}

func TestPaddingFailureClosesWithoutLeakingControl(t *testing.T) {
	for _, cmd := range []cell.RelayCommand{cell.RelayPaddingNegotiate, cell.RelayPaddingNegotiated, cell.RelayDrop} {
		c, n := built(t)
		n.mu.Lock()
		err := n.emit(1, cell.RelayMessage{Command: cmd})
		n.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err = c.Receive(ctx)
		cancel()
		if !errors.Is(err, ErrProtocol) {
			t.Fatal(cmd, err)
		}
	}
}

func TestPaddingDropNeverQueuesOrRepeats(t *testing.T) {
	for _, name := range []string{"busy", "disabled after start", "peer already padded", "canceled", "already sent", "allowed"} {
		t.Run(name, func(t *testing.T) {
			c, n, p := paddingCircuit(t, OnionRendezvous)
			c.padding = circuitPadding{PaddingStats: PaddingStats{Started: true}, machine: 1}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "busy":
				c.sendGate <- struct{}{}
				defer func() { <-c.sendGate }()
			case "disabled after start":
				p.enabled.Store(false)
			case "peer already padded":
				c.padding.Received = 1
			case "canceled":
				cancel()
			case "already sent":
				c.padding.Sent = 1
			}
			before := len(n.writes)
			if err := c.sendPaddingDrop(ctx); err != nil {
				t.Fatal(err)
			}
			want := 0
			if name == "allowed" {
				want = 1
			}
			if len(n.writes) != before+want || p.padding.Load() != int32(want) {
				t.Fatal("padding bypassed gate/state/policy")
			}
			if err := c.sendPaddingDrop(ctx); err != nil || len(n.writes) != before+want {
				t.Fatal("repeated padding", err)
			}
		})
	}
}

func TestPaddingBlockedWriteCancellation(t *testing.T) {
	c, n, _ := paddingCircuit(t, OnionRendezvous)
	c.padding = circuitPadding{PaddingStats: PaddingStats{Started: true}, machine: 1}
	n.mu.Lock()
	n.blockWrites = true
	n.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := c.sendPaddingDrop(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if !errors.Is(c.Err(), context.DeadlineExceeded) {
		t.Fatal("encrypted write failure left circuit usable", c.Err())
	}
}
