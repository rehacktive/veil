package circuit

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"veil/cell"
	"veil/channel"
	"veil/directory"
	"veil/ntor"
	"veil/relaycrypto"
)

func TestThreeHopTrafficAndEarlyBudget(t *testing.T) {
	c, n := built(t)
	// Multiple cells, targeting earlier hops between exit messages, ensure
	// extension and mixed-hop traffic never reset or over-advance cipher states.
	for i := 0; i < 20; i++ {
		if _, err := c.Send(context.Background(), i%3, cell.RelayMessage{Command: cell.RelayDrop}); err != nil {
			t.Fatal(err)
		}
		data := bytes.Repeat([]byte{byte(i)}, cell.RelayDataSize)
		tag, err := c.Send(context.Background(), 2, cell.RelayMessage{Command: cell.RelayData, StreamID: 7, Data: data})
		if err != nil || tag == (relaycrypto.Tag{}) {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		m, err := c.Receive(ctx)
		cancel()
		if err != nil || m.Hop != 2 || m.StreamID != 7 || !bytes.Equal(m.Data, data) || m.Tag == (relaycrypto.Tag{}) {
			t.Fatal(m, err)
		}
	}
	for _, hop := range []int{0, 1, 2, 0, 2} {
		n.mu.Lock()
		err := n.emit(hop, cell.RelayMessage{Command: cell.RelaySendme, Data: []byte{1, 0, 20}})
		n.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		m, err := c.Receive(ctx)
		cancel()
		if err != nil || m.Hop != hop {
			t.Fatal(m, err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	early := 0
	for _, f := range n.writes {
		if f.Command == cell.RelayEarly {
			early++
		}
	}
	if early != 8 || n.writes[0].Command != cell.Create2 || n.writes[1].Command != cell.RelayEarly || n.writes[2].Command != cell.RelayEarly {
		t.Fatal("CREATE2/RELAY_EARLY sequence", early)
	}
	last := n.writes[len(n.writes)-1]
	if last.Command != cell.Destroy || !bytes.Equal(last.Payload, []byte{0}) || !n.closed {
		t.Fatal("missing private teardown", last)
	}
}

func TestBuildRejectsProtocolAndAuthenticationFailures(t *testing.T) {
	for _, test := range []struct {
		name        string
		configure   func(*testNetwork)
		guardFailed bool
		want        error
	}{
		{"wrong created command", func(n *testNetwork) {
			n.modify = func(i int, f *cell.Cell) {
				if i == 0 {
					f.Command = cell.Relay
				}
			}
		}, true, ErrProtocol},
		{"wrong circuit", func(n *testNetwork) {
			n.modify = func(i int, f *cell.Cell) {
				if i == 0 {
					f.CircuitID++
				}
			}
		}, true, ErrProtocol},
		{"bad first ntor", func(n *testNetwork) {
			n.modify = func(i int, f *cell.Cell) {
				if i == 0 {
					f.Payload[10] ^= 1
				}
			}
		}, true, ntor.ErrAuthentication},
		{"bad second ntor", func(n *testNetwork) {
			n.extension = func(i int, m *Message) {
				if i == 1 {
					m.Data[10] ^= 1
				}
			}
		}, false, ntor.ErrAuthentication},
		{"bad third ntor", func(n *testNetwork) {
			n.extension = func(i int, m *Message) {
				if i == 2 {
					m.Data[10] ^= 1
				}
			}
		}, false, ntor.ErrAuthentication},
		{"wrong extension hop", func(n *testNetwork) {
			n.extension = func(i int, m *Message) {
				if i == 2 {
					m.Hop = 0
				}
			}
		}, false, ErrProtocol},
		{"extension stream", func(n *testNetwork) { n.extension = func(i int, m *Message) { m.StreamID = 1 } }, false, ErrProtocol},
		{"extension trailing bytes", func(n *testNetwork) { n.extension = func(i int, m *Message) { m.Data = append(m.Data, 0) } }, false, ErrProtocol},
		{"extension short length", func(n *testNetwork) { n.extension = func(i int, m *Message) { m.Data = []byte{0, 64, 1} } }, false, ErrProtocol},
		{"unexpected relay", func(n *testNetwork) { n.extension = func(i int, m *Message) { m.Command = cell.RelayBegin } }, false, ErrProtocol},
		{"inbound early", func(n *testNetwork) {
			n.modify = func(i int, f *cell.Cell) {
				if i == 1 {
					f.Command = cell.RelayEarly
				}
			}
		}, false, ErrProtocol},
		{"bad backward digest", func(n *testNetwork) {
			n.modify = func(i int, f *cell.Cell) {
				if i == 2 {
					f.Payload[25] ^= 1
				}
			}
		}, false, relaycrypto.ErrUnrecognized},
	} {
		t.Run(test.name, func(t *testing.T) {
			n := network(t)
			test.configure(n)
			a := &testAttempt{usable: directory.GuardUsable}
			c, err := build(context.Background(), n.hops, a, time.Second, n.dial, func() bool { return true })
			if c != nil || !errors.Is(err, test.want) {
				t.Fatalf("accepted invalid build: %v %v", c, err)
			}
			if a.success != 0 || (a.failure != 0) != test.guardFailed || a.closed != 1 || n.Err() == nil {
				t.Fatalf("incorrect cleanup/accounting: %+v", a)
			}
		})
	}
}

func TestBuildTimeoutCancellationAndGuardUsability(t *testing.T) {
	for _, stall := range []int{1, 2, 3} {
		n := network(t)
		n.stall = stall
		a := &testAttempt{usable: directory.GuardUsable}
		_, err := build(context.Background(), n.hops, a, 30*time.Millisecond, n.dial, func() bool { return true })
		if !errors.Is(err, context.DeadlineExceeded) || (a.failure != 0) != (stall == 1) || a.closed != 1 || n.Err() == nil {
			t.Fatal(stall, err, a)
		}
	}
	t.Run("parent cancellation", func(t *testing.T) {
		n := network(t)
		n.stall = 1
		a := &testAttempt{usable: directory.GuardUsable}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		_, err := build(ctx, n.hops, a, time.Second, n.dial, func() bool { return true })
		if !errors.Is(err, context.DeadlineExceeded) || a.failure != 0 || a.closed != 1 {
			t.Fatal(err, a)
		}
	})
	for _, test := range []struct {
		name                  string
		usability             directory.GuardUsability
		valid                 bool
		successErr, errorWant error
	}{
		{"waiting", directory.GuardWaiting, true, nil, context.DeadlineExceeded},
		{"unusable", directory.GuardUnusable, true, nil, directory.ErrPath},
		{"snapshot expired during build", directory.GuardUsable, false, nil, directory.ErrTime},
		{"guard state write", directory.GuardUsable, true, errors.New("disk failed"), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			n := network(t)
			a := &testAttempt{usable: test.usability, err: test.successErr}
			_, err := build(context.Background(), n.hops, a, 30*time.Millisecond, n.dial, func() bool { return test.valid })
			want := test.errorWant
			if want == nil {
				want = test.successErr
			}
			if !errors.Is(err, want) || a.failure != 0 || a.closed != 1 || n.Err() == nil {
				t.Fatal(err, a)
			}
		})
	}
}

func TestRemoteTeardownAndUnsolicitedMessages(t *testing.T) {
	for _, name := range []string{"destroy", "truncated", "duplicate extended", "stream from guard", "stream zero", "ciphertext", "padding flood", "drop flood", "unknown flood"} {
		t.Run(name, func(t *testing.T) {
			c, n := built(t)
			n.mu.Lock()
			switch name {
			case "destroy":
				n.frames <- cell.Cell{CircuitID: n.id, Command: cell.Destroy, Payload: []byte{6}}
			case "truncated":
				n.emit(1, cell.RelayMessage{Command: cell.RelayTruncated, Data: []byte{7}})
			case "duplicate extended":
				n.emit(1, cell.RelayMessage{Command: cell.RelayExtended2})
			case "stream from guard":
				n.emit(0, cell.RelayMessage{Command: cell.RelayData, StreamID: 1})
			case "stream zero":
				n.emit(2, cell.RelayMessage{Command: cell.RelayData})
			case "ciphertext":
				n.frames <- cell.Cell{CircuitID: n.id, Command: cell.Relay, Payload: make([]byte, cell.PayloadSize)}
			case "padding flood":
				for i := 0; i < 128; i++ {
					n.frames <- cell.Cell{Command: cell.PaddingNegotiate}
				}
			case "drop flood", "unknown flood":
				command := cell.RelayDrop
				if name == "unknown flood" {
					command = 255
				}
				for i := 0; i < 128; i++ {
					n.emit(2, cell.RelayMessage{Command: command})
				}
			}
			n.mu.Unlock()
			select {
			case <-c.Done():
			case <-time.After(time.Second):
				t.Fatal("failure did not propagate")
			}
			c.Close()
			if _, err := c.Receive(context.Background()); err == nil {
				t.Fatal("read after failure")
			}
			if _, err := c.Send(context.Background(), 2, cell.RelayMessage{Command: cell.RelayDrop}); err == nil {
				t.Fatal("write after failure")
			}
			if name == "destroy" || name == "truncated" {
				var remote *RemoteError
				if !errors.As(c.Err(), &remote) {
					t.Fatal(c.Err())
				}
				n.mu.Lock()
				last := n.writes[len(n.writes)-1]
				n.mu.Unlock()
				if name == "destroy" && last.Command == cell.Destroy {
					t.Fatal("reflected DESTROY")
				}
				if name == "truncated" && (last.Command != cell.Destroy || !bytes.Equal(last.Payload, []byte{0})) {
					t.Fatal("reflected teardown reason")
				}
			}
		})
	}
}

func TestConcurrentTrafficAndCancellation(t *testing.T) {
	c, n := built(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Receive(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := c.Send(ctx, 2, cell.RelayMessage{Command: cell.RelayDrop}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if c.Err() != nil {
		t.Fatal("canceled call closed circuit")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := c.Send(context.Background(), 2, cell.RelayMessage{Command: cell.RelayData, StreamID: uint16(i + 1), Data: []byte{byte(i)}})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := map[uint16]bool{}
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		m, err := c.Receive(ctx)
		cancel()
		if err != nil || seen[m.StreamID] || len(m.Data) != 1 || m.Data[0] != byte(m.StreamID-1) {
			t.Fatal(m, err)
		}
		seen[m.StreamID] = true
	}
	// A queued canceled send must not disturb the cipher state.
	c.sendGate <- struct{}{}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	_, err := c.Send(ctx, 2, cell.RelayMessage{Command: cell.RelayDrop})
	cancel()
	<-c.sendGate
	if !errors.Is(err, context.DeadlineExceeded) || c.Err() != nil {
		t.Fatal(err, c.Err())
	}
	// Once encryption is consumed, a stalled send is fatal.
	n.mu.Lock()
	n.blockWrites = true
	n.mu.Unlock()
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	_, err = c.Send(ctx, 2, cell.RelayMessage{Command: cell.RelayDrop})
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || c.Err() == nil {
		t.Fatal(err, c.Err())
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Close() }()
	}
	wg.Wait()
}

func TestLifetimeAndBlockedReceiveClose(t *testing.T) {
	n := network(t)
	a := &testAttempt{usable: directory.GuardUsable}
	ctx, cancel := context.WithCancel(context.Background())
	c, err := build(ctx, n.hops, a, time.Second, n.dial, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() { _, e := c.Receive(context.Background()); read <- e }()
	cancel()
	select {
	case err := <-read:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked receive")
	}
	c.Close()
	c, n = built(t)
	n.mu.Lock()
	for i := 0; i < 100; i++ {
		n.emit(2, cell.RelayMessage{Command: cell.RelayData, StreamID: 1})
	}
	n.mu.Unlock()
	closed := make(chan struct{})
	go func() { c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("full incoming queue blocked close")
	}
}

func TestLocalValidationAndIPv6LinkSpecs(t *testing.T) {
	c, _ := built(t)
	for _, m := range []cell.RelayMessage{{Command: cell.RelayExtend2}, {Command: cell.RelayTruncate}, {Command: cell.RelayConnected, StreamID: 1}, {Command: cell.RelayData}, {Command: cell.RelayDrop, StreamID: 1}, {Command: cell.RelayData, StreamID: 1, Data: make([]byte, 499)}} {
		if _, err := c.Send(context.Background(), 2, m); err == nil {
			t.Fatal("invalid outgoing accepted", m.Command)
		}
	}
	if _, err := c.Send(context.Background(), 0, cell.RelayMessage{Command: cell.RelayBegin, StreamID: 1}); err == nil {
		t.Fatal("stream to guard")
	}
	if c.Err() != nil {
		t.Fatal("validation consumed circuit")
	}
	n := network(t)
	target := n.hops[1].target
	target.Address = netip.MustParseAddrPort("[2001:db8::2]:443")
	links := linkSpecs(target)
	if len(links) != 3 || links[0].Type != cell.LinkRSAIdentity || links[1].Type != cell.LinkEd25519Identity || links[2].Type != cell.LinkIPv6 || len(links[2].Data) != 18 || !bytes.Equal(links[2].Data[16:], []byte{1, 187}) {
		t.Fatal(links)
	}
	for _, edit := range []func(*[3]hop){func(h *[3]hop) { h[1] = h[0] }, func(h *[3]hop) { h[1].ntor.OnionKey = [32]byte{} }, func(h *[3]hop) { h[0].target.Address = netip.AddrPort{} }, func(h *[3]hop) { h[0].ntor.Identity[0] ^= 1 }} {
		n := network(t)
		edit(&n.hops)
		a := &testAttempt{}
		called := false
		_, err := build(context.Background(), n.hops, a, time.Second, func(context.Context, channel.Target, channel.Options) (transport, error) {
			called = true
			return n, nil
		}, func() bool { return true })
		if err == nil || called || a.failure != 0 || a.closed != 1 {
			t.Fatal(err, called, a)
		}
	}
}
