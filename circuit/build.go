// Package circuit constructs native three-hop Tor circuits. It exposes relay
// messages or multiplexed net.Conn streams with fixed-window flow control.
// Circuit pooling and production anonymity guarantees are not provided.
package circuit

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"veil/cell"
	"veil/channel"
	"veil/directory"
	"veil/ntor"
	"veil/relaycrypto"
)

type Options struct {
	Port         uint16        // Required destination port for exit-policy selection.
	IPv6         bool          // Select an exit whose IPv6 summary permits Port.
	BuildTimeout time.Duration // Zero means one minute, including guard usability.
}

type hop struct {
	target channel.Target
	ntor   ntor.Relay
}

type guardAttempt interface {
	Success(time.Time) error
	Failure(time.Time, bool) error
	Usability(time.Time) directory.GuardUsability
	Close()
}

type transport interface {
	Send(context.Context, cell.Cell) error
	Receive(context.Context) (cell.Cell, error)
	AllocateCircuitID() (uint32, error)
	Done() <-chan struct{}
	Err() error
	Close() error
}

type dialFunc func(context.Context, channel.Target, channel.Options) (transport, error)

// Build selects a tracked guard and a compatible middle/exit from a live,
// verified snapshot, then authenticates all three hops with type-2 ntor. It
// makes one attempt: later-hop failures never trigger unrestricted guard
// rotation. ctx owns the circuit lifetime, including after Build returns.
// Use a single GuardStore owner for the state directory, shared with the
// directory manager. Call Close even if ctx is eventually canceled.
func Build(ctx context.Context, s *directory.Snapshot, guards *directory.GuardStore, options Options) (*Circuit, error) {
	return buildSelected(ctx, s, guards, options, func(ctx context.Context, target channel.Target, options channel.Options) (transport, error) {
		return channel.Dial(ctx, target, options)
	})
}

func buildSelected(ctx context.Context, s *directory.Snapshot, guards *directory.GuardStore, options Options, dial dialFunc) (*Circuit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.Port == 0 || guards == nil || options.BuildTimeout < 0 {
		return nil, errors.New("circuit: guard store, destination port, and nonnegative timeout are required")
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
	p, err := s.SelectPathWithGuard(a.Relay(), options.Port, options.IPv6, time.Now())
	if err != nil {
		a.Close()
		return nil, err
	}
	var hops [3]hop
	for i, r := range []directory.Relay{p.Guard, p.Middle, p.Exit} {
		hops[i] = hop{r.Target(), r.NTor()}
	}
	c, err := build(ctx, hops, a, options.BuildTimeout, dial, func() bool { return s.Valid(time.Now()) })
	if err != nil {
		return nil, err
	}
	c.path = p
	c.port, c.ipv6, c.window = options.Port, options.IPv6, window
	return c, nil
}

// build is also used by protocol tests with explicit test-network pins. There
// is deliberately no public API that bypasses verified path selection.
func build(lifetime context.Context, hops [3]hop, attempt guardAttempt, timeout time.Duration, dial dialFunc, valid func() bool) (result *Circuit, err error) {
	defer attempt.Close()
	if timeout == 0 {
		timeout = time.Minute
	}
	ctx, cancel := context.WithTimeout(lifetime, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Reject bad local descriptors before opening a connection or penalizing a
	// guard. ntor.Start also rejects low-order X25519 public keys.
	var states [3]*ntor.ClientState
	var requests [3][ntor.RequestSize]byte
	for i := 0; i < 3; i++ {
		h := hops[i]
		if h.target.Identity.RSA != h.ntor.Identity || h.target.Identity.Validate() != nil ||
			!h.target.Address.IsValid() || h.target.Address.Port() == 0 || h.target.Address.Addr().Zone() != "" ||
			h.target.Address.Addr().IsMulticast() || h.target.Address.Addr().IsUnspecified() {
			return nil, fmt.Errorf("%w: invalid hop descriptor", ErrProtocol)
		}
		for j := 0; j < 3; j++ {
			if j >= i {
				break
			}
			if hops[j].target.Identity.RSA == h.target.Identity.RSA || hops[j].target.Identity.Ed25519 == h.target.Identity.Ed25519 {
				return nil, fmt.Errorf("%w: repeated hop", ErrProtocol)
			}
		}
		states[i], requests[i], err = ntor.Start(h.ntor)
		if err != nil {
			return nil, err
		}
	}
	guardAuthenticated := false
	defer func() {
		// Parent cancellation is not evidence of guard failure. A locally imposed
		// build timeout before guard authentication is a failed reachability attempt.
		if err != nil && !guardAuthenticated && lifetime.Err() == nil {
			err = errors.Join(err, attempt.Failure(time.Now(), false))
		}
	}()
	deadline, _ := ctx.Deadline()
	ch, err := dial(lifetime, hops[0].target, channel.Options{HandshakeTimeout: max(time.Nanosecond, time.Until(deadline))})
	if err != nil {
		return nil, err
	}
	c := newCircuit(ch)
	defer func() {
		if err != nil {
			c.shutdown(err)
			c.wg.Wait()
		}
	}()
	c.id, err = ch.AllocateCircuitID()
	if err != nil {
		return nil, err
	}
	payload, err := cell.EncodeCreate2(cell.HandshakeNtor, requests[0][:])
	if err != nil {
		return nil, err
	}
	if err = ch.Send(ctx, cell.Cell{CircuitID: c.id, Command: cell.Create2, Payload: payload}); err != nil {
		return nil, err
	}
	f, err := c.receiveFrame(ctx)
	if err != nil {
		return nil, err
	}
	if f.Command != cell.Created2 {
		return nil, fmt.Errorf("%w: expected CREATED2", ErrProtocol)
	}
	reply, err := cell.DecodeCreated2(f.Payload)
	if err != nil {
		return nil, err
	}
	keys, err := states[0].Finish(reply)
	if err != nil {
		return nil, err
	}
	guardAuthenticated = true
	c.crypto, err = relaycrypto.NewClient(keys)
	if err != nil {
		return nil, err
	}
	for i := 1; i < 3; i++ {
		payload, e := cell.EncodeExtend2(cell.Extend2Message{Links: linkSpecs(hops[i].target), HandshakeType: cell.HandshakeNtor, Handshake: requests[i][:]})
		if e != nil {
			return nil, e
		}
		if _, e = c.sendRelay(ctx, i-1, cell.RelayMessage{Command: cell.RelayExtend2, Data: payload}); e != nil {
			return nil, e
		}
		m, e := c.receiveRelay(ctx)
		if e != nil {
			return nil, e
		}
		if m.Hop != i-1 || m.Command != cell.RelayExtended2 || m.StreamID != 0 {
			return nil, fmt.Errorf("%w: unexpected extension reply", ErrProtocol)
		}
		reply, e = cell.DecodeCreated2(m.Data)
		if e != nil || len(m.Data) != 2+len(reply) {
			return nil, fmt.Errorf("%w: malformed EXTENDED2", ErrProtocol)
		}
		keys, e = states[i].Finish(reply)
		if e != nil {
			return nil, e
		}
		if e = c.crypto.AddHop(keys); e != nil {
			return nil, e
		}
	}
	c.start(lifetime)
	if err = attempt.Success(time.Now()); err != nil {
		return nil, err
	}
	for {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if !valid() {
			return nil, directory.ErrTime
		}
		switch attempt.Usability(time.Now()) {
		case directory.GuardUsable:
			if err = c.Err(); err != nil {
				return nil, err
			}
			return c, nil
		case directory.GuardUnusable:
			return nil, directory.ErrPath
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-ch.Done():
			timer.Stop()
			return nil, ch.Err()
		case <-c.done:
			timer.Stop()
			return nil, c.Err()
		case <-timer.C:
		}
	}
}

func linkSpecs(target channel.Target) []cell.LinkSpec {
	a := target.Address.Addr().Unmap()
	address := append([]byte(nil), a.AsSlice()...)
	address = binary.BigEndian.AppendUint16(address, target.Address.Port())
	ids := []cell.LinkSpec{{Type: cell.LinkRSAIdentity, Data: target.Identity.RSA[:]}, {Type: cell.LinkEd25519Identity, Data: target.Identity.Ed25519[:]}}
	if a.Is4() {
		return append([]cell.LinkSpec{{Type: cell.LinkIPv4, Data: address}}, ids...)
	}
	// Spec order: IPv4, RSA, Ed25519, IPv6 (omitting absent addresses).
	return append(ids, cell.LinkSpec{Type: cell.LinkIPv6, Data: address})
}
