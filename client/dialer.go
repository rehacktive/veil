// Package client joins a verified directory/guard lifecycle to native Tor
// streams. Explicit isolation scopes permit circuit reuse; unscoped requests
// get dedicated circuits. There is no direct fallback.
package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"veil/circuit"
	"veil/directory"
	"veil/isolation"
	"veil/onion"
	"veil/socks5"
)

type snapshotSource interface {
	Snapshot() (*directory.Snapshot, error)
}
type streamCircuit interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	Close() error
}
type buildFunc func(context.Context, *directory.Snapshot, circuit.Options) (streamCircuit, error)

type Options struct {
	MaxPooledCircuits  int           // Pool bound including active/building/idle entries; default 16, max 256.
	CircuitMaxAge      time.Duration // Stop attaching streams after this age; default 10 minutes. Active streams drain.
	CircuitIdleTimeout time.Duration // Close unused pooled circuits; default 2 minutes.
	DisableReuse       bool          // Retain dedicated circuits even with explicit isolation tokens.
	BuildTimeout       time.Duration // Per build attempt; default 20 seconds.
	ConnectTimeout     time.Duration // Total queue/build/backoff/stream budget; default 1 minute.
	OnionTimeout       time.Duration // Total onion descriptor/introduction/rendezvous budget; default 3 minutes.
	BuildAttempts      int           // Default 3, maximum 5. Stream opens are never retried.
	MaxCircuits        int           // Connection slots including builds: default 16, max 256. Onion setup uses at most two circuits per slot.
}

type Dialer struct {
	cancel      context.CancelFunc
	pool        *circuitPool
	descriptors *descriptorCache
	lifetime    context.Context
	source      snapshotSource
	build       buildFunc
	options     Options
	slots       chan struct{}
	wait        func(context.Context, time.Duration) error
	onionBuild  func(context.Context, context.Context, string, uint16) (streamCircuit, error)
}

// New uses the same manager and guard store that own the private state. ctx
// owns every circuit's lifetime; canceling an individual DialContext after it
// succeeds does not close its stream. Close each returned connection and call
// Dialer.Close before releasing state. Use isolation.WithToken to opt into sharing.
func New(ctx context.Context, manager *directory.Manager, guards *directory.GuardStore, options Options) (*Dialer, error) {
	if manager == nil || guards == nil {
		return nil, errors.New("directory manager and guard store are required")
	}
	d, err := newDialer(ctx, manager, options, func(ctx context.Context, s *directory.Snapshot, o circuit.Options) (streamCircuit, error) {
		return circuit.Build(ctx, s, guards, o)
	})
	if err != nil {
		return nil, err
	}
	d.onionBuild = func(life, setup context.Context, host string, port uint16) (streamCircuit, error) {
		return d.buildOnion(life, setup, guards, host, port)
	}
	return d, nil
}
func newDialer(ctx context.Context, source snapshotSource, options Options, build buildFunc) (*Dialer, error) {
	if options.BuildTimeout == 0 {
		options.BuildTimeout = 20 * time.Second
	}
	if options.ConnectTimeout == 0 {
		options.ConnectTimeout = time.Minute
	}
	if options.OnionTimeout == 0 {
		options.OnionTimeout = 3 * time.Minute
	}
	if options.BuildAttempts == 0 {
		options.BuildAttempts = 3
	}
	if options.MaxCircuits == 0 {
		options.MaxCircuits = 16
	}
	if options.MaxPooledCircuits == 0 {
		options.MaxPooledCircuits = 16
	}
	if options.CircuitMaxAge == 0 {
		options.CircuitMaxAge = 10 * time.Minute
	}
	if options.CircuitIdleTimeout == 0 {
		options.CircuitIdleTimeout = 2 * time.Minute
	}
	if options.MaxPooledCircuits < 1 || options.MaxPooledCircuits > 256 || options.CircuitMaxAge < 0 || options.CircuitIdleTimeout < 0 {
		return nil, errors.New("invalid circuit pool limits")
	}

	if options.BuildTimeout < 0 || options.ConnectTimeout < 0 || options.OnionTimeout < 0 || options.BuildAttempts < 1 || options.BuildAttempts > 5 || options.MaxCircuits < 1 || options.MaxCircuits > 256 {
		return nil, errors.New("invalid client resource limits")
	}
	life, cancel := context.WithCancel(ctx)
	return &Dialer{lifetime: life, cancel: cancel, pool: newPool(), descriptors: newDescriptorCache(), source: source, build: build, options: options, slots: make(chan struct{}, options.MaxCircuits), wait: waitBuildRetry}, nil
}
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.pool.mu.Lock()
	if d.pool.closed {
		d.pool.mu.Unlock()
		return nil, context.Canceled
	}
	d.pool.work.Add(1)
	d.pool.mu.Unlock()
	defer d.pool.work.Done()

	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, &socks5.ReplyError{Code: 8, Err: errors.New("unsupported network")}
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return nil, errors.New("invalid destination port")
	}
	isOnion := onion.IsAddress(host)
	budget := d.options.ConnectTimeout
	if isOnion {
		if _, err := onion.ParseAddress(host); err != nil {
			return nil, replyError(err)
		}
		if d.onionBuild == nil {
			return nil, replyError(errors.New("onion client is unavailable"))
		}
		budget = d.options.OnionTimeout
		network = "tcp"
	}
	ctx, stopSetup := context.WithTimeout(ctx, budget)
	defer stopSetup()
	stopLife := context.AfterFunc(d.lifetime, stopSetup)
	defer stopLife()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.lifetime.Done():
		return nil, d.lifetime.Err()
	case d.slots <- struct{}{}:
	}
	transferred := false
	defer func() {
		if !transferred {
			<-d.slots
		}
	}()
	if scope, ok := isolation.Scope(ctx); ok && !d.options.DisableReuse {
		canonical := strings.TrimSuffix(strings.ToLower(host), ".")
		if ip, e := netip.ParseAddr(canonical); e == nil {
			canonical = ip.Unmap().String()
		}
		key := poolKey{scope: scope, host: canonical, port: uint16(number), ipv6: network == "tcp6"}
		conn, e := d.dialPooled(ctx, key, network, address, isOnion)
		if e != nil {
			return nil, replyError(e)
		}
		transferred = true
		return conn, nil
	}

	life, cancel := context.WithCancel(d.lifetime)
	stop := context.AfterFunc(ctx, cancel)
	defer func() {
		stop()
		if !transferred {
			cancel()
		}
	}()
	var c streamCircuit
	if isOnion {
		c, err = d.onionBuild(life, ctx, host, uint16(number))
	} else {
		c, err = d.buildCircuit(life, ctx, circuit.Options{Port: uint16(number), IPv6: network == "tcp6", BuildTimeout: d.options.BuildTimeout})
	}
	if err != nil {
		return nil, replyError(err)
	}
	defer func() {
		if !transferred {
			_ = c.Close()
		}
	}()
	conn, err := c.DialContext(ctx, network, address)
	if err != nil {
		return nil, replyError(err)
	}
	if !stop() || ctx.Err() != nil || life.Err() != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if life.Err() != nil {
			return nil, life.Err()
		}
		return nil, context.Canceled
	}
	owned := &ownedConn{Conn: conn, circuit: c, cancel: cancel}
	owned.release = func() { d.pool.mu.Lock(); delete(d.pool.dedicated, owned); d.pool.mu.Unlock(); <-d.slots }
	d.pool.mu.Lock()
	if d.pool.closed {
		d.pool.mu.Unlock()
		_ = conn.Close()
		return nil, context.Canceled
	}
	d.pool.dedicated[owned] = struct{}{}
	transferred = true
	d.pool.mu.Unlock()
	return owned, nil
}
func replyError(err error) error {
	code := byte(1)
	var end *circuit.StreamError
	switch {
	case errors.As(err, &end):
		switch end.Reason {
		case 2:
			code = 4
		case 4:
			code = 2
		case 5:
			code = 5
		case 7:
			code = 6
		case 8, 9:
			code = 3
		}
	case errors.Is(err, context.DeadlineExceeded):
		code = 6
	case errors.Is(err, directory.ErrPath):
		code = 2
	case errors.Is(err, directory.ErrTime):
		code = 3
	}
	return &socks5.ReplyError{Code: code, Err: err}
}

type ownedConn struct {
	net.Conn
	circuit streamCircuit
	cancel  context.CancelFunc
	release func()
	once    sync.Once
	err     error
}

func (c *ownedConn) Close() error {
	c.once.Do(func() { c.err = errors.Join(c.Conn.Close(), c.circuit.Close()); c.cancel(); c.release() })
	return c.err
}
