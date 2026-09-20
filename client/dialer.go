// Package client joins a verified directory/guard lifecycle to native Tor
// streams. Each connection owns a fresh circuit; there is no direct fallback.
package client

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"veil/circuit"
	"veil/directory"
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
	BuildTimeout time.Duration // Default 1 minute.
	MaxCircuits  int           // Default 16, maximum 256, including pending builds.
}

type Dialer struct {
	lifetime context.Context
	source   snapshotSource
	build    buildFunc
	options  Options
	slots    chan struct{}
}

// New uses the same manager and guard store that own the private state. ctx
// owns every circuit's lifetime; canceling an individual DialContext after it
// succeeds does not close its stream. Close each returned connection.
func New(ctx context.Context, manager *directory.Manager, guards *directory.GuardStore, options Options) (*Dialer, error) {
	if manager == nil || guards == nil {
		return nil, errors.New("directory manager and guard store are required")
	}
	return newDialer(ctx, manager, options, func(ctx context.Context, s *directory.Snapshot, o circuit.Options) (streamCircuit, error) {
		return circuit.Build(ctx, s, guards, o)
	})
}
func newDialer(ctx context.Context, source snapshotSource, options Options, build buildFunc) (*Dialer, error) {
	if options.BuildTimeout == 0 {
		options.BuildTimeout = time.Minute
	}
	if options.MaxCircuits == 0 {
		options.MaxCircuits = 16
	}
	if options.BuildTimeout < 0 || options.MaxCircuits < 1 || options.MaxCircuits > 256 {
		return nil, errors.New("invalid client resource limits")
	}
	return &Dialer{lifetime: ctx, source: source, build: build, options: options, slots: make(chan struct{}, options.MaxCircuits)}, nil
}
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, &socks5.ReplyError{Code: 8, Err: errors.New("unsupported network")}
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return nil, errors.New("invalid destination port")
	}
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
	life, cancel := context.WithCancel(d.lifetime)
	stop := context.AfterFunc(ctx, cancel)
	defer func() {
		stop()
		if !transferred {
			cancel()
		}
	}()
	snapshot, err := d.source.Snapshot()
	if err != nil {
		return nil, replyError(err)
	}
	c, err := d.build(life, snapshot, circuit.Options{Port: uint16(number), IPv6: network == "tcp6", BuildTimeout: d.options.BuildTimeout})
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
		return nil, life.Err()
	}
	transferred = true
	return &ownedConn{Conn: conn, circuit: c, cancel: cancel, release: func() { <-d.slots }}, nil
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
