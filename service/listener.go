package service

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"

	"veil/directory"
)

// Listener accepts native onion streams. The zero value is not usable.
// Close stops acceptance; the host drains accepted connections until they are
// closed. Cancel the context passed to Listen to stop the host and all streams.
type Listener struct {
	addr       onionAddr
	cancel     context.CancelFunc
	acceptCtx  context.Context
	stopAccept context.CancelFunc
	pending    chan *listenerConn
	closed     chan struct{}
	done       chan struct{}
	mu         sync.Mutex
	err        error
	active     int
}

var _ net.Listener = (*Listener)(nil)

type onionAddr string

func (a onionAddr) Network() string { return "onion" }
func (a onionAddr) String() string  { return string(a) }

// Listen starts hosting one onion port without a local TCP backend. Target must
// be empty. The caller owns the directory manager, guard store and identity,
// holds their state lock, and must bootstrap and keep the manager running.
// Listen returns before descriptor publication; Accept waits for incoming streams.
// MaxStreams bounds pending and accepted streams together. IdleTimeout applies
// only to forwarding: applications set deadlines on accepted connections.
// Existing hosting limits, including circuit lifetime and disruptive introduction
// rotation, also apply to listener connections.
func Listen(ctx context.Context, manager *directory.Manager, guards *directory.GuardStore, identity *directory.ServiceIdentity, options Options) (*Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h, err := newHost(manager, guards, identity, options, true)
	if err != nil {
		return nil, err
	}
	address, err := identity.Address()
	if err != nil {
		return nil, err
	}
	return startListener(ctx, h, onionAddr(net.JoinHostPort(address, strconv.Itoa(int(options.Port))))), nil
}

func startListener(parent context.Context, h *Host, addr onionAddr) *Listener {
	ctx, cancel := context.WithCancel(parent)
	acceptCtx, stopAccept := context.WithCancel(ctx)
	l := &Listener{addr: addr, cancel: cancel, acceptCtx: acceptCtx, stopAccept: stopAccept, pending: make(chan *listenerConn), closed: make(chan struct{}), done: make(chan struct{})}
	h.listener = l
	stop := context.AfterFunc(ctx, func() { l.closeWithError(ctx.Err()) })
	go func() {
		err := h.Run(ctx)
		l.closeWithError(err)
		cancel()
		stop()
		close(l.done)
	}()
	return l
}

// Accept waits for the next stream. After shutdown, errors match net.ErrClosed;
// a host failure or context cancellation is also available through errors.Is/As.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.closed:
			return nil, l.acceptError()
		case c := <-l.pending:
			l.mu.Lock()
			if l.err != nil {
				l.mu.Unlock()
				_ = c.Close()
				return nil, l.acceptError()
			}
			// Register ownership before Close can decide whether the host has drained.
			c.mu.Lock()
			if c.closed {
				c.mu.Unlock()
				l.mu.Unlock()
				continue
			}
			l.active++
			c.release = l.release
			c.mu.Unlock()
			l.mu.Unlock()
			return c, nil
		}
	}
}

func (l *Listener) acceptError() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return errors.Join(net.ErrClosed, l.err)
}

// Close unblocks Accept and rejects pending streams. Accepted connections remain
// open; close them or cancel Listen's context to finish shutting down the host.
// Repeated calls are harmless. Close does not wait for the host to stop; Done does.
func (l *Listener) Close() error { l.closeWithError(net.ErrClosed); return nil }

func (l *Listener) closeWithError(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err == nil {
		if err == nil {
			err = net.ErrClosed
		}
		l.err = err
		close(l.closed)
		l.stopAccept()
	}
	if l.active == 0 {
		l.cancel()
	}
}

func (l *Listener) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active--
	if l.err != nil && l.active == 0 {
		l.cancel()
	}
}

// Addr returns the stable onion hostname and virtual port, with network "onion".
func (l *Listener) Addr() net.Addr { return l.addr }

// Done closes after all hosting workers and streams have stopped. Keep the
// directory manager running and the state locked until this channel closes.
func (l *Listener) Done() <-chan struct{} { return l.done }

type incomingStream interface {
	Accept(context.Context) (net.Conn, error)
	Close() error
}

func (l *Listener) serve(ctx context.Context, request incomingStream) {
	defer request.Close()
	select {
	case <-l.closed:
		return
	default:
	}
	setup, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(l.acceptCtx, cancel)
	remote, err := request.Accept(setup)
	stop()
	cancel()
	if err != nil {
		return
	}
	c := &listenerConn{Conn: remote, addr: l.addr, done: make(chan struct{})}
	defer c.Close()
	select {
	case <-ctx.Done():
		return
	case <-l.closed:
		return
	case l.pending <- c:
	}
	select {
	case <-ctx.Done():
	case <-c.done:
	}
}

type listenerConn struct {
	net.Conn
	addr    net.Addr
	done    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	closed  bool
	release func()
}

func (c *listenerConn) LocalAddr() net.Addr { return c.addr }
func (c *listenerConn) Close() error {
	var err error
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		release := c.release
		c.mu.Unlock()
		err = c.Conn.Close()
		if release != nil {
			release()
		}
		close(c.done)
	})
	return err
}
