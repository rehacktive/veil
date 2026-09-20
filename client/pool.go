package client

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
	"veil/circuit"
)

type poolKey struct {
	scope [32]byte
	host  string
	port  uint16
	ipv6  bool
}
type pooledCircuit struct {
	key               poolKey
	c                 streamCircuit
	life              context.Context
	cancel            context.CancelFunc
	created, idle     time.Time
	refs              int
	building, retired bool
}
type circuitPool struct {
	mu        sync.Mutex
	dedicated map[*ownedConn]struct{}
	entries   map[*pooledCircuit]struct{}
	wake      chan struct{}
	closed    bool
	err       error
	work      sync.WaitGroup
	once      sync.Once
	done      chan struct{}
	now       func() time.Time
}

func newPool() *circuitPool {
	return &circuitPool{dedicated: make(map[*ownedConn]struct{}), entries: make(map[*pooledCircuit]struct{}), wake: make(chan struct{}), done: make(chan struct{}), now: time.Now}
}
func (p *circuitPool) signal() { close(p.wake); p.wake = make(chan struct{}) }
func circuitError(c streamCircuit) error {
	if health, ok := c.(interface{ Err() error }); ok {
		return health.Err()
	}
	return nil
}

// Close cancels this Dialer, joins pooled setup/maintenance and clears its
// descriptor cache. Active streams are interrupted. Close before releasing state.
func (d *Dialer) Close() error {
	p := d.pool
	p.mu.Lock()
	p.closed = true
	d.cancel()
	p.signal()
	p.mu.Unlock()
	d.descriptors.close()
	p.once.Do(func() { close(p.done) })
	p.work.Wait()
	<-p.done
	p.mu.Lock()
	var dedicated []*ownedConn
	for c := range p.dedicated {
		dedicated = append(dedicated, c)
	}
	for e := range p.entries {
		p.closeEntry(e)
	}
	p.mu.Unlock()
	for _, c := range dedicated {
		if err := c.Close(); err != nil {
			p.mu.Lock()
			if p.err == nil {
				p.err = err
			}
			p.mu.Unlock()
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// Called under the pool lock. Circuit.Close joins only circuit-owned workers;
// none call back into the pool. Keep the slot until bounded teardown finishes.
func (p *circuitPool) closeEntry(e *pooledCircuit) {
	e.retired = true
	e.cancel()
	if e.building {
		return
	}
	if _, ok := p.entries[e]; !ok {
		return
	}
	if err := e.c.Close(); err != nil && p.err == nil {
		p.err = err
	}
	delete(p.entries, e)
	p.signal()
}
func (d *Dialer) prunePool(now time.Time) {
	p := d.pool
	for e := range p.entries {
		if e.building {
			continue
		}
		if !now.Before(e.created.Add(d.options.CircuitMaxAge)) || circuitError(e.c) != nil {
			e.retired = true
		}
		if e.refs == 0 && (e.retired || !now.Before(e.idle.Add(d.options.CircuitIdleTimeout))) {
			p.closeEntry(e)
		}
	}
}
func (d *Dialer) runPool() {
	p := d.pool
	defer close(p.done)
	tick := time.NewTicker(max(10*time.Millisecond, min(time.Second, d.options.CircuitMaxAge, d.options.CircuitIdleTimeout)))
	defer tick.Stop()
	for {
		select {
		case <-d.lifetime.Done():
			p.mu.Lock()
			p.closed = true
			for e := range p.entries {
				p.closeEntry(e)
			}
			p.signal()
			p.mu.Unlock()
			return
		case <-tick.C:
			p.mu.Lock()
			d.prunePool(p.now())
			p.mu.Unlock()
		}
	}
}

func (d *Dialer) acquirePooled(ctx context.Context, key poolKey, isOnion bool) (*pooledCircuit, error) {
	p := d.pool
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if p.closed || d.lifetime.Err() != nil {
			p.mu.Unlock()
			return nil, context.Canceled
		}
		d.prunePool(p.now())
		building := false
		for e := range p.entries {
			if e.key != key || e.retired {
				continue
			}
			if e.building {
				building = true
				continue
			}
			if e.refs < 16 {
				e.refs++
				p.mu.Unlock()
				return e, nil
			}
		}
		if !building && len(p.entries) >= d.options.MaxPooledCircuits {
			var oldest *pooledCircuit
			for e := range p.entries {
				if !e.building && e.refs == 0 && (oldest == nil || e.idle.Before(oldest.idle)) {
					oldest = e
				}
			}
			if oldest != nil {
				p.closeEntry(oldest)
			}
		}
		if !building && len(p.entries) < d.options.MaxPooledCircuits {
			life, cancel := context.WithCancel(d.lifetime)
			e := &pooledCircuit{key: key, life: life, cancel: cancel, refs: 1, building: true}
			p.entries[e] = struct{}{}
			p.mu.Unlock()
			stop := context.AfterFunc(ctx, cancel)
			var c streamCircuit
			var err error
			if isOnion {
				c, err = d.onionBuild(life, ctx, key.host, key.port)
			} else {
				c, err = d.buildCircuit(life, ctx, circuit.Options{Port: key.port, IPv6: key.ipv6, BuildTimeout: d.options.BuildTimeout})
			}
			detached := stop()
			p.mu.Lock()
			e.c = c
			e.building = false
			e.created = p.now()
			if err == nil && (!detached || ctx.Err() != nil || life.Err() != nil || p.closed) {
				err = context.Canceled
				if ctx.Err() != nil {
					err = ctx.Err()
				}
			}
			if err != nil {
				cancel()
				if c != nil {
					err = errors.Join(err, c.Close())
				}
				delete(p.entries, e)
				p.signal()
				p.mu.Unlock()
				return nil, err
			}
			p.signal()
			p.mu.Unlock()
			return e, nil
		}
		wake := p.wake
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-d.lifetime.Done():
			return nil, d.lifetime.Err()
		case <-wake:
		}
	}
}

func (d *Dialer) dialPooled(ctx context.Context, key poolKey, network, address string, isOnion bool) (net.Conn, error) {
	p := d.pool
	p.once.Do(func() { go d.runPool() })
	// Even a cached circuit needs a currently verified directory before BEGIN.
	if _, err := d.source.Snapshot(); err != nil {
		return nil, err
	}
	e, err := d.acquirePooled(ctx, key, isOnion)
	if err != nil {
		return nil, err
	}
	if _, err := d.source.Snapshot(); err != nil {
		d.releasePooled(e, false)
		return nil, err
	}
	conn, err := e.c.DialContext(ctx, network, address)
	if err == nil && (ctx.Err() != nil || e.life.Err() != nil) {
		if ctx.Err() != nil {
			err = ctx.Err()
		} else {
			err = e.life.Err()
		}
	}
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		d.releasePooled(e, true)
		return nil, err // BEGIN is never replayed, including after a stale circuit fails.
	}
	return &pooledConn{Conn: conn, d: d, entry: e}, nil
}
func (d *Dialer) releasePooled(e *pooledCircuit, retire bool) {
	p := d.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	e.refs--
	e.idle = p.now()
	e.retired = e.retired || retire || p.closed
	if e.refs == 0 && e.retired {
		p.closeEntry(e)
	}
	p.signal()
}

type pooledConn struct {
	net.Conn
	d     *Dialer
	entry *pooledCircuit
	once  sync.Once
	err   error
}

func (c *pooledConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.d.releasePooled(c.entry, c.err != nil); <-c.d.slots })
	return c.err
}
