package channel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"veil/cell"
)

var ErrPoolCapacity = errors.New("Tor channel pool capacity exhausted")
var ErrCircuitQueue = errors.New("Tor circuit receive queue exhausted")

// Pool shares authenticated guard connections within one client/host owner.
// Sharing transport never shares circuit encryption, streams or isolation keys.
// Bootstrap channels are deliberately excluded. Close joins all owned work.
type Pool struct {
	ctx                    context.Context
	cancel                 context.CancelFunc
	policy                 *PaddingPolicy
	mu                     sync.Mutex
	closed                 bool
	entries                map[Target]*pooledChannel
	all                    map[*pooledChannel]struct{}
	leases                 int
	maxChannels, maxLeases int
	wg                     sync.WaitGroup
	dial                   func(context.Context, Target, Options) (*Channel, error)
}
type pooledChannel struct {
	pool      *Pool
	target    Target
	ready     chan struct{}
	ch        *Channel
	err       error // Immutable after ready closes.
	retired   bool
	leases    map[uint32]*Lease
	idleSince time.Time
}

func NewPool(ctx context.Context, policy *PaddingPolicy) *Pool {
	life, cancel := context.WithCancel(ctx)
	p := &Pool{ctx: life, cancel: cancel, policy: policy, entries: make(map[Target]*pooledChannel), all: make(map[*pooledChannel]struct{}), maxChannels: 8, maxLeases: 1024, dial: Dial}
	p.wg.Add(1)
	go p.maintain()
	return p
}

// Acquire reserves one never-reused circuit ID before any CREATE can be sent.
// A canceled waiter does not cancel a handshake needed by another circuit.
func (p *Pool) Acquire(ctx context.Context, target Target, options Options) (*Lease, error) {
	options, err := options.normalized()
	if err != nil {
		return nil, err
	}
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	if options.Padding == nil || options.PaddingPolicy != p.policy {
		return nil, fmt.Errorf("%w: incompatible padding owner", ErrProtocol)
	}
	setup, cancel := context.WithTimeout(ctx, options.HandshakeTimeout)
	defer cancel()
	for {
		if err := setup.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if p.closed || p.ctx.Err() != nil {
			p.mu.Unlock()
			return nil, ErrClosed
		}
		s := p.entries[target]
		if s != nil && s.ch != nil && (s.ch.Err() != nil || (!s.ch.info.CertificatesExpire.IsZero() && !time.Now().Before(s.ch.info.CertificatesExpire))) {
			s.retired = true
			delete(p.entries, target)
			s = nil
		}
		if s == nil {
			if len(p.all) >= p.maxChannels {
				p.mu.Unlock()
				return nil, ErrPoolCapacity
			}
			s = &pooledChannel{pool: p, target: target, ready: make(chan struct{}), leases: make(map[uint32]*Lease)}
			p.entries[target] = s
			p.all[s] = struct{}{}
			p.wg.Add(1)
			physicalOptions := options
			physicalOptions.HandshakeTimeout = 30 * time.Second
			go p.connect(s, physicalOptions)
		}
		select {
		case <-s.ready:
			if s.err != nil {
				p.mu.Unlock()
				return nil, s.err
			}
		default:
			p.mu.Unlock()
			select {
			case <-setup.Done():
				return nil, setup.Err()
			case <-p.ctx.Done():
				return nil, ErrClosed
			case <-s.ready:
			}
			if s.err != nil {
				return nil, s.err
			}
			continue
		}
		if p.leases >= p.maxLeases {
			p.mu.Unlock()
			return nil, ErrPoolCapacity
		}
		id, err := s.ch.AllocateCircuitID()
		if errors.Is(err, ErrCircuitIDsExhausted) {
			s.retired = true
			delete(p.entries, target)
			p.mu.Unlock()
			continue
		}
		if err != nil {
			p.mu.Unlock()
			return nil, err
		}
		leaseCtx, leaseCancel := context.WithCancel(p.ctx)
		l := &Lease{ctx: leaseCtx, cancel: leaseCancel, sendGate: make(chan struct{}, 1), shared: s, id: id, incoming: make(chan cell.Cell, 1024), done: make(chan struct{}), closed: make(chan struct{})}
		s.leases[id] = l
		s.idleSince = time.Time{}
		p.leases++
		p.wg.Add(1)
		go l.run(ctx)
		p.mu.Unlock()
		return l, nil
	}
}

func (p *Pool) connect(s *pooledChannel, options Options) {
	defer p.wg.Done()
	ch, err := p.dial(p.ctx, s.target, options)
	p.mu.Lock()
	s.ch, s.err = ch, err
	if err != nil {
		if p.entries[s.target] == s {
			delete(p.entries, s.target)
		}
		delete(p.all, s)
	} else {
		s.idleSince = time.Now()
	}
	close(s.ready)
	p.mu.Unlock()
	if err != nil {
		return
	}
	defer func() {
		_ = ch.Close()
		p.mu.Lock()
		if p.entries[s.target] == s {
			delete(p.entries, s.target)
		}
		delete(p.all, s)
		var leases []*Lease
		for _, l := range s.leases {
			leases = append(leases, l)
		}
		p.mu.Unlock()
		for _, l := range leases {
			l.abort(ch.Err())
		}
	}()
	for {
		frame, err := ch.Receive(p.ctx)
		if err != nil {
			return
		}
		p.mu.Lock()
		l := s.leases[frame.CircuitID]
		p.mu.Unlock()
		if l == nil {
			ch.mu.Lock()
			_, known := ch.usedIDs[frame.CircuitID]
			ch.mu.Unlock()
			if !known {
				ch.shutdown(fmt.Errorf("%w: unsolicited circuit ID", ErrProtocol))
				return
			}
			continue
		}
		l.deliver(frame)
	}
}

func (p *Pool) maintain() {
	defer p.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		idle := 30 * time.Minute
		var changed <-chan struct{}
		if p.policy != nil {
			_, _, idle, changed = p.policy.current()
		}
		select {
		case <-p.ctx.Done():
			p.mu.Lock()
			p.closed = true
			var channels []*Channel
			for s := range p.all {
				if s.ch != nil {
					channels = append(channels, s.ch)
				}
			}
			p.mu.Unlock()
			for _, ch := range channels {
				_ = ch.Close()
			}
			return
		case <-ticker.C:
		case <-changed:
			continue
		}
		var closeChannels []*Channel
		p.mu.Lock()
		for s := range p.all {
			if s.ch != nil && len(s.leases) == 0 && (s.retired || time.Since(s.idleSince) >= idle) {
				s.retired = true
				if p.entries[s.target] == s {
					delete(p.entries, s.target)
				}
				closeChannels = append(closeChannels, s.ch)
			}
		}
		p.mu.Unlock()
		for _, ch := range closeChannels {
			_ = ch.Close()
		}
	}
}
func (p *Pool) Close() error {
	p.mu.Lock()
	p.closed = true
	p.cancel()
	p.mu.Unlock()
	p.wg.Wait()
	return nil
}

// Lease is a circuit-scoped transport. Closing it sends DESTROY when needed and
// releases only this circuit. The pool controls the underlying TLS lifetime.
type Lease struct {
	ctx                  context.Context
	cancel               context.CancelFunc
	sendGate             chan struct{}
	shared               *pooledChannel
	id                   uint32
	incoming             chan cell.Cell
	done, closed         chan struct{}
	mu                   sync.Mutex
	err                  error
	allocated, destroyed bool
}

func (l *Lease) AllocateCircuitID() (uint32, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return 0, l.err
	}
	if l.allocated {
		return 0, ErrProtocol
	}
	l.allocated = true
	return l.id, nil
}
func (l *Lease) Done() <-chan struct{} { return l.done }
func (l *Lease) Err() error            { l.mu.Lock(); defer l.mu.Unlock(); return l.err }
func (l *Lease) MarkUsed()             { l.shared.ch.MarkUsed() }
func (l *Lease) Send(ctx context.Context, frame cell.Cell) error {
	return l.sendFrames(ctx, []cell.Cell{frame}, false)
}

// SendBatch preserves the lease's ordering and cancellation semantics for a
// bounded fixed-cell batch. Every cell must belong to this lease's circuit.
func (l *Lease) SendBatch(ctx context.Context, frames []cell.Cell) error {
	return l.sendFrames(ctx, frames, true)
}

func (l *Lease) sendFrames(ctx context.Context, frames []cell.Cell, batch bool) error {
	if len(frames) == 0 || len(frames) > MaxBatchCells {
		return ErrProtocol
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(l.ctx, cancel)
	defer func() { stop(); cancel() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.done:
		return l.Err()
	case l.sendGate <- struct{}{}:
	}
	defer func() { <-l.sendGate }()

	if err := l.Err(); err != nil {
		return err
	}
	destroyed := false
	for _, frame := range frames {
		if frame.CircuitID != l.id {
			return ErrProtocol
		}
		destroyed = destroyed || frame.Command == cell.Destroy
	}
	queued, err := l.shared.ch.sendCells(ctx, frames, false, batch)
	if queued && destroyed {
		l.mu.Lock()
		l.destroyed = true
		l.mu.Unlock()
	}
	return err
}
func (l *Lease) Receive(ctx context.Context) (cell.Cell, error) {
	if err := ctx.Err(); err != nil {
		return cell.Cell{}, err
	}
	select {
	case <-ctx.Done():
		return cell.Cell{}, ctx.Err()
	case <-l.done:
		return cell.Cell{}, l.Err()
	case f := <-l.incoming:
		if err := l.Err(); err != nil {
			return cell.Cell{}, err
		}
		return f, nil
	}
}
func (l *Lease) deliver(frame cell.Cell) {
	l.mu.Lock()
	if l.err != nil {
		l.mu.Unlock()
		return
	}
	if frame.Command == cell.Destroy {
		l.destroyed = true
	}
	select {
	case l.incoming <- frame:
		l.mu.Unlock()
	default:
		l.mu.Unlock()
		l.abort(ErrCircuitQueue)
	}
}
func (l *Lease) abort(err error) {
	if err == nil {
		err = ErrClosed
	}
	l.mu.Lock()
	if l.err != nil {
		l.mu.Unlock()
		return
	}
	l.err = err
	l.cancel()
	close(l.done)
	l.mu.Unlock()
	p := l.shared.pool
	p.mu.Lock()
	delete(l.shared.leases, l.id)
	if len(l.shared.leases) == 0 {
		l.shared.idleSince = time.Now()
	}
	p.mu.Unlock()
}
func (l *Lease) run(life context.Context) {
	p := l.shared.pool
	defer p.wg.Done()
	defer close(l.closed)
	select {
	case <-life.Done():
		l.abort(life.Err())
	case <-l.shared.ch.Done():
		l.abort(l.shared.ch.Err())
	case <-l.done:
	}
	l.sendGate <- struct{}{}
	defer func() { <-l.sendGate }()
	l.mu.Lock()
	destroyed := l.destroyed
	l.mu.Unlock()
	if !destroyed && l.shared.ch.Err() == nil {
		ctx, cancel := context.WithTimeout(p.ctx, 500*time.Millisecond)
		queued, _ := l.shared.ch.sendCell(ctx, cell.Cell{CircuitID: l.id, Command: cell.Destroy, Payload: []byte{0}}, false)
		cancel()
		// If teardown cannot be queued, stop admitting circuits on this
		// channel and close it after existing leases drain. A stalled actual
		// write still hits the transport deadline; queue pressure alone must
		// not let one endpoint destroy its siblings.
		if !queued {
			p.mu.Lock()
			l.shared.retired = true
			if p.entries[l.shared.target] == l.shared {
				delete(p.entries, l.shared.target)
			}
			p.mu.Unlock()
		}
	}
	p.mu.Lock()
	p.leases--
	p.mu.Unlock()
}
func (l *Lease) Close() error { l.abort(ErrClosed); <-l.closed; return nil }
