package channel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"veil/cell"
	"veil/torcert"
)

type poolPeer struct {
	conn  net.Conn
	codec *cell.Codec
	out   chan cell.Cell
}
type poolFixture struct {
	p      *Pool
	mu     sync.Mutex
	peers  []*poolPeer
	gate   <-chan struct{}
	dialed chan struct{}
}

func newPoolFixture(t *testing.T, policies ...*PaddingPolicy) *poolFixture {
	t.Helper()
	var policy *PaddingPolicy
	if len(policies) > 0 {
		policy = policies[0]
	}
	f := &poolFixture{p: NewPool(context.Background(), policy), dialed: make(chan struct{}, 16)}
	f.p.dial = func(ctx context.Context, _ Target, o Options) (*Channel, error) {
		f.dialed <- struct{}{}
		if f.gate != nil {
			select {
			case <-f.gate:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		a, b := net.Pipe()
		codec, _ := cell.NewCodec(4)
		ch := newPaddedChannel(ctx, a, a, codec, Info{LinkVersion: 4, CertificatesExpire: time.Now().Add(time.Hour)}, 32, o.Padding, o.PaddingPolicy)
		peer := &poolPeer{b, codec, make(chan cell.Cell, 4096)}
		f.mu.Lock()
		f.peers = append(f.peers, peer)
		f.mu.Unlock()
		go func() {
			defer b.Close()
			for {
				frame, err := codec.Read(b)
				if err != nil {
					return
				}
				select {
				case peer.out <- frame:
				case <-ctx.Done():
					return
				}
			}
		}()
		return ch, nil
	}
	t.Cleanup(func() { f.p.Close() })
	return f
}
func poolTarget() Target {
	return Target{Address: netip.MustParseAddrPort("127.0.0.1:9001"), Identity: torcert.Identity{RSA: [20]byte{1}, Ed25519: [32]byte{2}}}
}
func (f *poolFixture) acquire(t *testing.T) (*Lease, *poolPeer) {
	t.Helper()
	l, err := f.p.Acquire(context.Background(), poolTarget(), Options{Padding: &PaddingOptions{}, PaddingPolicy: f.p.policy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f.mu.Lock()
	defer f.mu.Unlock()
	return l, f.peers[len(f.peers)-1]
}
func leaseID(t *testing.T, l *Lease) uint32 {
	t.Helper()
	id, err := l.AllocateCircuitID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func peerWrite(t *testing.T, p *poolPeer, f cell.Cell) {
	t.Helper()
	p.conn.SetWriteDeadline(time.Now().Add(time.Second))
	if err := p.codec.Write(p.conn, f); err != nil {
		t.Fatal(err)
	}
}
func leaseRead(t *testing.T, l *Lease) cell.Cell {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f, err := l.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func awaitLease(t *testing.T, l *Lease) {
	t.Helper()
	select {
	case <-l.Done():
	case <-time.After(time.Second):
		t.Fatal("lease did not close")
	}
}

func TestPoolMultiplexCloseAndRetainedReuse(t *testing.T) {
	f := newPoolFixture(t)
	a, peer := f.acquire(t)
	b, other := f.acquire(t)
	if peer != other || a.shared.ch != b.shared.ch {
		t.Fatal("same guard was redialed")
	}
	aid, bid := leaseID(t, a), leaseID(t, b)
	if aid == bid {
		t.Fatal("reused circuit ID")
	}
	peerWrite(t, peer, cell.Cell{CircuitID: bid, Command: cell.Created2, Payload: []byte{2}})
	peerWrite(t, peer, cell.Cell{CircuitID: aid, Command: cell.Created2, Payload: []byte{1}})
	if leaseRead(t, a).Payload[0] != 1 || leaseRead(t, b).Payload[0] != 2 {
		t.Fatal("cross-circuit delivery")
	}
	a.Close()
	if b.Err() != nil || b.shared.ch.Err() != nil {
		t.Fatal("closing one circuit killed sibling")
	}
	// Replies to a retired allocated ID cannot be delivered to a later lease.
	for j := 0; j < 1000; j++ {
		peerWrite(t, peer, cell.Cell{CircuitID: aid, Command: cell.Relay, Payload: make([]byte, cell.PayloadSize)})
	}
	peerWrite(t, peer, cell.Cell{CircuitID: bid, Command: cell.Created2, Payload: []byte{3}})
	if leaseRead(t, b).Payload[0] != 3 {
		t.Fatal("stale cell delivered to sibling")
	}
	b.Close()
	c, newPeer := f.acquire(t)
	cid := leaseID(t, c)
	if newPeer != peer || cid == aid || cid == bid {
		t.Fatal("idle channel not safely reused")
	}
	if err := c.Send(context.Background(), cell.Cell{CircuitID: bid, Command: cell.Destroy}); !errors.Is(err, ErrProtocol) {
		t.Fatal("lease allowed foreign circuit ID")
	}
}

func TestPoolQueueOverflowIsCircuitLocal(t *testing.T) {
	f := newPoolFixture(t)
	slow, peer := f.acquire(t)
	fast, _ := f.acquire(t)
	sid, fid := leaseID(t, slow), leaseID(t, fast)
	for j := 0; j < cap(slow.incoming)+1; j++ {
		peerWrite(t, peer, cell.Cell{CircuitID: sid, Command: cell.Created2})
	}
	awaitLease(t, slow)
	if !errors.Is(slow.Err(), ErrCircuitQueue) {
		t.Fatal(slow.Err())
	}
	peerWrite(t, peer, cell.Cell{CircuitID: fid, Command: cell.Created2, Payload: []byte{7}})
	if leaseRead(t, fast).Payload[0] != 7 || fast.shared.ch.Err() != nil {
		t.Fatal("slow circuit blocked sibling")
	}
}

func TestPoolUnknownIDAndTransportFailure(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		f := newPoolFixture(t)
		a, peer := f.acquire(t)
		b, _ := f.acquire(t)
		leaseID(t, a)
		leaseID(t, b)
		if unknown {
			peerWrite(t, peer, cell.Cell{CircuitID: 0x80000000, Command: cell.Created2})
		} else {
			peer.conn.Close()
		}
		awaitLease(t, a)
		awaitLease(t, b)
		if unknown && !errors.Is(a.Err(), ErrProtocol) {
			t.Fatal(a.Err())
		}
	}
}

func TestPoolIdentityPinsAndCapacity(t *testing.T) {
	f := newPoolFixture(t)
	f.p.maxChannels = 2
	f.p.maxLeases = 2
	a, _ := f.acquire(t)
	leaseID(t, a)
	target := poolTarget()
	target.Identity.Ed25519[1] = 3
	b, err := f.p.Acquire(context.Background(), target, Options{Padding: &PaddingOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.shared.ch == a.shared.ch {
		t.Fatal("changed identity reused TLS")
	}
	if _, err := f.p.Acquire(context.Background(), target, Options{Padding: &PaddingOptions{}}); !errors.Is(err, ErrPoolCapacity) {
		t.Fatal("lease cap", err)
	}
	target.Address = netip.MustParseAddrPort("127.0.0.1:9002")
	if _, err := f.p.Acquire(context.Background(), target, Options{Padding: &PaddingOptions{}}); !errors.Is(err, ErrPoolCapacity) {
		t.Fatal("channel cap", err)
	}
	if a.Err() != nil {
		t.Fatal("capacity pressure evicted active lease")
	}
	if _, err := f.p.Acquire(context.Background(), poolTarget(), Options{}); !errors.Is(err, ErrProtocol) {
		t.Fatal("bootstrap shared with application", err)
	}
}

func TestPoolSingleHandshakeCanceledWaiterAndClose(t *testing.T) {
	f := newPoolFixture(t)
	gate := make(chan struct{})
	f.gate = gate
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := f.p.Acquire(ctx, poolTarget(), Options{Padding: &PaddingOptions{}}); first <- err }()
	<-f.dialed
	second := make(chan *Lease, 1)
	failed := make(chan error, 1)
	go func() {
		l, err := f.p.Acquire(context.Background(), poolTarget(), Options{Padding: &PaddingOptions{}})
		if err != nil {
			failed <- err
		} else {
			second <- l
		}
	}()
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(gate)
	var l *Lease
	select {
	case l = <-second:
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("second waiter stalled")
	}
	if len(f.dialed) != 0 {
		t.Fatal("duplicate TLS handshake")
	}
	f.p.Close()
	awaitLease(t, l)
	select {
	case <-l.closed:
	default:
		t.Fatal("pool close did not join leases")
	}
	if _, err := f.p.Acquire(context.Background(), poolTarget(), Options{Padding: &PaddingOptions{}}); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestPoolLifetimeCancellationAndIdlePolicy(t *testing.T) {
	policy := &PaddingPolicy{}
	policy.Update(PaddingOptions{}, time.Now().Add(time.Hour), time.Hour)
	f := newPoolFixture(t, policy)
	ctx, cancel := context.WithCancel(context.Background())
	a, err := f.p.Acquire(ctx, poolTarget(), Options{Padding: &PaddingOptions{}, PaddingPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := f.acquire(t)
	leaseID(t, a)
	leaseID(t, b)
	cancel()
	awaitLease(t, a)
	a.Close()
	if b.Err() != nil {
		t.Fatal("circuit lifetime canceled sibling")
	}
	b.Close()
	policy.Update(PaddingOptions{}, time.Now().Add(time.Hour), time.Millisecond)
	select {
	case <-b.shared.ch.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("live idle timeout not applied")
	}
}

func TestSharedSendCancellationPreservesTransport(t *testing.T) {
	// Deliberately stop consuming the wire after negotiation. Canceling a queued
	// circuit write must not cancel TLS; once the peer reads it, siblings proceed.
	a, b := net.Pipe()
	defer b.Close()
	codec, _ := cell.NewCodec(4)
	c := newChannel(context.Background(), a, a, codec, Info{LinkVersion: 4}, 2)
	defer c.Close()
	id, _ := c.AllocateCircuitID()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	queued, err := c.sendCell(ctx, cell.Cell{CircuitID: id, Command: cell.Create2}, false)
	if !queued || !errors.Is(err, context.DeadlineExceeded) || c.Err() != nil {
		t.Fatal(queued, err, c.Err())
	}
	b.SetReadDeadline(time.Now().Add(time.Second))
	frame, err := codec.Read(b)
	if err != nil || frame.CircuitID != id {
		t.Fatal(frame, err)
	}
	sent := make(chan error, 1)
	go func() {
		_, err := c.sendCell(context.Background(), cell.Cell{CircuitID: id, Command: cell.Destroy}, false)
		sent <- err
	}()
	if frame, err := codec.Read(b); err != nil || frame.Command != cell.Destroy {
		t.Fatal(frame, err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}

func TestLeaseCloseInterruptsPendingWriteWithoutClosingSibling(t *testing.T) {
	p := NewPool(context.Background(), nil)
	defer p.Close()
	var peer net.Conn
	var codec *cell.Codec
	p.dial = func(ctx context.Context, _ Target, o Options) (*Channel, error) {
		a, b := net.Pipe()
		peer = b
		codec, _ = cell.NewCodec(4)
		return newPaddedChannel(ctx, a, a, codec, Info{LinkVersion: 4}, 2, o.Padding), nil
	}
	a, err := p.Acquire(context.Background(), poolTarget(), Options{Padding: &PaddingOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	b, err := p.Acquire(context.Background(), poolTarget(), Options{Padding: &PaddingOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	aid, bid := leaseID(t, a), leaseID(t, b)
	sent := make(chan error, 1)
	go func() { sent <- a.Send(context.Background(), cell.Cell{CircuitID: aid, Command: cell.Create2}) }()
	// Read one byte to prove the first write is blocked part-way through a cell.
	prefix := make([]byte, 1)
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(prefix); err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { a.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("circuit close hung on shared write")
	}
	if err := <-sent; err == nil || b.Err() != nil || b.shared.ch.Err() != nil {
		t.Fatal("pending cancellation affected sibling", err, b.Err())
	}
	// Consume the remaining first frame, then its ordered DESTROY, and prove
	// a sibling can write over the same TLS transport afterwards.
	rest := make([]byte, 513)
	if _, err := io.ReadFull(peer, rest); err != nil {
		t.Fatal(err)
	}
	if f, err := codec.Read(peer); err != nil || f.Command != cell.Destroy || f.CircuitID != aid {
		t.Fatal(f, err)
	}
	go func() { sent <- b.Send(context.Background(), cell.Cell{CircuitID: bid, Command: cell.Create2}) }()
	if f, err := codec.Read(peer); err != nil || f.CircuitID != bid {
		t.Fatal(f, err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}
