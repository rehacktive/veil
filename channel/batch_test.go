package channel

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"veil/cell"
)

type countedWrites struct {
	net.Conn
	sizes chan int
}

func (c *countedWrites) Write(p []byte) (int, error) {
	c.sizes <- len(p)
	return c.Conn.Write(p)
}

func TestBatchValidationAndWholeWriteAcknowledgment(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	wire := &countedWrites{a, make(chan int, 8)}
	codec, _ := cell.NewCodec(5)
	c := newChannel(context.Background(), a, wire, codec, Info{LinkVersion: 5}, 2)
	defer c.Close()
	id, _ := c.AllocateCircuitID()
	valid := cell.Cell{CircuitID: id, Command: cell.Create2}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, frames := range [][]cell.Cell{
		nil, make([]cell.Cell, MaxBatchCells+1),
		{valid, {CircuitID: id ^ 1, Command: cell.Create2}},
		{valid, {CircuitID: id, Command: cell.Relay, Payload: []byte{1}}},
		{valid, {Command: cell.VPadding}},
	} {
		if err := c.SendBatch(ctx, frames); !errors.Is(err, ErrProtocol) {
			t.Fatal("invalid batch accepted", err)
		}
	}
	select {
	case <-wire.sizes:
		t.Fatal("invalid batch wrote a prefix")
	default:
	}
	sent := make(chan error, 1)
	go func() { sent <- c.SendBatch(ctx, []cell.Cell{valid, {CircuitID: id, Command: cell.Destroy}}) }()
	if f, err := codec.Read(b); err != nil || f.Command != cell.Create2 {
		t.Fatal(f, err)
	}
	select {
	case err := <-sent:
		t.Fatal("batch acknowledged before its last cell", err)
	default:
	}
	if f, err := codec.Read(b); err != nil || f.Command != cell.Destroy {
		t.Fatal(f, err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if n := <-wire.sizes; n != 2*514 || len(wire.sizes) != 0 {
		t.Fatal("batch was split into separate writes", n)
	}
}

func TestPartialBatchFailureClosesChannel(t *testing.T) {
	c, peer := runtimePair(t, 2)
	id, _ := c.AllocateCircuitID()
	sent := make(chan error, 1)
	go func() {
		sent <- c.SendBatch(context.Background(), []cell.Cell{
			{CircuitID: id, Command: cell.Create2}, {CircuitID: id, Command: cell.Destroy},
		})
	}()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(peer, make([]byte, 515)); err != nil {
		t.Fatal(err)
	}
	peer.Close()
	if err := <-sent; err == nil {
		t.Fatal("partial batch succeeded")
	}
	waitClosed(t, c)
}

func TestLeaseBatchCancellationPreservesOrderingAndSibling(t *testing.T) {
	p := NewPool(context.Background(), nil)
	defer p.Close()
	var peer net.Conn
	codec, _ := cell.NewCodec(4)
	p.dial = func(ctx context.Context, _ Target, o Options) (*Channel, error) {
		a, b := net.Pipe()
		peer = b
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
	if err := a.SendBatch(context.Background(), []cell.Cell{{CircuitID: aid, Command: cell.Create2}, {CircuitID: bid, Command: cell.Destroy}}); !errors.Is(err, ErrProtocol) {
		t.Fatal("cross-lease batch accepted", err)
	}
	sent := make(chan error, 1)
	go func() {
		sent <- a.SendBatch(context.Background(), []cell.Cell{
			{CircuitID: aid, Command: cell.Create2}, {CircuitID: aid, Command: cell.Relay, Payload: make([]byte, cell.PayloadSize)},
		})
	}()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(peer, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { a.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("lease close blocked on batch")
	}
	if err := <-sent; err == nil || b.Err() != nil || b.shared.ch.Err() != nil {
		t.Fatal("batch cancellation failed isolation", err)
	}
	if _, err := io.ReadFull(peer, make([]byte, 513)); err != nil {
		t.Fatal(err)
	}
	for _, command := range []cell.Command{cell.Relay, cell.Destroy} {
		if f, err := codec.Read(peer); err != nil || f.CircuitID != aid || f.Command != command {
			t.Fatal("batch/DESTROY order changed", f, err)
		}
	}
	go func() { sent <- b.Send(context.Background(), cell.Cell{CircuitID: bid, Command: cell.Create2}) }()
	if f, err := codec.Read(peer); err != nil || f.CircuitID != bid {
		t.Fatal(f, err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}
