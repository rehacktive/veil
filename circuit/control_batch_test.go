package circuit

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"veil/cell"
	"veil/channel"
	"veil/directory"
)

type batchNetwork struct {
	*testNetwork
	counts    []int
	failAfter int
}

func (b *batchNetwork) SendBatch(ctx context.Context, frames []cell.Cell) error {
	b.counts = append(b.counts, len(frames))
	for i, f := range frames {
		if b.failAfter > 0 && i == b.failAfter {
			return errors.New("fixture: partial batch")
		}
		if err := b.Send(ctx, f); err != nil {
			return err
		}
	}
	return nil
}

func controlBatchFixture(t *testing.T) (*streamMux, *batchNetwork, *[]cell.RelayMessage) {
	t.Helper()
	n := &batchNetwork{testNetwork: network(t)}
	var received []cell.RelayMessage
	n.stream = func(msg cell.RelayMessage, hop int) error {
		if hop != 2 {
			return errors.New("wrong control hop")
		}
		received = append(received, msg)
		return nil
	}
	c, err := buildHops(context.Background(), n.hops, &testAttempt{usable: directory.GuardUsable}, time.Second,
		func(context.Context, channel.Target, channel.Options) (transport, error) { return n, nil }, func() bool { return true }, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return newStreamMux(c), n, &received
}

func TestControlBatchBoundsOrderAndRetiredACKFiltering(t *testing.T) {
	m, n, received := controlBatchFixture(t)
	m.streams[3] = &streamConn{id: 3}
	first := cell.RelayMessage{Command: cell.RelaySendme, Data: []byte{1, 0, 20}}
	m.control(cell.RelaySendme, 2, nil) // Retired stream; skip only this ACK.
	m.control(cell.RelaySendme, 3, nil)
	for i := 0; i < channel.MaxBatchCells; i++ {
		m.control(cell.RelayEnd, uint16(i+4), []byte{1})
	}
	if err := m.sendControls(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if len(n.counts) != 1 || n.counts[0] != channel.MaxBatchCells-1 || len(m.controls) != 3 {
		t.Fatal("batch bound/filter", n.counts, len(m.controls))
	}
	if (*received)[0].StreamID != 0 || (*received)[1].StreamID != 3 {
		t.Fatal("control order changed", *received)
	}
	if err := m.sendControls(context.Background(), <-m.controls); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(n.counts, []int{15, 3}) {
		t.Fatal(n.counts)
	}
	for i, msg := range (*received)[2:] {
		if msg.Command != cell.RelayEnd || msg.StreamID != uint16(i+4) {
			t.Fatal("encrypted control order/digest changed", i, msg)
		}
	}
	if err := m.sendControls(context.Background(), cell.RelayMessage{Command: cell.RelaySendme, StreamID: 2}); err != nil || len(n.counts) != 2 {
		t.Fatal("all-stale batch wrote bytes", err)
	}
}

func TestControlBatchCancellationAndPartialFailure(t *testing.T) {
	m, n, received := controlBatchFixture(t)
	first := cell.RelayMessage{Command: cell.RelayEnd, StreamID: 1, Data: []byte{1}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	early := m.c.early
	if err := m.sendControls(ctx, first); !errors.Is(err, context.Canceled) || len(n.counts) != 0 || m.c.early != early || m.c.Err() != nil {
		t.Fatal("pre-queue cancellation changed cipher/channel state", err)
	}
	if err := m.sendControls(context.Background(), first); err != nil || len(*received) != 1 {
		t.Fatal("single control did not flush", err)
	}
	n.failAfter = 1
	m.control(cell.RelayEnd, 2, []byte{1})
	if err := m.sendControls(context.Background(), first); err == nil || m.c.Err() == nil {
		t.Fatal("indeterminate encrypted batch left circuit usable", err)
	}
}
