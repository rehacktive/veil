package circuit

import (
	"context"
	"errors"
	"testing"
	"time"
	"veil/cell"
	"veil/directory"
)

func TestFourHopOnionAllowsEntryAsEndpoint(t *testing.T) {
	n := network(t, 4)
	n.hops[3], n.secrets[3] = n.hops[0], n.secrets[0]
	a := &testAttempt{usable: directory.GuardUsable}
	c, err := buildHops(context.Background(), n.hops, a, time.Second, n.dial, func() bool { return true }, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.relayEnd != 3 || c.endHop.Load() != 3 || a.success != 1 {
		t.Fatal("fourth relay not authenticated")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := c.Send(ctx, 3, cell.RelayMessage{Command: cell.RelayData, StreamID: 1, Data: []byte("four authenticated layers")}); err != nil {
		t.Fatal(err)
	}
	reply, err := c.Receive(ctx)
	if err != nil || reply.Hop != 3 || string(reply.Data) != "four authenticated layers" {
		t.Fatal(reply, err)
	}
}

func TestVanguardPathRejectsShortLoopsBeforeDial(t *testing.T) {
	for _, scenario := range []struct {
		i, j  int
		onion bool
	}{{1, 0, true}, {2, 0, true}, {3, 1, true}, {3, 0, false}} {
		n := network(t, 4)
		n.hops[scenario.i] = n.hops[scenario.j]
		a := &testAttempt{usable: directory.GuardUsable}
		_, err := buildHops(context.Background(), n.hops, a, time.Second, n.dial, func() bool { return true }, scenario.onion)
		if !errors.Is(err, ErrProtocol) || len(n.writes) != 0 || a.failure != 0 || a.closed != 1 {
			t.Fatal("invalid path dialed or penalized guard", scenario, err)
		}
	}
}
