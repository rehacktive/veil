package channel

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
	"veil/cell"
)

func paddedPair(t *testing.T, p *PaddingOptions) (*Channel, net.Conn, *cell.Codec) {
	t.Helper()
	a, b := net.Pipe()
	codec, _ := cell.NewCodec(5)
	c := newPaddedChannel(context.Background(), a, a, codec, Info{LinkVersion: 5}, 2, p)
	t.Cleanup(func() { c.Close(); b.Close() })
	b.SetDeadline(time.Now().Add(2 * time.Second))
	return c, b, codec
}

func expectNegotiation(t *testing.T, peer net.Conn, codec *cell.Codec, command byte) {
	t.Helper()
	f, err := codec.Read(peer)
	if err != nil {
		t.Fatal(err)
	}
	if f.Command != cell.PaddingNegotiate || f.CircuitID != 0 || len(f.Payload) != cell.PayloadSize || f.Payload[0] != 0 || f.Payload[1] != command {
		t.Fatal("wrong negotiation", f)
	}
	for _, b := range f.Payload[2:] {
		if b != 0 {
			t.Fatal("negotiation leaked local parameters")
		}
	}
}
func expectIdle(t *testing.T, peer net.Conn, codec *cell.Codec) {
	t.Helper()
	peer.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, err := codec.Read(peer)
	var e net.Error
	if !errors.As(err, &e) || !e.Timeout() {
		t.Fatalf("expected idle link: %v", err)
	}
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
}

func TestLinkPaddingActivationAndDisable(t *testing.T) {
	t.Run("deferred", func(t *testing.T) {
		c, peer, codec := paddedPair(t, &PaddingOptions{Low: 40 * time.Millisecond, High: 40 * time.Millisecond})
		expectNegotiation(t, peer, codec, 2)
		expectIdle(t, peer, codec)
		c.MarkUsed()
		f, err := codec.Read(peer)
		if err != nil || f.Command != cell.Padding || f.CircuitID != 0 {
			t.Fatal(f, err)
		}
	})
	t.Run("disabled", func(t *testing.T) {
		c, peer, codec := paddedPair(t, &PaddingOptions{})
		expectNegotiation(t, peer, codec, 1)
		c.MarkUsed()
		expectIdle(t, peer, codec)
	})
	t.Run("directory bootstrap", func(t *testing.T) {
		c, peer, codec := paddedPair(t, nil)
		c.MarkUsed()
		expectIdle(t, peer, codec)
	})
}

func TestLinkPaddingOutboundResetAndInboundIndependence(t *testing.T) {
	c, peer, codec := paddedPair(t, &PaddingOptions{Low: 80 * time.Millisecond, High: 80 * time.Millisecond, BeforeUsage: true})
	expectNegotiation(t, peer, codec, 2)
	// An outbound application cell resets the existing idle interval.
	time.Sleep(50 * time.Millisecond)
	id, _ := c.AllocateCircuitID()
	sent := make(chan error, 1)
	go func() { sent <- c.Send(context.Background(), cell.Cell{Command: cell.Destroy, CircuitID: id}) }()
	f, err := codec.Read(peer)
	if err != nil || f.Command != cell.Destroy {
		t.Fatal(f, err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	expectIdle(t, peer, codec)
	// Continuously received padding cannot suppress our own outgoing padding.
	incomingDone := make(chan struct{})
	go func() {
		defer close(incomingDone)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-c.Done():
				return
			case <-ticker.C:
				if codec.Write(peer, cell.Cell{Command: cell.Padding}) != nil {
					return
				}
			}
		}
	}()
	f, err = codec.Read(peer)
	if err != nil || f.Command != cell.Padding {
		t.Fatal(f, err)
	}
	c.Close()
	<-incomingDone
}

func TestPaddingCloseUnblocksIdleWrite(t *testing.T) {
	c, peer, codec := paddedPair(t, &PaddingOptions{Low: time.Millisecond, High: time.Millisecond, BeforeUsage: true})
	expectNegotiation(t, peer, codec, 2)
	// Stop consuming output: the timer's padding write blocks on the peer.
	time.Sleep(10 * time.Millisecond)
	closed := make(chan struct{})
	go func() { c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("blocked padding leaked writer")
	}
}

func TestPaddingDistributionAndOptionBounds(t *testing.T) {
	p := PaddingOptions{Low: 1500 * time.Millisecond, High: 9500 * time.Millisecond}
	var sum time.Duration
	const samples = 20000
	for range samples {
		d, err := p.delay()
		if err != nil || d < p.Low || d >= p.High {
			t.Fatal(d, err)
		}
		sum += d - p.Low
	}
	// max(X,X) has mean 2/3 of the interval; a uniform sampler is measurably wrong.
	ratio := float64(sum) / float64(samples) / float64(p.High-p.Low)
	if ratio < 0.63 || ratio > 0.70 {
		t.Fatal("wrong idle distribution", ratio)
	}
	for _, p := range []PaddingOptions{{Low: -1}, {Low: time.Second}, {High: time.Minute + 1}} {
		if _, err := (Options{Padding: &p}).normalized(); err == nil {
			t.Fatal("accepted invalid padding", p)
		}
	}
}

func TestLivePaddingPolicyDisableResumeAndExpiry(t *testing.T) {
	policy := &PaddingPolicy{}
	policy.Update(PaddingOptions{Low: time.Minute, High: time.Minute, BeforeUsage: true}, time.Now().Add(time.Hour), time.Hour)
	a, b := net.Pipe()
	codec, _ := cell.NewCodec(5)
	c := newPaddedChannel(context.Background(), a, a, codec, Info{LinkVersion: 5}, 2, nil, policy)
	defer c.Close()
	defer b.Close()
	b.SetDeadline(time.Now().Add(3 * time.Second))
	expectNegotiation(t, b, codec, 2)
	policy.Update(PaddingOptions{}, time.Now().Add(time.Hour), time.Hour)
	expectNegotiation(t, b, codec, 1)
	expectIdle(t, b, codec)
	// MarkUsed while disabled must persist across a live policy replacement.
	c.MarkUsed()
	policy.Update(PaddingOptions{Low: 40 * time.Millisecond, High: 40 * time.Millisecond}, time.Now().Add(time.Hour), time.Hour)
	expectNegotiation(t, b, codec, 2)
	if f, err := codec.Read(b); err != nil || f.Command != cell.Padding {
		t.Fatal(f, err)
	}
	policy.Update(PaddingOptions{Low: time.Minute, High: time.Minute}, time.Now().Add(120*time.Millisecond), time.Hour)
	// An already in-flight padding cell may finish before the update is applied.
	for j := 0; j < 3; j++ {
		f, err := codec.Read(b)
		if err != nil {
			t.Fatal(err)
		}
		if f.Command == cell.PaddingNegotiate && f.Payload[1] == 1 {
			break
		}
		if f.Command != cell.Padding || j == 2 {
			t.Fatal("expired policy did not stop padding", f)
		}
	}
	expectIdle(t, b, codec)
	if c.Err() != nil {
		t.Fatal("policy expiry closed active transport", c.Err())
	}
}

func TestLivePolicyCoalescingAndBounds(t *testing.T) {
	p := &PaddingPolicy{}
	_, _, _, first := p.current()
	expires := time.Now().Add(time.Hour)
	for j := 0; j < 1000; j++ {
		p.Update(PaddingOptions{Low: time.Duration(j) * time.Millisecond, High: time.Minute}, expires, time.Hour)
	}
	select {
	case <-first:
	default:
		t.Fatal("subscriber not notified")
	}
	value, _, _, latest := p.current()
	if value.Low != 999*time.Millisecond {
		t.Fatal(value)
	}
	p.Update(value, expires, time.Hour)
	select {
	case <-latest:
		t.Fatal("unchanged policy woke subscribers")
	default:
	}
	p.Update(PaddingOptions{Low: -time.Second, High: 2 * time.Minute}, expires, 48*time.Hour)
	value, _, idle, _ := p.current()
	if value.Low != 0 || value.High != time.Minute || idle != 24*time.Hour {
		t.Fatal(value, idle)
	}
}
