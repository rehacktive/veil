package client

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"veil/circuit"
	"veil/directory"
	"veil/socks5"
)

type source struct{ err error }

func (s source) Snapshot() (*directory.Snapshot, error) { return &directory.Snapshot{}, s.err }

type fakeCircuit struct {
	ctx    context.Context
	closed atomic.Int32
	remote net.Conn
	fail   error
}

func (c *fakeCircuit) DialContext(context.Context, string, string) (net.Conn, error) {
	if c.fail != nil {
		return nil, c.fail
	}
	a, b := net.Pipe()
	c.remote = b
	return a, nil
}
func (c *fakeCircuit) Close() error {
	c.closed.Add(1)
	if c.remote != nil {
		return c.remote.Close()
	}
	return nil
}
func TestDedicatedCircuitOwnership(t *testing.T) {
	life, cancelLife := context.WithCancel(context.Background())
	defer cancelLife()
	var circuits []*fakeCircuit
	d, err := newDialer(life, source{}, Options{MaxCircuits: 1}, func(ctx context.Context, _ *directory.Snapshot, o circuit.Options) (streamCircuit, error) {
		if o.Port != 443 || o.IPv6 {
			t.Fatal(o)
		}
		c := &fakeCircuit{ctx: ctx}
		circuits = append(circuits, c)
		return c, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := d.DialContext(ctx, "tcp4", "example.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if circuits[0].ctx.Err() != nil {
		t.Fatal("dial cancellation killed established circuit")
	}
	blocked, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if _, err = d.DialContext(blocked, "tcp4", "other.invalid:443"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	stop()
	conn.Close()
	conn.Close()
	if circuits[0].closed.Load() != 1 || circuits[0].ctx.Err() == nil {
		t.Fatal("circuit leaked")
	}
	second, err := d.DialContext(context.Background(), "tcp4", "other.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if len(circuits) != 2 {
		t.Fatal("reused circuit")
	}
	cancelLife()
	if circuits[1].ctx.Err() == nil {
		t.Fatal("lifetime ignored")
	}
}
func TestDialFailureCleanup(t *testing.T) {
	for _, where := range []string{"directory", "build", "stream", "cancel"} {
		var c *fakeCircuit
		src := source{}
		if where == "directory" {
			src.err = directory.ErrTime
		}
		d, _ := newDialer(context.Background(), src, Options{}, func(ctx context.Context, _ *directory.Snapshot, _ circuit.Options) (streamCircuit, error) {
			if where == "build" {
				return nil, errors.New("build failed")
			}
			if where == "cancel" {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			c = &fakeCircuit{ctx: ctx, fail: &circuit.StreamError{Reason: 2}}
			return c, nil
		})
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		conn, err := d.DialContext(ctx, "tcp4", "x.invalid:443")
		cancel()
		if conn != nil || err == nil {
			t.Fatal(where, err)
		}
		if len(d.slots) != 0 {
			t.Fatal("slot leaked")
		}
		if c != nil && (c.closed.Load() != 1 || c.ctx.Err() == nil) {
			t.Fatal("failed circuit leaked")
		}
	}
}
func TestSOCKSFailureMapping(t *testing.T) {
	for reason, code := range map[byte]byte{2: 4, 4: 2, 5: 5, 7: 6, 8: 3, 9: 3, 1: 1} {
		var reply *socks5.ReplyError
		if !errors.As(replyError(&circuit.StreamError{Reason: reason}), &reply) || reply.Code != code {
			t.Fatal(reason, reply)
		}
	}
}
