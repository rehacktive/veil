package client

import (
	"context"
	"errors"
	"testing"
	"time"
	"veil/circuit"
	"veil/directory"
	"veil/isolation"
	"veil/socks5"
)

func TestOnionOnlyRejectsBeforeNetworkPoolAndCapacity(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		d, err := newDialer(context.Background(), nil, Options{OnionOnly: true, MaxCircuits: 1}, func(context.Context, *directory.Snapshot, circuit.Options) (streamCircuit, error) {
			t.Error("exit builder called")
			return nil, errors.New("unexpected build")
		})
		if err != nil {
			t.Fatal(err)
		}
		// A full connection budget and an existing exit circuit must not bypass or
		// delay policy rejection. A nil source also detects directory access.
		d.slots <- struct{}{}
		ctx := context.Background()
		if scoped {
			ctx = isolation.WithToken(ctx, "session")
		}
		scope, _ := isolation.Scope(ctx)
		life, cancel := context.WithCancel(context.Background())
		e := &pooledCircuit{key: poolKey{scope: scope, host: "example.com", port: 443}, c: &echoCircuit{}, life: life, cancel: cancel, created: time.Now(), idle: time.Now()}
		d.pool.entries[e] = struct{}{}
		for _, address := range []string{"example.com:443", "EXAMPLE.COM.:443", "127.0.0.1:80", "1.1.1.1:443", "[::1]:80", "[::ffff:127.0.0.1]:80", "invalid.onion:80", "abcdefghijklmnop.onion:80", "valid.onion.evil:80", "onion:80"} {
			for _, network := range []string{"tcp", "tcp4", "tcp6"} {
				request, stop := context.WithTimeout(ctx, 100*time.Millisecond)
				conn, err := d.DialContext(request, network, address)
				stop()
				var reply *socks5.ReplyError
				if conn != nil || !errors.Is(err, ErrOnionOnly) || !errors.As(err, &reply) || reply.Code != 2 {
					t.Fatalf("%s %s: %v", network, address, err)
				}
			}
		}
		if e.c.(*echoCircuit).opens.Load() != 0 || len(d.slots) != 1 {
			t.Fatal("blocked request touched pool or capacity")
		}
		<-d.slots
		d.Close()
	}
}
func TestOnionOnlyAllowsValidServicesAndReuse(t *testing.T) {
	const host = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
	for _, token := range []string{"", "session"} {
		d, f := poolDialer(t, Options{OnionOnly: true})
		d.build = func(context.Context, *directory.Snapshot, circuit.Options) (streamCircuit, error) {
			t.Error("exit builder called")
			return nil, errors.New("unexpected exit")
		}
		d.onionBuild = func(life, setup context.Context, name string, port uint16) (streamCircuit, error) {
			return f.build(life, nil, circuit.Options{})
		}
		a := connectPool(t, d, token, "tcp", host+":80")
		roundTrip(t, a, []byte("onion-only"))
		a.Close()
		b := connectPool(t, d, token, "tcp6", host+".:80")
		b.Close()
		want := 2
		if token != "" {
			want = 1
		}
		if f.count() != want {
			t.Fatal("onion routing/reuse changed", f.count())
		}
	}
}
