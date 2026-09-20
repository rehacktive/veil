package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func destination(host string, port uint16) []byte {
	b := append([]byte{5, 1, 0, 3, byte(len(host))}, []byte(host)...)
	return binary.BigEndian.AppendUint16(b, port)
}

func TestOnionConnectAndBudget(t *testing.T) {
	const host = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
	called := make(chan string, 1)
	local, _, _ := startHandler(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		deadline, _ := ctx.Deadline()
		if time.Until(deadline) < 30*time.Second {
			t.Error("ordinary timeout used for onion")
		}
		called <- address
		return nil, &ReplyError{Code: 4, Err: errors.New("test service unavailable")}
	}, Options{ConnectTimeout: time.Second, OnionTimeout: time.Minute})
	exchange(t, local, []byte{5, 1, 0}, []byte{5, 0})
	exchange(t, local, destination(host, 80), []byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
	if got := <-called; got != host+":80" {
		t.Fatal(got)
	}
}
func exchange(t *testing.T, c net.Conn, send, want []byte) {
	t.Helper()
	if _, err := c.Write(send); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x: %v", got, want, err)
	}
}
func startHandler(t *testing.T, dial DialFunc, o Options) (net.Conn, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	a, b := net.Pipe()
	done := make(chan struct{})
	opts, err := o.defaults()
	if err != nil {
		t.Fatal(err)
	}
	go func() { handle(ctx, b, dial, opts); close(done) }()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() {
		cancel()
		a.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("handler leaked")
		}
	})
	return a, cancel, done
}
func TestConnectPreservesHostnameAndPipelinedBytes(t *testing.T) {
	for _, auth := range []bool{false, true} {
		called := make(chan string, 1)
		local, _, _ := startHandler(t, func(ctx context.Context, network, address string) (net.Conn, error) {
			called <- network + " " + address
			a, b := net.Pipe()
			go func() {
				defer b.Close()
				payload := make([]byte, 10000)
				if _, err := io.ReadFull(b, payload); err == nil {
					_, _ = b.Write(payload)
				}
			}()
			return a, nil
		}, Options{})
		if auth {
			exchange(t, local, []byte{5, 2, 0, 2}, []byte{5, 2})
			exchange(t, local, []byte{1, 3, 'u', 's', 'r', 3, 'p', 'w', 'd'}, []byte{1, 0})
		} else {
			exchange(t, local, []byte{5, 1, 0}, []byte{5, 0})
		}
		payload := bytes.Repeat([]byte("x"), 10000)
		sent := make(chan error, 1)
		go func() { _, err := local.Write(append(destination("EXAMPLE.INVALID", 443), payload...)); sent <- err }()
		reply := make([]byte, 10)
		if _, err := io.ReadFull(local, reply); err != nil || reply[1] != 0 {
			t.Fatal(reply, err)
		}
		if got := <-called; got != "tcp4 example.invalid:443" {
			t.Fatal(got)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(local, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatal("relay", err)
		}
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
	}
}
func TestRequests(t *testing.T) {
	for _, tc := range []struct {
		b                []byte
		network, address string
		code             byte
	}{
		{[]byte{5, 1, 0, 1, 1, 2, 3, 4, 0, 80}, "tcp4", "1.2.3.4:80", 0},
		{append([]byte{5, 1, 0, 4}, append(net.ParseIP("2001:db8::1").To16(), 0, 80)...), "tcp6", "[2001:db8::1]:80", 0},
		{destination("veil.test", 80), "tcp4", "veil.test:80", 0},
		{[]byte{5, 3, 0, 1}, "", "", 7}, {[]byte{5, 2, 0, 1}, "", "", 7},
		{[]byte{5, 1, 0, 9}, "", "", 8}, {[]byte{5, 1, 1, 1}, "", "", 1},
		{destination("x\x00.test", 80), "", "", 4}, {destination("x.onion", 80), "", "", 4},
		{destination("x.test", 0), "", "", 1}, {[]byte{5, 1, 0, 1, 1}, "", "", 1},
	} {
		network, address, code, err := request(bytes.NewReader(tc.b))
		if code != tc.code || (err == nil) != (tc.code == 0) || err == nil && (network != tc.network || address != tc.address) {
			t.Fatal(tc, network, address, code, err)
		}
	}
}
func TestFailureRepliesNoFallback(t *testing.T) {
	for _, code := range []byte{1, 2, 3, 4, 5, 6, 7, 8, 255} {
		var calls atomic.Int32
		conn, _, _ := startHandler(t, func(context.Context, string, string) (net.Conn, error) {
			calls.Add(1)
			return nil, &ReplyError{Code: code, Err: errors.New("failure")}
		}, Options{})
		exchange(t, conn, []byte{5, 1, 0}, []byte{5, 0})
		want := code
		if want > 8 {
			want = 1
		}
		exchange(t, conn, destination("missing.test", 80), []byte{5, want, 0, 1, 0, 0, 0, 0, 0, 0})
		if calls.Load() != 1 {
			t.Fatal("retried/fell back")
		}
	}
}
func TestUnsupportedAndMalformedHandshake(t *testing.T) {
	for _, greeting := range [][]byte{{5, 1, 1}, {5, 1, 255}, {4, 1, 0}, {5, 0}} {
		conn, _, done := startHandler(t, func(context.Context, string, string) (net.Conn, error) {
			t.Error("dialed malformed request")
			return nil, errors.New("no")
		}, Options{})
		_, _ = conn.Write(greeting) // A bad version may be rejected before all bytes are read.
		got, _ := io.ReadAll(conn)
		if greeting[0] == 5 && greeting[1] > 0 && !bytes.Equal(got, []byte{5, 255}) {
			t.Fatal(got)
		}
		<-done
	}
}
func TestCancellationAndTimeouts(t *testing.T) {
	for _, stage := range []string{"handshake", "connect", "transfer", "idle", "lifetime"} {
		t.Run(stage, func(t *testing.T) {
			o := Options{HandshakeTimeout: 30 * time.Millisecond, ConnectTimeout: 30 * time.Millisecond, IdleTimeout: 30 * time.Millisecond, MaxLifetime: time.Second}
			if stage == "lifetime" {
				o.MaxLifetime = 40 * time.Millisecond
				o.IdleTimeout = time.Second
			}
			entered := make(chan struct{}, 1)
			conn, cancel, done := startHandler(t, func(ctx context.Context, _ string, _ string) (net.Conn, error) {
				entered <- struct{}{}
				if stage == "connect" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				a, b := net.Pipe()
				go func() { defer b.Close(); _, _ = io.Copy(io.Discard, b) }()
				return a, nil
			}, o)
			if stage != "handshake" {
				exchange(t, conn, []byte{5, 1, 0}, []byte{5, 0})
				if stage == "connect" {
					exchange(t, conn, destination("x.test", 80), []byte{5, 6, 0, 1, 0, 0, 0, 0, 0, 0})
				} else {
					exchange(t, conn, destination("x.test", 80), []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				}
				<-entered
			}
			if stage == "transfer" {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("did not stop")
			}
		})
	}
}
func TestListenAndServeLimits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, address := range []string{"0.0.0.0:9050", "[::]:9050", "192.0.2.1:9050", "localhost:9050"} {
		if _, err := Listen(ctx, address); err == nil {
			t.Fatal(address)
		}
	}
	l, err := Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, l, func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("no") }, Options{MaxConnections: 1})
	}()
	a, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	// Receiving the greeting reply proves the first handler owns the only slot.
	exchange(t, a, []byte{5, 1, 0}, []byte{5, 0})
	b, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = b.Read(make([]byte, 1)); err == nil {
		t.Fatal("accepted excess client")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve leaked")
	}
}
func FuzzRequest(f *testing.F) {
	f.Add(destination("veil.test", 80))
	f.Add([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1024 {
			return
		}
		network, address, code, err := request(bytes.NewReader(b))
		if err == nil {
			if code != 0 || !strings.HasPrefix(network, "tcp") || address == "" {
				t.Fatal("invalid success")
			}
		}
	})
}
