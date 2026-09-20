package circuit

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"veil/channel"
	"veil/directory"
	"veil/socks5"
)

// Test-only explicit localhost hops: never exported or linked into bin/veil.
// This harness runs the production SOCKS server and native circuit/stream code.
func TestLocalTorProxyDemo(t *testing.T) {
	if os.Getenv("VEIL_TEST_PROXY_DEMO") != "1" {
		t.Skip("requires make proxy-demo")
	}
	port, err := strconv.ParseUint(os.Getenv("VEIL_TEST_STREAM_PORT"), 10, 16)
	if err != nil || port == 0 {
		t.Fatal("invalid local fixture port")
	}
	hops := localTestHops(t)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	listener, err := socks5.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	dial := func(request context.Context, network, address string) (net.Conn, error) {
		life, release := context.WithCancel(ctx)
		stop := context.AfterFunc(request, release)
		success := false
		defer func() {
			stop()
			if !success {
				release()
			}
		}()
		c, err := build(life, hops, &testAttempt{usable: directory.GuardUsable}, 15*time.Second, func(ctx context.Context, target channel.Target, o channel.Options) (transport, error) {
			return channel.Dial(ctx, target, o)
		}, func() bool { return true })
		if err != nil {
			return nil, err
		}
		c.port = uint16(port)
		conn, err := c.DialContext(request, network, address)
		if err != nil {
			c.Close()
			return nil, err
		}
		if !stop() || request.Err() != nil {
			conn.Close()
			c.Close()
			return nil, request.Err()
		}
		success = true
		return &proxyTestConn{Conn: conn, c: c, cancel: release}, nil
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"event": "proxy_demo_ready", "listen": listener.Addr().String(), "url": "http://veil.test:" + strconv.FormatUint(port, 10) + "/"}); err != nil {
		t.Fatal(err)
	}
	if err := socks5.Serve(ctx, listener, dial, socks5.Options{MaxConnections: 8, ConnectTimeout: 20 * time.Second}); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type proxyTestConn struct {
	net.Conn
	c      *Circuit
	cancel context.CancelFunc
	once   sync.Once
}

func (c *proxyTestConn) Close() error {
	c.once.Do(func() { c.Conn.Close(); c.c.Close(); c.cancel() })
	return nil
}
