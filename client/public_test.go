package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
	"veil/directory"
	"veil/socks5"
)

// Opt-in: VEIL_PUBLIC_STATE=/absolute/private/state go test -race ./client
// -run '^TestPublicSOCKSReuse$' -v -timeout=12m. Sends HTTP to Tor Project's
// published onion and HTTPS to its Tor checker; preserves persistent guards.
func TestPublicSOCKSReuse(t *testing.T) {
	state := os.Getenv("VEIL_PUBLIC_STATE")
	if state == "" {
		t.Skip("set VEIL_PUBLIC_STATE for public Tor interoperability")
	}
	lock, err := directory.LockState(state)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	roots, sources, err := directory.Mainnet()
	if err != nil {
		t.Fatal(err)
	}
	cache, err := directory.NewCache(state, roots)
	if err != nil {
		t.Fatal(err)
	}
	guards, err := directory.NewGuardStore(state)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := directory.NewManager(cache, guards, sources, directory.ManagerOptions{Attempts: 8, AttemptTimeout: 3 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	life, cancel := context.WithCancel(context.Background())
	defer cancel()
	managed := make(chan struct{})
	var managerErr error
	go func() { managerErr = manager.Run(life); close(managed) }()
	defer func() {
		cancel()
		<-managed
		if managerErr != nil && !errors.Is(managerErr, context.Canceled) {
			t.Error(managerErr)
		}
	}()
	startup, stop := context.WithTimeout(life, 10*time.Minute)
	defer stop()
	for {
		if _, err := manager.Snapshot(); err == nil {
			break
		}
		select {
		case <-managed:
			t.Fatal("directory manager stopped", managerErr)
		case <-startup.Done():
			t.Fatal(startup.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	d, err := New(life, manager, guards, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	listener, err := socks5.Listen(life, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, stopServer := context.WithCancel(life)
	served := make(chan error, 1)
	go func() {
		served <- socks5.Serve(serveCtx, listener, func(ctx context.Context, network, address string) (net.Conn, error) {
			c, err := d.DialContext(ctx, network, address)
			if err != nil {
				t.Logf("native dial failed: %v; cause: %v", err, errors.Unwrap(err))
			}
			return c, err
		}, socks5.Options{})
	}()
	defer func() { stopServer(); <-served }()
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
		return dialTestSOCKS(ctx, listener.Addr().String(), address)
	}}
	defer transport.CloseIdleConnections()
	browser := &http.Client{Transport: transport, Timeout: 3 * time.Minute}
	const host = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
	get := func(url, contains string) error {
		response, err := browser.Get(url)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
		if err != nil {
			return err
		}
		if response.StatusCode != 200 || !bytes.Contains(body, []byte(contains)) {
			return fmt.Errorf("unexpected HTTP response: status=%d bytes=%d", response.StatusCode, len(body))
		}
		return nil
	}
	url := "http://" + host + "/index.html"
	if err := get(url, "Tor Project"); err != nil {
		t.Fatal(err)
	}
	entry := func() *pooledCircuit {
		d.pool.mu.Lock()
		defer d.pool.mu.Unlock()
		for e := range d.pool.entries {
			if e.key.host == host && !e.retired {
				return e
			}
		}
		return nil
	}
	original := entry()
	if original == nil {
		t.Fatal("SOCKS tokens did not enable pooling")
	}
	for wave := 0; wave < 2; wave++ {
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := get(url, "Tor Project"); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if entry() != original {
			t.Fatal("parallel requests replaced service circuit")
		}
	}
	d.descriptors.mu.Lock()
	records := len(d.descriptors.records)
	d.descriptors.mu.Unlock()
	if records != 1 {
		t.Fatal("expected one scoped service descriptor", records)
	}
	d.pool.mu.Lock()
	original.created = time.Now().Add(-11 * time.Minute)
	d.pool.mu.Unlock()
	if err := get(url, "Tor Project"); err != nil {
		t.Fatal(err)
	}
	if entry() == original {
		t.Fatal("aged service circuit reused")
	}
	if err := get("https://check.torproject.org/api/ip", `"IsTor":true`); err != nil {
		t.Fatal(err)
	}
	t.Log("10 onion HTTP requests passed: 9 reused one service circuit, rotation built a replacement; HTTPS checker confirms IsTor=true")
}

func dialTestSOCKS(ctx context.Context, proxy, address string) (_ net.Conn, result error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || len(host) > 255 {
		return nil, errors.New("invalid test destination")
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			c.Close()
		}
	}()
	deadline := time.Now().Add(3 * time.Minute)
	if at, ok := ctx.Deadline(); ok && at.Before(deadline) {
		deadline = at
	}
	c.SetDeadline(deadline)
	exchange := func(send, want []byte) error {
		if _, err := c.Write(send); err != nil {
			return err
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(c, got); err != nil {
			return err
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("unexpected SOCKS reply %x", got)
		}
		return nil
	}
	if err := exchange([]byte{5, 1, 2}, []byte{5, 2}); err != nil {
		return nil, err
	}
	if err := exchange([]byte{1, 4, 'v', 'e', 'i', 'l', 4, 't', 'e', 's', 't'}, []byte{1, 0}); err != nil {
		return nil, err
	}
	request := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	request = binary.BigEndian.AppendUint16(request, uint16(number))
	if err := exchange(request, []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return c, nil
}
