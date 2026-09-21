//go:build veiltest

package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"veil/circuit"
	"veil/directory"
)

func TestLocalTorHosting(t *testing.T) {
	for _, mode := range []string{"forward", "listener"} {
		t.Run(mode, func(t *testing.T) { testLocalTorHosting(t, mode == "listener") })
	}
}

func testLocalTorHosting(t *testing.T, listen bool) {
	config := os.Getenv("VEIL_TEST_HOST_CONFIG")
	if config == "" {
		t.Skip("requires private hosting harness")
	}
	state := os.Getenv("VEIL_TEST_HOST_STATE")
	lock, err := directory.LockState(state)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	raw, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Authorities []string
		Relay       struct{ Address, RSA, Ed25519, NTor string }
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	root, err := directory.ParseFingerprint(cfg.Authorities[0])
	if err != nil {
		t.Fatal(err)
	}
	cache, err := directory.NewCache(state, []directory.Fingerprint{root})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := cache.Load(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var pins []struct{ RSA, Ed25519 string }
	if err := json.Unmarshal([]byte(os.Getenv("VEIL_TEST_CIRCUIT_PEERS")), &pins); err != nil {
		t.Fatal(err)
	}
	var relays []directory.Relay
	for _, pin := range pins {
		rsa, err := directory.ParseFingerprint(pin.RSA)
		if err != nil {
			t.Fatal(err)
		}
		b, err := hex.DecodeString(pin.Ed25519)
		if err != nil {
			t.Fatal(err)
		}
		var ed [32]byte
		copy(ed[:], b)
		r, err := snapshot.RelayByIdentity(rsa, ed)
		if err != nil {
			t.Fatal(err)
		}
		relays = append(relays, r)
	}
	guards, err := directory.NewGuardStore(state)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := directory.NewManager(cache, guards, []directory.TorSource{{Target: relays[2].Target(), OnionKey: relays[2].NTor().OnionKey}}, directory.ManagerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Distinct identities prevent the C Tor client reusing a cached descriptor
	// from the other mode after its introduction circuits have been closed.
	identityState := filepath.Join(state, "forward-identity")
	if listen {
		identityState = filepath.Join(state, "listener-identity")
	}
	identityLock, err := directory.LockState(identityState)
	if err != nil {
		t.Fatal(err)
	}
	defer identityLock.Close()
	identity, err := directory.OpenServiceIdentity(identityState)
	if err != nil {
		t.Fatal(err)
	}
	name, err := identity.Address()
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("Veil onion hosting works!\n"), 90000)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/large" {
			_, _ = w.Write(payload)
		} else {
			_, _ = io.WriteString(w, "Veil onion hosting works!\n")
		}
	})
	options := Options{Port: 80, Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	if !listen {
		backend := httptest.NewServer(handler)
		defer backend.Close()
		options.Target = strings.TrimPrefix(backend.URL, "http://")
	}
	h, err := newHost(manager, guards, identity, options, listen)
	if err != nil {
		t.Fatal(err)
	}
	h.selectIntro = func(s *directory.Snapshot, excluded []directory.Fingerprint) (directory.Relay, error) {
		for _, r := range relays {
			found := false
			for _, id := range excluded {
				if id == r.Identity() {
					found = true
				}
			}
			if !found {
				return r, nil
			}
		}
		return directory.Relay{}, directory.ErrPath
	}
	h.build = func(ctx context.Context, s *directory.Snapshot, target *directory.Relay, p circuit.OnionPurpose) (*circuit.Circuit, error) {
		if target == nil {
			t.Error("missing target")
			return nil, circuit.ErrProtocol
		}
		var hops [3]directory.Relay
		n := 0
		for _, r := range relays {
			if r.Identity() != target.Identity() && n < 2 {
				hops[n] = r
				n++
			}
		}
		hops[2] = *target
		return circuit.BuildLocalServiceTest(ctx, hops, p)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	directoryDone := make(chan error, 1)
	go func() { directoryDone <- manager.Run(ctx) }()
	defer func() { cancel(); <-directoryDone }()
	for {
		if _, err := manager.Snapshot(); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	done := make(chan error, 1)
	if listen {
		listener := startListener(ctx, h, onionAddr(name+":80"))
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
		go func() { done <- server.Serve(listener) }()
		defer func() { server.Close(); cancel(); <-listener.Done() }()
	} else {
		go func() { done <- h.Run(ctx) }()
	}
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("hosting workers leaked")
		}
	}()
	address := "http://" + name
	var data []byte
	for j := 0; j < 6; j++ {
		cmd := exec.CommandContext(ctx, "curl", "--fail", "--silent", "--show-error", "--max-time", "20", "--noproxy", "", "--socks5-hostname", os.Getenv("VEIL_TEST_HOST_SOCKS"), address)
		data, err = cmd.Output()
		if err == nil {
			break
		}
		t.Log("waiting for service publication/client bootstrap", err)
		select {
		case err := <-done:
			done <- err
			t.Fatal("host stopped", err)
		case <-time.After(time.Second):
		}
	}
	if err != nil || !bytes.Equal(data, []byte("Veil onion hosting works!\n")) {
		t.Fatal("onion HTTP failed", err, string(data))
	}
	cmd := exec.CommandContext(ctx, "curl", "--fail", "--silent", "--show-error", "--max-time", "30", "--noproxy", "", "--socks5-hostname", os.Getenv("VEIL_TEST_HOST_SOCKS"), address+"/large")
	data, err = cmd.Output()
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatal("bulk transfer failed", err, len(data))
	}
	var parallel sync.WaitGroup
	for j := 0; j < 4; j++ {
		parallel.Add(1)
		go func(j int) {
			defer parallel.Done()
			cmd := exec.CommandContext(ctx, "curl", "--fail", "--silent", "--show-error", "--max-time", "30", "--noproxy", "", "--socks5-hostname", os.Getenv("VEIL_TEST_HOST_SOCKS"), "--proxy-user", fmt.Sprintf("test:%d", j), address+"/large")
			got, err := cmd.Output()
			if err != nil || !bytes.Equal(got, payload) {
				t.Errorf("parallel transfer %d failed: %v, %d bytes", j, err, len(got))
			}
		}(j)
	}
	parallel.Wait()
	denied := exec.CommandContext(ctx, "curl", "--fail", "--silent", "--show-error", "--max-time", "10", "--noproxy", "", "--socks5-hostname", os.Getenv("VEIL_TEST_HOST_SOCKS"), address+":81/")
	if err := denied.Run(); err == nil {
		t.Fatal("unmapped virtual port accepted")
	}
	t.Logf("C Tor client -> native Veil service: HTTP, five %d-byte downloads (four concurrent), and unmapped-port rejection passed", len(data))
}
