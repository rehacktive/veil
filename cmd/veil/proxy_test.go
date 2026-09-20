package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"veil/internal/diagnostics"

	"veil/directory"
	"veil/socks5"
)

type fakeProxyDirectory struct {
	ready   atomic.Bool
	failure chan error
	stopped chan struct{}
}

func (m *fakeProxyDirectory) Snapshot() (*directory.Snapshot, error) {
	if m.ready.Load() {
		return &directory.Snapshot{}, nil
	}
	return nil, directory.ErrTime
}
func (m *fakeProxyDirectory) Run(ctx context.Context) error {
	defer close(m.stopped)
	select {
	case err := <-m.failure:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

type readyWriter chan []byte

func (w readyWriter) Write(b []byte) (int, error) { w <- bytes.Clone(b); return len(b), nil }

func TestProxyCLIFlags(t *testing.T) {
	for _, args := range [][]string{
		{"proxy"}, {"proxy", "extra"}, {"proxy", "-bogus"},
		{"proxy", "-public"},
		{"proxy", "-public", "-config", "missing", "-state", "state"},
		{"proxy", "-public", "-state", "state", "-bootstrap-timeout", "0"},
		{"proxy", "-public", "-state", "state", "-build-timeout", "0"},
		{"proxy", "-public", "-state", "state", "-onion-timeout", "0"},
		{"proxy", "-public", "-state", "state", "-circuit-max-age", "0"},
		{"proxy", "-public", "-state", "state", "-circuit-idle-timeout", "-1s"},
		{"proxy", "-public", "-state", "state", "-max-pooled-circuits", "0"},
		{"proxy", "-public", "-state", "state", "-max-pooled-circuits", "257"},
		{"proxy", "-public", "-state", "state", "-build-attempts", "0"},
		{"proxy", "-public", "-state", "state", "-build-attempts", "6"},
		{"proxy", "-config", "missing", "-state", "state", "-connect-timeout", "0"},
		{"proxy", "-config", "missing", "-state", "state", "-idle-timeout", "-1s"},
		{"proxy", "-config", "missing", "-state", "state", "-max-connections", "257"},
		{"proxy", "-config", "missing", "-state", "state", "-listen", "0.0.0.0:9050"},
	} {
		if err := run(args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatal(args)
		}
	}
	if err := run([]string{"proxy", "-onion-only", "-debug", "-h"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
}
func TestProxyDirectoryLifecycle(t *testing.T) {
	for _, stage := range []string{"startup-timeout", "startup-failure", "live-failure", "shutdown", "onion-only"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			listener, err := socks5.Listen(ctx, "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			m := &fakeProxyDirectory{failure: make(chan error, 1), stopped: make(chan struct{})}
			if stage != "startup-timeout" && stage != "startup-failure" {
				m.ready.Store(true)
			}
			if stage == "startup-failure" {
				m.failure <- directory.ErrTrust
			}
			ready := make(readyWriter, 64)
			logger := slog.New(slog.NewJSONHandler(ready, &slog.HandlerOptions{Level: slog.LevelDebug}))
			done := make(chan error, 1)
			go func() {
				done <- serveProxy(ctx, listener, m, func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("test dial failure") }, 30*time.Millisecond, socks5.Options{Logger: logger, OnionOnly: stage == "onion-only"})
			}()
			if stage == "live-failure" || stage == "shutdown" || stage == "onion-only" {
				var status map[string]string
				select {
				case raw := <-ready:
					if err := json.Unmarshal(raw, &status); err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("never became ready")
				}
				if status["msg"] != "socks5_ready" {
					t.Fatal(status)
				}
				wantMode := "all"
				if stage == "onion-only" {
					wantMode = "onion-only"
				}
				if status["mode"] != wantMode {
					t.Fatal("wrong readiness mode", status)
				}
				conn, err := net.Dial("tcp", status["listen"])
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				if _, err = conn.Write([]byte{5, 1, 0}); err != nil {
					t.Fatal(err)
				}
				reply := make([]byte, 2)
				if _, err = io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, []byte{5, 0}) {
					t.Fatal(reply, err)
				}
				if stage == "live-failure" {
					m.failure <- directory.ErrTrust
				} else {
					cancel()
				}
			}
			select {
			case err := <-done:
				if (stage == "shutdown" || stage == "onion-only") && err != nil {
					t.Fatal(err)
				}
				if strings.HasSuffix(stage, "failure") && err == nil {
					t.Fatal("ignored failure")
				}
				if stage == "startup-timeout" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("proxy did not stop")
			}
			select {
			case <-m.stopped:
			default:
				t.Fatal("directory goroutine leaked")
			}
		})
	}
}

func TestProxyQuietByDefault(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := socks5.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &fakeProxyDirectory{failure: make(chan error, 1), stopped: make(chan struct{})}
	m.ready.Store(true)
	var logs bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- serveProxy(ctx, listener, m, func(context.Context, string, string) (net.Conn, error) {
			t.Error("blocked destination reached dialer")
			return nil, errors.New("unexpected dial")
		}, time.Second, socks5.Options{OnionOnly: true, Logger: diagnostics.New(false, &logs)})
	}()
	c, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(c, greeting[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{5, 1, 0, 1, 1, 1, 1, 1, 0, 80}); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil || reply[1] != 2 {
		t.Fatal(reply, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy did not stop")
	}
	if logs.Len() != 0 {
		t.Fatal("quiet proxy produced logs", logs.String())
	}
}

func TestProxyDebugFlagIsPerInvocation(t *testing.T) {
	for _, flag := range []string{"-debug", "-debug=false", ""} {
		var out, logs bytes.Buffer
		args := []string{"-public", "-state", t.TempDir(), "-listen", "0.0.0.0:9050"}
		if flag != "" {
			args = append(args, flag)
		}
		// Listener validation fails before accessing state or the network.
		if err := proxy(context.Background(), args, &out, &logs); err == nil {
			t.Fatal("invalid listener accepted")
		}
		if out.Len() != 0 {
			t.Fatal("proxy wrote to stdout")
		}
		if flag == "-debug" {
			if !strings.Contains(logs.String(), "proxy_starting") || !strings.Contains(logs.String(), "proxy_stopped") {
				t.Fatal(logs.String())
			}
		} else if logs.Len() != 0 {
			t.Fatal("logging remained enabled", logs.String())
		}
	}
}
