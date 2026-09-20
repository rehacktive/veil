package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
	if err := run([]string{"proxy", "-h"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
}
func TestProxyDirectoryLifecycle(t *testing.T) {
	for _, stage := range []string{"startup-timeout", "startup-failure", "output-failure", "live-failure", "shutdown"} {
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
			ready := make(readyWriter, 1)
			var out io.Writer = ready
			if stage == "output-failure" {
				out = failingWriter{}
			}
			done := make(chan error, 1)
			go func() {
				done <- serveProxy(ctx, listener, m, func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("test dial failure") }, 30*time.Millisecond, socks5.Options{}, out)
			}()
			if stage == "live-failure" || stage == "shutdown" {
				var status map[string]string
				select {
				case raw := <-ready:
					if err := json.Unmarshal(raw, &status); err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("never became ready")
				}
				if status["event"] != "socks5_ready" {
					t.Fatal(status)
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
				if stage == "shutdown" && err != nil {
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
