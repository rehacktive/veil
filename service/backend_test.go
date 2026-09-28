package service

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"veil/directory"
)

func TestForwardLocalBackends(t *testing.T) {
	for _, network := range []string{"tcp", "unix"} {
		t.Run(network, func(t *testing.T) {
			if network == "unix" && runtime.GOOS == "windows" {
				t.Skip("Unix socket fixture")
			}
			address := "127.0.0.1:0"
			if network == "unix" {
				// Keep below sockaddr_un's path limit, including on macOS.
				dir, err := os.MkdirTemp("", "veil-sock-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.RemoveAll(dir) })
				address = filepath.Join(dir, "backend.sock")
			}
			backend, err := net.Listen(network, address)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { backend.Close() })
			if err := backend.(interface{ SetDeadline(time.Time) error }).SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			target := backend.Addr().String()
			if network == "unix" {
				target = "unix:" + address
			}
			h, err := New(&directory.Manager{}, &directory.GuardStore{}, &directory.ServiceIdentity{}, Options{Port: 80, Target: target})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			server, peer := net.Pipe()
			defer peer.Close()
			peer.SetDeadline(time.Now().Add(3 * time.Second))
			ready, done := make(chan struct{}), make(chan struct{})
			go func() { defer close(done); h.forward(ctx, pipeRequest{server, ready}) }()
			local, err := backend.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer local.Close()
			local.SetDeadline(time.Now().Add(3 * time.Second))
			select {
			case <-ready:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			for _, pair := range [][2]net.Conn{{peer, local}, {local, peer}} {
				written := make(chan error, 1)
				go func() { _, err := io.WriteString(pair[0], "request and response"); written <- err }()
				b := make([]byte, len("request and response"))
				if _, err := io.ReadFull(pair[1], b); err != nil || string(b) != "request and response" {
					t.Fatal(string(b), err)
				}
				if err := <-written; err != nil {
					t.Fatal(err)
				}
			}
			cancel()
			waitListener(t, done)
			// A missing backend must reject the stream, never accept it or fall
			// back to another transport. Closing the listener removes its socket.
			backend.Close()
			server2, peer2 := net.Pipe()
			defer peer2.Close()
			ready2 := make(chan struct{})
			ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
			defer cancel2()
			h.forward(ctx2, pipeRequest{server2, ready2})
			select {
			case <-ready2:
				t.Fatal("missing backend accepted")
			default:
			}
			if network == "unix" {
				// Never delete or replace a non-socket file occupying the path.
				if err := os.WriteFile(address, []byte("keep me"), 0600); err != nil {
					t.Fatal(err)
				}
				server3, peer3 := net.Pipe()
				defer peer3.Close()
				ready3 := make(chan struct{})
				h.forward(ctx2, pipeRequest{server3, ready3})
				select {
				case <-ready3:
					t.Fatal("regular file accepted as backend")
				default:
				}
				if contents, err := os.ReadFile(address); err != nil || string(contents) != "keep me" {
					t.Fatal("backend file changed", err)
				}
			}
		})
	}
}
