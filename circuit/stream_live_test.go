package circuit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"veil/channel"
	"veil/directory"
)

func TestLocalTorStreams(t *testing.T) {
	port, err := strconv.ParseUint(os.Getenv("VEIL_TEST_STREAM_PORT"), 10, 16)
	if err != nil || port == 0 {
		t.Skip("requires scripts/check_local_directory.py --stream-test")
	}
	hops := localTestHops(t)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	c, err := build(ctx, hops, &testAttempt{usable: directory.GuardUsable}, 15*time.Second, func(ctx context.Context, target channel.Target, opts channel.Options) (transport, error) {
		return channel.Dial(ctx, target, opts)
	}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Test-only explicit hops cannot satisfy production subnet/exit summaries.
	// The script permits only this private fixture port on the loopback exit.
	c.port = uint16(port)
	address := net.JoinHostPort("veil.test", strconv.FormatUint(port, 10))
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		s, err := c.DialContext(ctx, "tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer s.Close()
			s.SetDeadline(time.Now().Add(30 * time.Second))
			data := bytes.Repeat([]byte{byte(i + 1)}, 2*1024*1024)
			done := make(chan error, 1)
			go func() { _, err := s.Write(append([]byte{'E'}, data...)); done <- err }()
			got := make([]byte, len(data))
			_, err := io.ReadFull(s, got)
			if err != nil {
				t.Error("large transfer", err)
			} else if !bytes.Equal(data, got) {
				t.Error("corrupt data")
			}
			if err := <-done; err != nil {
				t.Error("large write", err)
			}
		}(i)
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	// END must preserve the already received tail and translate DONE to EOF.
	s, err := c.DialContext(ctx, "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	s.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = s.Write([]byte{'F'}); err != nil {
		t.Fatal(err)
	}
	tail, err := io.ReadAll(s)
	s.Close()
	if err != nil || string(tail) != "tail" {
		t.Fatal("EOF", string(tail), err)
	}
	// DNS is answered only by the exit's private resolver fixture.
	_, err = c.DialContext(ctx, "tcp", net.JoinHostPort("missing.test", strconv.FormatUint(port, 10)))
	var remote *StreamError
	if !errors.As(err, &remote) || remote.Reason != 2 {
		t.Fatal("expected exit DNS failure", err)
	}
	canceled, stop := context.WithTimeout(ctx, 200*time.Millisecond)
	_, err = c.DialContext(canceled, "tcp", net.JoinHostPort("stall.test", strconv.FormatUint(port, 10)))
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("pending DNS cancellation", err)
	}
	// An address outside the single allowed exit destination must be rejected.
	_, err = c.DialContext(ctx, "tcp", "127.0.0.2:"+strconv.FormatUint(port, 10))
	if !errors.As(err, &remote) || remote.Reason != 4 {
		t.Fatal("expected exit-policy failure", err)
	}
	s, err = c.DialContext(ctx, "tcp", address)
	if err != nil {
		t.Fatal("circuit after stream failures", err)
	}
	s.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
	if _, err = s.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("read deadline", err)
	}
	s.SetReadDeadline(time.Time{})
	blocked := make(chan error, 1)
	go func() { _, err := s.Read(make([]byte, 1)); blocked <- err }()
	c.Close()
	select {
	case err := <-blocked:
		if err == nil {
			t.Fatal("closed circuit read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("circuit close did not unblock stream")
	}
	s.Close()
	fmt.Println("native Tor streams: four concurrent 2 MiB round trips; exit DNS, EOF, DNS/policy failures, cancellation and deadlines verified")
}
