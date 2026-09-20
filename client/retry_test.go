package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"veil/cell"
	"veil/channel"
	"veil/circuit"
	"veil/directory"
	"veil/ntor"
	"veil/relaycrypto"
	"veil/torcert"
)

func TestBuildRetryClassification(t *testing.T) {
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, context.DeadlineExceeded, os.ErrDeadlineExceeded,
		&net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}},
		errors.Join(io.EOF, syscall.ECONNRESET)} {
		if !retryableBuild(fmt.Errorf("build: %w", err)) {
			t.Fatal("lost transient failure", err)
		}
	}
	for _, err := range []error{nil, context.Canceled, directory.ErrTrust, directory.ErrTime, directory.ErrDocument,
		directory.ErrState, directory.ErrPath, directory.ErrUnsupported, directory.ErrStateLocked,
		ntor.ErrAuthentication, torcert.ErrCertificate, relaycrypto.ErrUnrecognized,
		circuit.ErrProtocol, channel.ErrProtocol, cell.ErrInvalid, errors.New("unknown"),
		errors.Join(io.EOF, directory.ErrState), &circuit.StreamError{Reason: 6}} {
		if retryableBuild(err) {
			t.Fatal("retried terminal error", err)
		}
	}
	for reason := byte(0); reason < 16; reason++ {
		want := reason == 4 || reason == 5 || reason == 6 || reason == 8 || reason == 9 || reason == 10
		if retryableBuild(&circuit.RemoteError{Hop: 0, Reason: reason}) != want {
			t.Fatal(reason)
		}
	}
}

type countingSource struct {
	calls  int
	failAt int
}

func (s *countingSource) Snapshot() (*directory.Snapshot, error) {
	s.calls++
	if s.calls == s.failAt {
		return nil, directory.ErrTime
	}
	return &directory.Snapshot{}, nil
}

func TestBuildRetrySuccessAndOwnership(t *testing.T) {
	s := &countingSource{}
	var attempts []context.Context
	var successful *fakeCircuit
	d, err := newDialer(context.Background(), s, Options{MaxCircuits: 1, ConnectTimeout: 30 * time.Millisecond}, func(ctx context.Context, _ *directory.Snapshot, o circuit.Options) (streamCircuit, error) {
		if len(attempts) > 0 && attempts[len(attempts)-1].Err() == nil {
			t.Fatal("failed attempt still alive")
		}
		attempts = append(attempts, ctx)
		if o.BuildTimeout != 20*time.Second {
			t.Fatal(o)
		}
		if len(attempts) < 3 {
			return nil, &circuit.RemoteError{Hop: 0, Reason: 6}
		}
		successful = &fakeCircuit{ctx: ctx}
		return successful, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	waits := 0
	d.wait = func(_ context.Context, base time.Duration) error {
		waits++
		if len(d.slots) != 1 || base != 250*time.Millisecond*time.Duration(1<<(waits-1)) {
			t.Fatal("lost slot or backoff", base)
		}
		return nil
	}
	conn, err := d.DialContext(context.Background(), "tcp", "example.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if s.calls != 3 || waits != 2 {
		t.Fatal("incorrect attempt budget", s.calls, waits)
	}
	// The setup deadline is detached once CONNECT succeeds.
	select {
	case <-successful.ctx.Done():
		t.Fatal("setup deadline killed an established connection")
	case <-time.After(60 * time.Millisecond):
	}
	conn.Close()
	if successful.closed.Load() != 1 || len(d.slots) != 0 || successful.ctx.Err() == nil {
		t.Fatal("ownership leaked")
	}
}

func TestBuildRetryBoundsAndDirectoryRecheck(t *testing.T) {
	for _, failDirectory := range []bool{false, true} {
		s := &countingSource{}
		if failDirectory {
			s.failAt = 2
		}
		calls := 0
		d, _ := newDialer(context.Background(), s, Options{BuildAttempts: 3}, func(ctx context.Context, _ *directory.Snapshot, _ circuit.Options) (streamCircuit, error) {
			calls++
			return nil, io.EOF
		})
		d.wait = func(context.Context, time.Duration) error { return nil }
		_, err := d.DialContext(context.Background(), "tcp", "example.invalid:443")
		if failDirectory {
			if calls != 1 || !errors.Is(err, directory.ErrTime) {
				t.Fatal(calls, err)
			}
		} else if calls != 3 || !errors.Is(err, io.EOF) {
			t.Fatal(calls, err)
		}
		if len(d.slots) != 0 {
			t.Fatal("slot leaked")
		}
	}
	for _, options := range []Options{{BuildAttempts: -1}, {BuildAttempts: 6}, {ConnectTimeout: -1}, {BuildTimeout: -1}} {
		if _, err := newDialer(context.Background(), source{}, options, nil); err == nil {
			t.Fatal(options)
		}
	}
}

func TestBuildRetriesStopAtCancellationAndTotalDeadline(t *testing.T) {
	for _, stage := range []string{"build", "backoff", "shutdown"} {
		t.Run(stage, func(t *testing.T) {
			life, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int32
			d, _ := newDialer(life, source{}, Options{ConnectTimeout: 20 * time.Millisecond}, func(ctx context.Context, _ *directory.Snapshot, _ circuit.Options) (streamCircuit, error) {
				calls.Add(1)
				if stage == "build" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return nil, io.EOF
			})
			if stage == "shutdown" {
				d.wait = func(ctx context.Context, _ time.Duration) error { cancel(); <-ctx.Done(); return ctx.Err() }
			}
			_, err := d.DialContext(context.Background(), "tcp", "example.invalid:443")
			want := context.DeadlineExceeded
			if stage == "shutdown" {
				want = context.Canceled
			}
			if !errors.Is(err, want) || calls.Load() != 1 || len(d.slots) != 0 {
				t.Fatal(calls.Load(), err)
			}
		})
	}
}

func TestNoRetryAfterStreamOpen(t *testing.T) {
	for _, failure := range []error{io.EOF, &circuit.StreamError{Reason: 6}, context.DeadlineExceeded} {
		calls := 0
		c := &fakeCircuit{fail: failure}
		d, _ := newDialer(context.Background(), source{}, Options{}, func(ctx context.Context, _ *directory.Snapshot, _ circuit.Options) (streamCircuit, error) {
			calls++
			c.ctx = ctx
			return c, nil
		})
		d.wait = func(context.Context, time.Duration) error { t.Fatal("retried destination stream"); return nil }
		_, err := d.DialContext(context.Background(), "tcp", "example.invalid:443")
		if !errors.Is(err, failure) || calls != 1 || c.closed.Load() != 1 || len(d.slots) != 0 {
			t.Fatal(calls, err)
		}
	}
}
