package directory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"veil/cell"
	"veil/channel"
)

func TestSessionCanceledQueueAndDial(t *testing.T) {
	t.Run("canceled queue", func(t *testing.T) {
		s := (TorSource{}).Open(context.Background())
		defer s.Close()
		s.gate <- struct{}{}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := s.Fetch(ctx, "/tor/keys/all", 100); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		<-s.gate
	})
	t.Run("cancel dial", func(t *testing.T) {
		s := (TorSource{}).Open(context.Background())
		defer s.Close()
		started := make(chan struct{})
		s.dial = func(ctx context.Context, _ channel.Target, _ channel.Options) (*channel.Channel, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := s.Fetch(ctx, "/tor/keys/all", 100); done <- err }()
		<-started
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("dial did not cancel")
		}
	})
	t.Run("close active dial", func(t *testing.T) {
		s := (TorSource{}).Open(context.Background())
		started := make(chan struct{})
		s.dial = func(ctx context.Context, _ channel.Target, _ channel.Options) (*channel.Channel, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		done := make(chan error, 1)
		go func() { _, err := s.Fetch(context.Background(), "/tor/keys/all", 100); done <- err }()
		<-started
		s.Close()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("close did not cancel")
		}
		if _, err := s.Fetch(context.Background(), "/tor/keys/all", 100); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("concurrent close", func(t *testing.T) {
		s := (TorSource{}).Open(context.Background())
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); s.Close() }()
		}
		wg.Wait()
	})
}
func TestRetiredCircuitFiltering(t *testing.T) {
	old := uint32(0x80000001)
	current := uint32(0x80000002)
	ch := &fakeCircuit{frames: []cell.Cell{{CircuitID: old, Command: cell.Relay}, {CircuitID: old, Command: cell.Destroy}, {CircuitID: current, Command: cell.Created2}}}
	filtered := &sessionChannel{ch: ch, retired: map[uint32]bool{old: true}}
	frame, err := filtered.Receive(context.Background())
	if err != nil || frame.CircuitID != current {
		t.Fatal(frame, err)
	}
	for i := 0; i < 128; i++ {
		ch.frames = append(ch.frames, cell.Cell{CircuitID: old, Command: cell.Relay})
	}
	if _, err := filtered.Receive(context.Background()); err == nil {
		t.Fatal("unbounded retired cell flood")
	}
}
