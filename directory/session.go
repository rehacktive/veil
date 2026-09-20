package directory

import (
	"context"
	"errors"
	"sync"
	"time"

	"veil/cell"
	"veil/channel"
)

// Session reuses one authenticated channel, with a fresh one-hop circuit for
// each sequential HTTP request. A failure or request cancellation closes the
// connection; subsequent requests may reconnect. Close cancels active I/O.
// No requests are retried internally and no application streams are exposed.
type Session struct {
	source  TorSource
	ctx     context.Context
	cancel  context.CancelFunc
	gate    chan struct{}
	mu      sync.Mutex
	ch      *channel.Channel
	retired map[uint32]bool
	// Invoked after ntor authentication and before BEGIN_DIR. Installed by Manager
	// to report guard success and enforce non-primary guard usability.
	onCircuit func(context.Context) error
	dial      func(context.Context, channel.Target, channel.Options) (*channel.Channel, error)
}

func (s TorSource) Open(ctx context.Context) *Session {
	ctx, cancel := context.WithCancel(ctx)
	return &Session{source: s, ctx: ctx, cancel: cancel, gate: make(chan struct{}, 1), retired: map[uint32]bool{}, dial: channel.Dial}
}
func (s *Session) Close() error {
	s.cancel()
	s.mu.Lock()
	ch := s.ch
	s.ch = nil
	s.mu.Unlock()
	if ch != nil {
		return ch.Close()
	}
	return nil
}
func (s *Session) discard() {
	s.mu.Lock()
	ch := s.ch
	s.ch = nil
	s.mu.Unlock()
	if ch != nil {
		_ = ch.Close() // Channel.Close is idempotent and always returns nil.
	}
	s.retired = map[uint32]bool{}
}
func (s *Session) Fetch(ctx context.Context, path string, limit int) (b []byte, err error) {
	if err := validateRequest(path, limit); err != nil {
		return nil, err
	}
	timeout := s.source.Timeout
	if timeout == 0 {
		timeout = time.Minute
	}
	if timeout < 0 {
		return nil, errors.New("invalid directory timeout")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case s.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
	defer func() { <-s.gate }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	ch := s.ch
	s.mu.Unlock()
	if ch != nil && (ch.Err() != nil || len(s.retired) >= 256) {
		s.discard()
		ch = nil
	}
	if ch == nil {
		// The dial must stop if this request is canceled, while the successful
		// channel retains the session's lifetime rather than the request's deadline.
		lifetime, stop := context.WithCancel(s.ctx)
		stopRequest := context.AfterFunc(ctx, stop)
		ch, err = s.dial(lifetime, s.source.Target, channel.Options{})
		stopped := stopRequest()
		if err != nil || !stopped || ctx.Err() != nil {
			stop()
			if ch != nil {
				_ = ch.Close() // Preserve the dial/cancellation error.
			}
			if err != nil {
				return nil, err
			}
			return nil, ctx.Err()
		}
		s.mu.Lock()
		if s.ctx.Err() != nil {
			s.mu.Unlock()
			stop()
			_ = ch.Close() // Preserve cancellation.
			return nil, s.ctx.Err()
		}
		s.ch = ch
		s.mu.Unlock()
		// Channel close terminates the small derived lifetime context too.
		go func() { <-ch.Done(); stop() }()
	}
	defer func() {
		if err != nil {
			s.discard()
		}
	}()
	id, err := ch.AllocateCircuitID()
	if err != nil {
		return nil, err
	}
	filtered := &sessionChannel{ch: ch, retired: s.retired}
	b, err = fetchCircuit(ctx, filtered, id, s.source, path, limit, s.onCircuit)
	if err != nil {
		return nil, err
	}
	if err = ch.Send(ctx, cell.Cell{Command: cell.Destroy, CircuitID: id, Payload: []byte{0}}); err != nil {
		return nil, err
	}
	s.retired[id] = true
	return b, nil
}

type sessionChannel struct {
	ch      cellChannel
	retired map[uint32]bool
}

func (s *sessionChannel) Send(ctx context.Context, c cell.Cell) error { return s.ch.Send(ctx, c) }
func (s *sessionChannel) Receive(ctx context.Context) (cell.Cell, error) {
	for n := 0; n < 128; n++ {
		c, err := s.ch.Receive(ctx)
		if err != nil {
			return c, err
		}
		if !s.retired[c.CircuitID] {
			return c, nil
		}
	}
	return cell.Cell{}, errors.New("excess cells for retired directory circuits")
}
