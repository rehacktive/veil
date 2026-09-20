package client

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"os"
	"syscall"
	"time"

	"veil/circuit"
)

// A retry re-enters the normal verified selector with the SAME GuardStore.
// It never supplies exclusions, resets guard reachability, or replays BEGIN.
func (d *Dialer) buildCircuit(life, setup context.Context, options circuit.Options) (streamCircuit, error) {
	for attempt := 0; ; attempt++ {
		if err := setup.Err(); err != nil {
			return nil, err
		}
		if err := life.Err(); err != nil {
			return nil, err
		}
		snapshot, err := d.source.Snapshot()
		if err != nil {
			return nil, err
		}
		attemptLife, cancel := context.WithCancel(life)
		c, err := d.build(attemptLife, snapshot, options)
		if err == nil {
			// Parent cancellation/ownedConn.Close owns the successful attempt.
			return &attemptCircuit{streamCircuit: c, cancel: cancel}, nil
		}
		cancel()
		if c != nil {
			err = errors.Join(err, c.Close())
		}
		if setup.Err() != nil {
			return nil, setup.Err()
		}
		if life.Err() != nil {
			return nil, life.Err()
		}
		if attempt+1 >= d.options.BuildAttempts || !retryableBuild(err) {
			return nil, err
		}
		base := min(250*time.Millisecond*time.Duration(1<<attempt), time.Second)
		if err := d.wait(life, base); err != nil {
			if setup.Err() != nil {
				return nil, setup.Err()
			}
			return nil, err
		}
	}
}

type attemptCircuit struct {
	streamCircuit
	cancel context.CancelFunc
}

func (c *attemptCircuit) Close() error {
	defer c.cancel()
	return c.streamCircuit.Close()
}

// Allow only known transport failures. Every leaf of a joined error must be
// retryable so a simultaneous local state/cleanup failure cannot be hidden.
// Unknown errors, protocol/authentication failures and directory/guard errors
// are terminal. In particular ErrPath must not reset an exhausted guard sample.
func retryableBuild(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !retryableBuild(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return retryableBuild(wrapped.Unwrap())
	}
	if remote, ok := err.(*circuit.RemoteError); ok {
		switch remote.Reason {
		case 4, 5, 6, 8, 9, 10: // HIBERNATING, RESOURCELIMIT, CONNECTFAILED, CHANNEL_CLOSED, FINISHED, TIMEOUT.
			return true
		}
		return false
	}
	switch err {
	case io.EOF, io.ErrUnexpectedEOF, context.DeadlineExceeded, os.ErrDeadlineExceeded,
		syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ECONNABORTED,
		syscall.ETIMEDOUT, syscall.EHOSTUNREACH, syscall.ENETUNREACH,
		syscall.ENETDOWN, syscall.EPIPE:
		return true
	}
	return false
}

func waitBuildRetry(ctx context.Context, base time.Duration) error {
	jitter, err := rand.Int(rand.Reader, big.NewInt(int64(base)))
	if err != nil {
		return err
	}
	timer := time.NewTimer(base + time.Duration(jitter.Int64()))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
