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
	"veil/directory"
	"veil/internal/diagnostics"
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
		diagnostics.Log(setup, d.options.Logger, "circuit_build", "attempt", attempt+1, "port", options.Port, "ipv6", options.IPv6)
		c, err := d.build(attemptLife, snapshot, options)
		if err == nil {
			diagnostics.Log(setup, d.options.Logger, "circuit_ready", "attempt", attempt+1)
			d.logExit(setup, c)
			// Parent cancellation/ownedConn.Close owns the successful attempt.
			return &attemptCircuit{streamCircuit: c, cancel: cancel}, nil
		}
		cancel()
		diagnostics.Log(setup, d.options.Logger, "circuit_build_failed", "attempt", attempt+1, "error", err)
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
		diagnostics.Log(setup, d.options.Logger, "circuit_retry", "next_attempt", attempt+2)
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
		case 4, 5, 6, 8, 9, 10, 11: // HIBERNATING, RESOURCELIMIT, CONNECTFAILED, CHANNEL_CLOSED, FINISHED, TIMEOUT, DESTROYED.
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

func (c *attemptCircuit) Err() error { return circuitError(c.streamCircuit) }

func (d *Dialer) logExit(ctx context.Context, c streamCircuit) {
	if d.options.Logger == nil {
		return
	}
	if wrapped, ok := c.(*attemptCircuit); ok {
		c = wrapped.streamCircuit
	}
	if routed, ok := c.(interface{ Path() directory.Path }); ok {
		exit := routed.Path().Exit
		diagnostics.Log(ctx, d.options.Logger, "exit_relay", "nickname", exit.Nickname(), "address", exit.Address().String(), "identity", exit.Identity().String())
	}
}
