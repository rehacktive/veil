package client

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
	"veil/circuit"
	"veil/onion"
)

func TestOnionAttemptTimeoutAllowsRecoveryAndKeepsSuccessfulLifetime(t *testing.T) {
	life, cancel := context.WithCancel(context.Background())
	defer cancel()
	setup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	var failedLife context.Context
	_, err := onionAttempt(life, setup, 15*time.Millisecond, func(l, s context.Context) (streamCircuit, error) {
		failedLife = l
		<-s.Done()
		return nil, s.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) || !retryableBuild(err) || failedLife.Err() == nil || setup.Err() != nil {
		t.Fatalf("failed attempt did not release its budget: %v", err)
	}
	var successfulLife, successfulSetup context.Context
	c, err := onionAttempt(life, setup, 15*time.Millisecond, func(l, s context.Context) (streamCircuit, error) {
		successfulLife, successfulSetup = l, s
		return &fakeCircuit{ctx: l}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if successfulSetup.Err() == nil || successfulLife.Err() != nil {
		t.Fatal("setup cancellation killed successful circuit")
	}
	stop()
	if successfulLife.Err() != nil {
		t.Fatal("outer setup owns established circuit")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if successfulLife.Err() == nil {
		t.Fatal("close leaked circuit lifetime")
	}
}

func TestOnionAttemptRejectsLateSuccessAndCleansUp(t *testing.T) {
	var c *fakeCircuit
	_, err := onionAttempt(context.Background(), context.Background(), time.Millisecond, func(l, s context.Context) (streamCircuit, error) {
		<-s.Done()
		c = &fakeCircuit{ctx: l}
		return c, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || c.closed.Load() != 1 || c.ctx.Err() == nil {
		t.Fatal("late success leaked", err)
	}
}

func TestOnionAttemptPreservesCancellationAndAuthenticationFailures(t *testing.T) {
	for _, failure := range []error{context.Canceled, onion.ErrAuthentication, circuit.ErrProtocol} {
		_, err := onionAttempt(context.Background(), context.Background(), time.Second, func(l, s context.Context) (streamCircuit, error) { return nil, failure })
		if !errors.Is(err, failure) || retryableBuild(err) {
			t.Fatal("terminal failure became retryable", err)
		}
	}
}

func TestIntroductionRejectionRetryClassification(t *testing.T) {
	for _, status := range []uint16{1, 2, 3, 65535} {
		err := fmt.Errorf("introduction exchange: %w", errors.Join(&circuit.IntroductionError{Status: status}, nil))
		if retryableBuild(err) != (status == 1) {
			t.Fatalf("wrong retry policy for status %d", status)
		}
	}
	if retryableBuild(errors.Join(&circuit.IntroductionError{Status: 1}, onion.ErrAuthentication)) {
		t.Fatal("joined authentication error ignored")
	}
}

func TestOnionAttemptBuildCancellationIsRetryableOnlyForLocalDeadline(t *testing.T) {
	for _, authenticationFailure := range []bool{false, true} {
		_, err := onionAttempt(context.Background(), context.Background(), time.Millisecond, func(l, s context.Context) (streamCircuit, error) {
			<-l.Done()
			if authenticationFailure {
				return nil, errors.Join(l.Err(), onion.ErrAuthentication)
			}
			return nil, fmt.Errorf("building circuit: %w", l.Err())
		})
		if authenticationFailure {
			if !errors.Is(err, onion.ErrAuthentication) || retryableBuild(err) {
				t.Fatal("masked authentication error", err)
			}
		} else if !errors.Is(err, context.DeadlineExceeded) || !retryableBuild(err) {
			t.Fatal("local deadline became terminal cancellation", err)
		}
	}
}
