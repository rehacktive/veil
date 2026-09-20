package directory

import (
	"crypto/rand"
	"errors"
	"math/big"
	"time"
)

// randomDuration returns a cryptographically random duration in [0, bound).
func randomDuration(bound time.Duration) (time.Duration, error) {
	if bound <= 0 {
		return 0, errors.New("invalid random interval")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(bound)))
	if err != nil {
		return 0, err
	}
	return time.Duration(n.Int64()), nil
}
func randomizedDate(now time.Time, spread time.Duration) (time.Time, error) {
	delta, err := randomDuration(spread)
	return now.Add(-delta), err
}

// retryDelay follows Tor's decorrelated jitter schedule, with explicit caps.
func retryDelay(previous, base, cap time.Duration) (time.Duration, error) {
	base = max(base, time.Second)
	upper := max(base+time.Second, previous*3)
	delta, err := randomDuration(upper - base)
	if err != nil {
		return 0, err
	}
	return min(cap, base+delta), nil
}

// RefreshTime chooses the Tor client refresh window: 3/4 of a fresh interval
// after freshness ends, up to 7/8 of the remaining validity interval.
func RefreshTime(s *Snapshot) (time.Time, error) {
	if s == nil || s.consensus == nil {
		return time.Time{}, ErrTime
	}
	c := s.consensus
	first := c.freshUntil.Add((c.freshUntil.Sub(c.validAfter) / 4) * 3)
	if !first.Before(c.validUntil) {
		first = c.freshUntil
	}
	width := (c.validUntil.Sub(first) / 8) * 7
	if width <= 0 {
		return time.Time{}, ErrTime
	}
	delta, err := randomDuration(width)
	return first.Add(delta), err
}
