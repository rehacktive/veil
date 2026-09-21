//go:build veiltest

package circuit

// This file is absent from production builds. It supplies explicit localhost
// hops only to the private-network interoperability test binary.
import (
	"context"
	"time"
	"veil/channel"
	"veil/directory"
)

type localAttempt struct{}

func (localAttempt) Success(time.Time) error                      { return nil }
func (localAttempt) Failure(time.Time, bool) error                { return nil }
func (localAttempt) Usability(time.Time) directory.GuardUsability { return directory.GuardUsable }
func (localAttempt) Close()                                       {}
func BuildLocalServiceTest(ctx context.Context, relays [3]directory.Relay, purpose OnionPurpose) (*Circuit, error) {
	var hops [3]hop
	for j, r := range relays {
		if !r.Address().Addr().IsLoopback() {
			return nil, ErrProtocol
		}
		hops[j] = hop{r.Target(), r.NTor()}
	}
	c, err := build(ctx, hops, localAttempt{}, 15*time.Second, func(ctx context.Context, t channel.Target, o channel.Options) (transport, error) {
		return channel.Dial(ctx, t, o)
	}, func() bool { return true })
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.path = directory.Path{Guard: relays[0], Middle: relays[1], Exit: relays[2]}
	c.hs = &onionCircuit{purpose: purpose}
	c.mu.Unlock()
	return c, nil
}
