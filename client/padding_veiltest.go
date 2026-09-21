//go:build veiltest

package client

import (
	"net"
	"veil/circuit"
)

// IntroductionPaddingForTest exposes only retained circuit counters to the
// private-network interoperability binary. Absent from production builds.
func (d *Dialer) IntroductionPaddingForTest() []circuit.PaddingStats {
	d.intros.mu.Lock()
	defer d.intros.mu.Unlock()
	var result []circuit.PaddingStats
	for c := range d.intros.active {
		if c, ok := c.(*circuit.Circuit); ok {
			result = append(result, c.PaddingStats())
		}
	}
	return result
}

// RendezvousPaddingForTest reads counters even after an unpooled stream closes.
func RendezvousPaddingForTest(conn net.Conn) (circuit.PaddingStats, bool) {
	if owned, ok := conn.(*ownedConn); ok {
		if attempt, ok := owned.circuit.(*attemptCircuit); ok {
			if c, ok := attempt.streamCircuit.(*circuit.Circuit); ok {
				return c.PaddingStats(), true
			}
		}
	}
	return circuit.PaddingStats{}, false
}

func (d *Dialer) ChannelPoolForTest() (int, int) { return d.channels.CountsForTest() }
