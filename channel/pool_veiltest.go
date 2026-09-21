//go:build veiltest

package channel

// CountsForTest inspects transport ownership in the private C Tor test binary.
func (p *Pool) CountsForTest() (channels, leases int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for s := range p.all {
		if s.ch != nil && s.ch.Err() == nil {
			channels++
		}
	}
	return channels, p.leases
}
