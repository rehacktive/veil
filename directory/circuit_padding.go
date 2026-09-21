package directory

import (
	"sync"
	"time"
)

// PaddingBudget shares circuit padding policy/accounting across every circuit
// using a GuardStore. It is memory-only; counts never reset on circuit rotation.
type PaddingBudget struct {
	mu               sync.Mutex
	enabled          bool
	expires          time.Time
	allowed, percent uint64
	padding, other   uint64
}

func (g *GuardStore) PaddingBudget() *PaddingBudget { return &g.paddingBudget }

func (b *PaddingBudget) update(s *Snapshot) {
	b.mu.Lock()
	defer b.mu.Unlock()
	param := func(key string, fallback, maximum int64) uint64 {
		v, ok := s.consensus.params[key]
		if !ok {
			v = fallback
		}
		return uint64(max(0, min(maximum, v)))
	}
	b.enabled = param("circpad_padding_disabled", 0, 1) == 0 && param("circpad_padding_reduced", 0, 1) == 0
	b.expires = s.consensus.validUntil
	b.allowed = param("circpad_global_allowed_cells", 0, 65534)
	// C Tor uses _pct; the prose specification spells this _percent. Honor both,
	// taking the stricter nonzero limit if both are present.
	b.percent = param("circpad_global_max_padding_pct", 0, 100)
	other := param("circpad_global_max_padding_percent", 0, 100)
	if other != 0 && (b.percent == 0 || other < b.percent) {
		b.percent = other
	}
}
func (b *PaddingBudget) Enabled() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.enabled && time.Now().Before(b.expires)
}
func (b *PaddingBudget) NonPadding() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	// Keep percentage multiplication bounded even after extremely long uptime.
	if b.other+b.padding >= 1<<56 {
		b.other /= 2
		b.padding /= 2
	}
	b.other++
}
func (b *PaddingBudget) TryPadding() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.enabled || !time.Now().Before(b.expires) {
		return false
	}
	total := b.other + b.padding
	if b.percent != 0 && b.padding >= b.allowed && total > 0 && 100*b.padding/total > b.percent {
		return false
	}
	b.padding++
	return true
}

// SupportsCircuitPadding reports authenticated support for the setup machines.
func (r Relay) SupportsCircuitPadding() bool { return r.status.protocols.has("Padding", 2) }
