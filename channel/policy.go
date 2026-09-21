package channel

import (
	"sync"
	"time"
)

// PaddingPolicy publishes consensus policy to existing channels. The directory
// owner is responsible for authenticity and rollback protection.
type PaddingPolicy struct {
	mu      sync.Mutex
	value   PaddingOptions
	expires time.Time
	idle    time.Duration
	changed chan struct{}
}

// Update bounds values before publishing; callers should use a verified consensus.
func (p *PaddingPolicy) Update(value PaddingOptions, expires time.Time, idle time.Duration) {
	value.Low = max(0, min(time.Minute, value.Low))
	value.High = max(value.Low, min(time.Minute, value.High))
	idle = max(time.Millisecond, min(24*time.Hour, idle))
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.value == value && p.expires.Equal(expires) && p.idle == idle {
		return
	}
	p.value, p.expires, p.idle = value, expires, idle
	if p.changed != nil {
		close(p.changed)
	}
	p.changed = make(chan struct{})
}
func (p *PaddingPolicy) current() (PaddingOptions, time.Time, time.Duration, <-chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.changed == nil {
		p.changed = make(chan struct{})
	}
	value := p.value
	if !time.Now().Before(p.expires) {
		value = PaddingOptions{}
	}
	idle := p.idle
	if idle <= 0 {
		idle = 30 * time.Minute
	}
	return value, p.expires, idle, p.changed
}
