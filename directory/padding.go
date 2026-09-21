package directory

import (
	"time"
	"veil/channel"
)

// LinkPadding reads the authenticated network's normal client policy. The
// bounds match C Tor's consensus clamping (0..60000 ms; high at least low).
func (s *Snapshot) LinkPadding() (channel.PaddingOptions, error) {
	if s == nil || s.consensus == nil {
		return channel.PaddingOptions{}, ErrTime
	}
	param := func(name string, fallback, low, high int64) int64 {
		v, ok := s.consensus.params[name]
		if !ok {
			v = fallback
		}
		return max(low, min(high, v))
	}
	low := param("nf_ito_low", 1500, 0, 60000)
	high := param("nf_ito_high", 9500, low, 60000)
	return channel.PaddingOptions{Low: time.Duration(low) * time.Millisecond, High: time.Duration(high) * time.Millisecond, BeforeUsage: param("nf_pad_before_usage", 1, 0, 1) == 1}, nil
}

// LinkPaddingPolicy is shared by application channels using this guard owner.
func (g *GuardStore) LinkPaddingPolicy() *channel.PaddingPolicy { return &g.linkPadding }
func (g *GuardStore) updateLinkPadding(s *Snapshot) {
	p, err := s.LinkPadding()
	if err != nil {
		return
	}
	g.linkPadding.Update(p, s.consensus.validUntil, s.linkIdleTimeout())
}

func (s *Snapshot) linkIdleTimeout() time.Duration {
	seconds := int64(1800)
	if value, ok := s.consensus.params["nf_conntimeout_clients"]; ok {
		seconds = max(60, min(86400, value))
	}
	return time.Duration(seconds) * time.Second
}
