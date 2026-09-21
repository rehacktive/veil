package directory

import (
	"testing"
	"time"
)

func TestConsensusLinkPadding(t *testing.T) {
	s := &Snapshot{consensus: &consensus{}}
	p, err := s.LinkPadding()
	if err != nil || p.Low != 1500*time.Millisecond || p.High != 9500*time.Millisecond || !p.BeforeUsage {
		t.Fatal(p, err)
	}
	s.consensus.params = map[string]int64{"nf_ito_low": 0, "nf_ito_high": 0, "nf_pad_before_usage": 0}
	p, err = s.LinkPadding()
	if err != nil || p.High != 0 || p.BeforeUsage {
		t.Fatal(p, err)
	}
	s.consensus.params = map[string]int64{"nf_ito_low": 70000, "nf_ito_high": -100}
	p, err = s.LinkPadding()
	if err != nil || p.Low != time.Minute || p.High != p.Low {
		t.Fatal(p, err)
	}
	if _, err := (*Snapshot)(nil).LinkPadding(); err == nil {
		t.Fatal("nil directory policy")
	}
}

func TestLinkRetentionConsensusBounds(t *testing.T) {
	s := &Snapshot{consensus: &consensus{params: map[string]int64{}}}
	if s.linkIdleTimeout() != 30*time.Minute {
		t.Fatal("default retention")
	}
	for value, want := range map[int64]time.Duration{-1: time.Minute, 60: time.Minute, 3600: time.Hour, 999999: 24 * time.Hour} {
		s.consensus.params["nf_conntimeout_clients"] = value
		if got := s.linkIdleTimeout(); got != want {
			t.Fatal(value, got)
		}
	}
}
