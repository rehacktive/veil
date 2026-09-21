package directory

import (
	"testing"
	"time"
)

func TestCircuitPaddingConsensusAndGlobalBudget(t *testing.T) {
	s := &Snapshot{consensus: &consensus{validUntil: time.Now().Add(time.Hour), params: map[string]int64{"circpad_global_max_padding_pct": 10, "circpad_global_allowed_cells": 2}}}
	b := &PaddingBudget{}
	b.update(s)
	if !b.Enabled() || !b.TryPadding() || !b.TryPadding() || b.TryPadding() {
		t.Fatal("allowance/percentage not enforced")
	}
	for j := 0; j < 20; j++ {
		b.NonPadding()
	}
	if !b.TryPadding() || b.TryPadding() {
		t.Fatal("nonpadding denominator not shared")
	}
	b.update(s)
	if b.TryPadding() {
		t.Fatal("consensus update reset traffic counters")
	}
	s.consensus.params["circpad_padding_disabled"] = 1
	b.update(s)
	if b.Enabled() || b.TryPadding() {
		t.Fatal("disabled padding")
	}
	s.consensus.params["circpad_padding_disabled"] = 0
	s.consensus.params["circpad_padding_reduced"] = 1
	b.update(s)
	if b.Enabled() {
		t.Fatal("reduced mode should omit setup machines")
	}
	s.consensus.params = map[string]int64{"circpad_global_max_padding_pct": 200, "circpad_global_max_padding_percent": 20, "circpad_global_allowed_cells": -10}
	b.update(s)
	if b.percent != 20 || b.allowed != 0 {
		t.Fatal("bounds or stricter alias", b.percent, b.allowed)
	}
	s.consensus.validUntil = time.Now().Add(-time.Second)
	b.update(s)
	if b.Enabled() || b.TryPadding() {
		t.Fatal("expired policy")
	}
	var absent *PaddingBudget
	if absent.Enabled() || absent.TryPadding() {
		t.Fatal("nil policy enabled")
	}
	absent.NonPadding()
}

func TestCircuitPaddingAuthenticatedCapability(t *testing.T) {
	for _, version := range []string{"Padding=1", "Padding=2", "Padding=1-2"} {
		r := Relay{}
		r.status.protocols, _ = parseProtocols([]string{version})
		if r.SupportsCircuitPadding() != (version != "Padding=1") {
			t.Fatal(version)
		}
	}
}
