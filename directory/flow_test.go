package directory

import "testing"

func TestCircuitWindowParameters(t *testing.T) {
	for _, tc := range []struct {
		params map[string]int64
		want   int
	}{
		{nil, 1000}, {map[string]int64{"circwindow": -1}, 100},
		{map[string]int64{"circwindow": 2000}, 1000},
		{map[string]int64{"circwindow": 500}, 500},
		{map[string]int64{"circwindow": 950}, 0},
		{map[string]int64{"sendme_emit_min_version": 2}, 0},
		{map[string]int64{"sendme_accept_min_version": 2}, 0},
	} {
		s := &Snapshot{consensus: &consensus{params: tc.params}}
		got, err := s.CircuitWindow()
		if got != tc.want || (err != nil) != (tc.want == 0) {
			t.Fatal(tc, got, err)
		}
	}
}
