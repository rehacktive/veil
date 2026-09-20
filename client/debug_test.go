package client

import (
	"bytes"
	"strings"
	"testing"
	"veil/internal/diagnostics"
)

func TestDebugCircuitReuseDoesNotLogIsolationTokenOrPayload(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		var logs bytes.Buffer
		d, _ := poolDialer(t, Options{Logger: diagnostics.New(enabled, &logs)})
		for i := 0; i < 2; i++ {
			c := connectPool(t, d, "private-isolation-token", "tcp", "example.com:80")
			roundTrip(t, c, []byte("private-traffic-payload"))
			c.Close()
		}
		d.Close()
		text := logs.String()
		if !enabled {
			if text != "" {
				t.Fatal("logs emitted without debug")
			}
			continue
		}
		for _, want := range []string{"destination_requested", "circuit_build", "circuit_ready", "circuit_reused"} {
			if !strings.Contains(text, want) {
				t.Fatal("missing event", want, text)
			}
		}
		if strings.Contains(text, "private-isolation-token") || strings.Contains(text, "private-traffic-payload") {
			t.Fatal("private contents logged")
		}
	}
}
