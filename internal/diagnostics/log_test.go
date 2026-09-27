package diagnostics

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
)

func TestConcurrentLogsAreEscapedAndScoped(t *testing.T) {
	var out bytes.Buffer
	logger := New(true, &out)
	ctx := WithLogger(context.Background(), logger.With("request_id", 7))
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); Log(ctx, logger, "event", "value", "remote\nforged\x1b[31m") }()
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 32 {
		t.Fatal("interleaved or unescaped records", len(lines))
	}
	for _, line := range lines {
		if !strings.Contains(line, "request_id=7") || strings.ContainsRune(line, '\x1b') {
			t.Fatal(line)
		}
	}
	before := out.Len()
	Log(ctx, nil, "must_be_silent")
	if out.Len() != before {
		t.Fatal("context bypassed disabled logging")
	}
}

func TestCLILogLevels(t *testing.T) {
	for _, mode := range []struct {
		name         string
		debug, quiet bool
	}{
		{"default", false, false}, {"debug", true, false}, {"quiet", false, true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			var out bytes.Buffer
			logger := NewCLI(mode.debug, mode.quiet, &out)
			Info(context.Background(), logger, "startup_complete")
			Log(context.Background(), logger, "connection_detail", "destination", "private-destination")
			if strings.Contains(out.String(), "startup_complete") != !mode.quiet {
				t.Fatal(out.String())
			}
			if strings.Contains(out.String(), "private-destination") != mode.debug {
				t.Fatal(out.String())
			}
		})
	}
}
