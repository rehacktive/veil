package main

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestCircuitCheckArgumentsAndMissingCache(t *testing.T) {
	if err := circuitCheck(context.Background(), []string{"-h"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{nil, {"-unknown"}, {"extra"}, {"-state", "state"}, {"-state", "state", "-authorities", "bad"}, {"-state", "state", "-authorities", strings.Repeat("1", 40), "-port", "0"}, {"-state", "state", "-authorities", strings.Repeat("1", 40), "-port", "65536"}, {"-state", "state", "-authorities", strings.Repeat("1", 40), "-timeout", "0"}} {
		if err := circuitCheck(context.Background(), args, io.Discard, io.Discard); err == nil {
			t.Fatal("accepted", args)
		}
	}
	if err := circuitCheck(context.Background(), []string{"-state", t.TempDir() + "/missing", "-authorities", strings.Repeat("1", 40)}, io.Discard, io.Discard); err == nil {
		t.Fatal("accepted missing cache")
	}
}
