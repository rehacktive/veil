package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestChannelCheckArguments(t *testing.T) {
	for _, args := range [][]string{
		nil, {"extra"}, {"-unknown"}, {"-address", "example.org:9001"},
		{"-address", "127.0.0.1:9001", "-rsa", "bad"},
		{"-address", "127.0.0.1:9001", "-rsa", strings.Repeat("01", 20), "-ed25519", "bad"},
		{"-timeout", "0s"}, {"-timeout", "-1s"},
		{"-address", "127.0.0.1:9001", "-rsa", strings.Repeat("00", 20), "-ed25519", strings.Repeat("00", 32)},
	} {
		if err := channelCheck(context.Background(), args, io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	if err := run([]string{"channel-check", "-h"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runContext(ctx, []string{"channel-check", "-address", "127.0.0.1:9001", "-rsa", strings.Repeat("01", 20), "-ed25519", strings.Repeat("02", 32)}, strings.NewReader(""), io.Discard, io.Discard)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
