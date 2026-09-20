//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package main

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"veil/directory"
)

func TestStateCommandsRejectOtherOwner(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	lock, err := directory.LockState(state)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	for _, args := range [][]string{
		{"proxy", "-public", "-state", state, "-listen", "127.0.0.1:0"},
		{"proxy", "-config", "missing", "-state", state, "-listen", "127.0.0.1:0"},
		{"directory-bootstrap", "-config", "missing", "-state", state},
		{"directory-watch", "-config", "missing", "-state", state},
		{"circuit-check", "-state", state, "-authorities", strings.Repeat("1", 40)},
	} {
		if err := run(args, strings.NewReader(""), io.Discard, io.Discard); !errors.Is(err, directory.ErrStateLocked) {
			t.Fatal(args[0], "did not reject concurrent state ownership", err)
		}
	}
}

func TestStateReleasedAfterStartupFailure(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	for _, command := range []string{"proxy", "directory-bootstrap", "directory-watch", "circuit-check"} {
		args := []string{command, "-state", state}
		if command == "circuit-check" {
			args = append(args, "-authorities", strings.Repeat("1", 40))
		} else {
			args = append(args, "-config", "missing")
		}
		if command == "proxy" {
			args = append(args, "-listen", "127.0.0.1:0")
		}
		if err := run(args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatal("expected startup failure")
		}
		lock, err := directory.LockState(state)
		if err != nil {
			t.Fatal(command, "leaked ownership", err)
		}
		lock.Close()
	}
}
