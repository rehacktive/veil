//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package directory

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestStateLockOwnership(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	first, err := LockState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	for _, alias := range []string{dir, dir + "/."} {
		if other, err := LockState(alias); !errors.Is(err, ErrStateLocked) {
			if other != nil {
				other.Close()
			}
			t.Fatal("duplicate owner accepted", err)
		}
	}
	independent, err := LockState(filepath.Join(t.TempDir(), "separate"))
	if err != nil {
		t.Fatal(err)
	}
	independent.Close()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := first.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	next, err := LockState(dir)
	if err != nil {
		t.Fatal("close did not release ownership", err)
	}
	defer next.Close()
	// Closing an old handle again must never unlock a later owner.
	first.Close()
	if other, err := LockState(dir); !errors.Is(err, ErrStateLocked) {
		if other != nil {
			other.Close()
		}
		t.Fatal("stale close released new owner", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("unexpected persistent lock files", entries, err)
	}
}

func TestStateLockRejectsUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	public := t.TempDir()
	os.Chmod(public, 0755)
	for _, path := range []string{"", link, file, public} {
		if l, err := LockState(path); err == nil {
			l.Close()
			t.Fatal("accepted unsafe state directory", path)
		}
	}
}

func TestStateLockProcessExit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStateLockHelper$")
	cmd.Env = append(os.Environ(), "VEIL_LOCK_TEST_STATE="+dir)
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	ready, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || ready != "locked\n" {
		t.Fatal(ready, err)
	}
	if l, err := LockState(dir); !errors.Is(err, ErrStateLocked) {
		if l != nil {
			l.Close()
		}
		t.Fatal("another process bypassed ownership", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	l, err := LockState(dir)
	if err != nil {
		t.Fatal("crash left stale ownership", err)
	}
	defer l.Close()
}

func TestStateLockHelper(t *testing.T) {
	dir := os.Getenv("VEIL_LOCK_TEST_STATE")
	if dir == "" {
		return
	}
	l, err := LockState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fmt.Println("locked")
	var b [1]byte
	_, _ = os.Stdin.Read(b[:])
}
