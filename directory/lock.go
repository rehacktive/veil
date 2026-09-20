package directory

import (
	"errors"
	"fmt"
	"os"
	"sync"
)

var ErrStateLocked = errors.New("state directory is already in use by another Veil owner")

// StateLock holds an exclusive advisory OS lock on the directory inode itself.
// Keep it alive until all managers, guards, caches and circuits using that state
// have stopped. All writers must cooperate; never remove or replace an active
// state directory. Process exit releases ownership, with no stale lock file.
// Do not copy a StateLock. Close is concurrent-safe and idempotent.
type StateLock struct {
	file *os.File
	once sync.Once
	err  error
}

// LockState acquires ownership without waiting. Acquire it before opening any
// Cache or GuardStore. Different paths to the same inode share the same lock.
// Unsupported operating systems/filesystems fail closed. Use local storage.
func LockState(path string) (*StateLock, error) {
	if path == "" {
		return nil, errors.New("state directory is required")
	}
	if err := privateDirectory(path); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	locked := false
	defer func() {
		if !locked {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state lock requires a private directory (0700)")
	}
	if err := lockDirectory(f); err != nil {
		return nil, fmt.Errorf("lock state: %w", err)
	}
	locked = true
	return &StateLock{file: f}, nil
}

func (l *StateLock) Close() error {
	l.once.Do(func() { l.err = l.file.Close() })
	return l.err
}
