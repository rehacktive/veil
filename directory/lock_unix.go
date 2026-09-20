//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package directory

import (
	"errors"
	"math"
	"os"
	"syscall"
)

func lockDirectory(f *os.File) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var lockErr error
	if err := raw.Control(func(fd uintptr) {
		if fd > math.MaxInt {
			lockErr = errors.New("state lock file descriptor exceeds int range")
			return
		}
		for {
			lockErr = syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
			if !errors.Is(lockErr, syscall.EINTR) {
				break
			}
		}
	}); err != nil {
		return err
	}
	if errors.Is(lockErr, syscall.EWOULDBLOCK) || errors.Is(lockErr, syscall.EAGAIN) {
		return ErrStateLocked
	}
	return lockErr
}
