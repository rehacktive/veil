//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package directory

import (
	"errors"
	"os"
)

func lockDirectory(*os.File) error {
	return errors.New("exclusive state locking is unsupported on this operating system")
}
