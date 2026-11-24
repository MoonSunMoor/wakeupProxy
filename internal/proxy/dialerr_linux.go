//go:build linux

package proxy

import (
	"errors"

	"golang.org/x/sys/unix"
)

func isConnRefused(err error) bool {
	return errors.Is(err, unix.ECONNREFUSED)
}

func isUnreachableErrno(err error) bool {
	return errors.Is(err, unix.EHOSTUNREACH) ||
		errors.Is(err, unix.ENETUNREACH) ||
		errors.Is(err, unix.ETIMEDOUT)
}
