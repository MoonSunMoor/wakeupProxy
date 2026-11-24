//go:build windows

package proxy

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, windows.WSAECONNREFUSED)
}

func isUnreachableErrno(err error) bool {
	return errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.ETIMEDOUT) ||
		errors.Is(err, windows.WSAEHOSTUNREACH) ||
		errors.Is(err, windows.WSAENETUNREACH) ||
		errors.Is(err, windows.WSAETIMEDOUT)
}
