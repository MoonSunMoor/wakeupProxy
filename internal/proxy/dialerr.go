package proxy

import (
	"context"
	"errors"
	"net"
)

// shouldWakeOnDialError reports whether an initial 1-second TCP dial failure
// indicates a sleeping/unreachable target (timeout, EHOSTUNREACH, ENETUNREACH)
// rather than an awake host rejecting the port (ECONNREFUSED) or another local error.
func shouldWakeOnDialError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || isConnRefused(err) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return isUnreachableErrno(err)
}

func dialFailureReason(err error) string {
	if isConnRefused(err) {
		return "conn_refused"
	}
	return "dial_failed"
}
