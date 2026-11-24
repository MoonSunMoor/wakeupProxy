//go:build !linux && !windows

package proxy

import (
	"context"
	"net"
)

func watchDisconnectFallback(ctx context.Context, _ *net.TCPConn, ch chan struct{}) {
	<-ctx.Done()
	close(ch)
}
