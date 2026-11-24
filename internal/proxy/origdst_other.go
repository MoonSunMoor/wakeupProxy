//go:build !linux

package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

func GetOriginalDst(_ *net.TCPConn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("SO_ORIGINAL_DST는 Linux에서만 지원됩니다")
}

func ListenTCPFreebind(ctx context.Context, listenAddr string) (net.Listener, error) {
	lc := net.ListenConfig{
		KeepAlive: 30 * time.Second,
	}
	return lc.Listen(ctx, "tcp4", listenAddr)
}

func WatchClientDisconnect(ctx context.Context, conn net.Conn) <-chan struct{} {
	ch := make(chan struct{})
	// Non-Linux fallback used in unit tests: poll using non-destructive Windows WSAPoll if TCPConn,
	// otherwise wait on ctx.
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return ch
	}
	go watchDisconnectFallback(ctx, tcpConn, ch)
	return ch
}
