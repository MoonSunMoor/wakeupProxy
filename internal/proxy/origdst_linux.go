//go:build linux

package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const soOriginalDst = 80 // SO_ORIGINAL_DST on Linux SOL_IP

type rawSockaddrInet4 struct {
	Family uint16
	Port   [2]byte
	Addr   [4]byte
	Zero   [8]byte
}

// GetOriginalDst reads the pre-DNAT/REDIRECT IPv4 destination from a TCP connection
// via SyscallConn without switching the socket out of non-blocking netpoller mode.
func GetOriginalDst(conn *net.TCPConn) (netip.AddrPort, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}

	var addr rawSockaddrInet4
	addrLen := uint32(unsafe.Sizeof(addr))
	var sockErr error

	ctrlErr := rawConn.Control(func(fd uintptr) {
		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			uintptr(unix.SOL_IP),
			uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&addrLen)),
			0,
		)
		if errno != 0 {
			sockErr = errno
		}
	})
	if ctrlErr != nil {
		return netip.AddrPort{}, ctrlErr
	}
	if sockErr != nil {
		return netip.AddrPort{}, fmt.Errorf("SO_ORIGINAL_DST 조회 실패: %w", sockErr)
	}
	if addr.Family != unix.AF_INET {
		return netip.AddrPort{}, fmt.Errorf("예상하지 못한 주소 패밀리: %d", addr.Family)
	}
	port := binary.BigEndian.Uint16(addr.Port[:])
	ip := netip.AddrFrom4(addr.Addr)
	return netip.AddrPortFrom(ip, port), nil
}

// ListenTCPFreebind binds a TCP4 listener with IP_FREEBIND and SO_REUSEADDR so
// the socket survives ingress interface down/up cycles (e.g. WireGuard restarts).
func ListenTCPFreebind(ctx context.Context, listenAddr string) (net.Listener, error) {
	lc := net.ListenConfig{
		KeepAlive: 30 * time.Second,
		Control: func(_, _ string, c syscall.RawConn) error {
			var setErr error
			if err := c.Control(func(fd uintptr) {
				if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); e != nil {
					setErr = e
					return
				}
				if e := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1); e != nil {
					setErr = e
					return
				}
			}); err != nil {
				return err
			}
			return setErr
		},
	}
	return lc.Listen(ctx, "tcp4", listenAddr)
}

// WatchClientDisconnect monitors a waiting client socket for peer FIN/RST using
// POLLRDHUP|POLLHUP|POLLERR without consuming any initial protocol bytes (e.g. RDP/SSH)
// queued in the kernel receive buffer, preserving splice(2) when the target wakes up.
func WatchClientDisconnect(ctx context.Context, conn net.Conn) <-chan struct{} {
	ch := make(chan struct{})
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return ch
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return ch
	}

	go func() {
		defer close(ch)
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				disconnected := false
				ctrlErr := rawConn.Control(func(fd uintptr) {
					pfd := []unix.PollFd{{
						Fd:     int32(fd),
						Events: unix.POLLRDHUP | unix.POLLHUP | unix.POLLERR | unix.POLLNVAL,
					}}
					n, pErr := unix.Poll(pfd, 0)
					if pErr != nil && !errors.Is(pErr, unix.EINTR) {
						disconnected = true
						return
					}
					if n > 0 && pfd[0].Revents&(unix.POLLRDHUP|unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
						disconnected = true
					}
				})
				if ctrlErr != nil || disconnected {
					return
				}
			}
		}
	}()
	return ch
}
