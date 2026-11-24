//go:build windows

package proxy

import (
	"context"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modws2_32   = windows.NewLazySystemDLL("ws2_32.dll")
	procWSAPoll = modws2_32.NewProc("WSAPoll")
)

const (
	wsaPollRDNorm = 0x0100
	wsaPollErr    = 0x0001
	wsaPollHup    = 0x0002
	wsaPollNVal   = 0x0004
)

type wsaPollFd struct {
	fd      windows.Handle
	events  int16
	revents int16
}

func watchDisconnectFallback(ctx context.Context, conn *net.TCPConn, ch chan struct{}) {
	defer close(ch)
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return
	}
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			disconnected := false
			ctrlErr := rawConn.Control(func(fd uintptr) {
				pfd := wsaPollFd{
					fd:     windows.Handle(fd),
					events: wsaPollRDNorm,
				}
				r1, _, _ := procWSAPoll.Call(uintptr(unsafe.Pointer(&pfd)), 1, 0)
				n := int32(r1)
				if n < 0 {
					disconnected = true
					return
				}
				if n > 0 {
					if pfd.revents&(wsaPollHup|wsaPollErr|wsaPollNVal) != 0 {
						disconnected = true
						return
					}
					if pfd.revents&wsaPollRDNorm != 0 {
						var one [1]byte
						var wsabuf windows.WSABuf
						wsabuf.Len = 1
						wsabuf.Buf = &one[0]
						var recvd uint32
						flags := uint32(windows.MSG_PEEK)
						rErr := windows.WSARecv(windows.Handle(fd), &wsabuf, 1, &recvd, &flags, nil, nil)
						if rErr == nil && recvd == 0 {
							disconnected = true
						}
					}
				}
			})
			if ctrlErr != nil || disconnected {
				return
			}
		}
	}
}
