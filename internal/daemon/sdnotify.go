package daemon

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// Notify sends a state notification string to systemd ($NOTIFY_SOCKET) if set.
func Notify(state string) error {
	sock := strings.TrimSpace(os.Getenv("NOTIFY_SOCKET"))
	if sock == "" {
		return nil
	}
	// Abstract socket names in systemd start with '@'.
	if strings.HasPrefix(sock, "@") {
		if runtime.GOOS != "linux" {
			return nil
		}
		sock = "\x00" + sock[1:]
	}

	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{
		Name: sock,
		Net:  "unixgram",
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

func NotifyReady() error {
	return Notify("READY=1\nSTATUS=Running\n")
}

func NotifyReloading() error {
	return Notify(fmt.Sprintf("RELOADING=1\nSTATUS=Reloading at %s\n", time.Now().Format(time.RFC3339)))
}

func NotifyStopping() error {
	return Notify("STOPPING=1\nSTATUS=Shutting down\n")
}
