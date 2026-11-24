//go:build linux

package proxy

import (
	"context"
	"testing"
)

func TestListenTCPFreebindBindsUnassignedIPv4(t *testing.T) {
	// 198.51.100.42 (TEST-NET-2) is not assigned on the host; IP_FREEBIND allows binding it anyway.
	ln, err := ListenTCPFreebind(context.Background(), "198.51.100.42:0")
	if err != nil {
		t.Fatalf("ListenTCPFreebind failed on unassigned IP: %v", err)
	}
	defer ln.Close()
}
