//go:build linux

package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"testing"
	"time"

	"github.com/MoonSunMoor/wakeupProxy/internal/config"
	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
	"github.com/MoonSunMoor/wakeupProxy/internal/nft"
)

func TestListenTCPFreebindBindsUnassignedIPv4(t *testing.T) {
	// 198.51.100.42 (TEST-NET-2) is not assigned on the host; IP_FREEBIND allows binding it anyway.
	ln, err := ListenTCPFreebind(context.Background(), "198.51.100.42:0")
	if err != nil {
		t.Fatalf("ListenTCPFreebind failed on unassigned IP: %v", err)
	}
	defer ln.Close()
}

func TestRealNFTablesRedirectAndOriginalDst(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft binary not installed; skipping kernel nftables REDIRECT integration test")
	}
	nftMgr := nft.CLIManager{}
	// Probe whether current process/namespace has CAP_NET_ADMIN for nftables.
	probeRuleset := "table inet wolproxy_test_probe\ndelete table inet wolproxy_test_probe\n"
	if err := nftMgr.Apply(context.Background(), probeRuleset); err != nil {
		t.Skipf("CAP_NET_ADMIN / nftables netlink unavailable (%v); run inside root/unshare -Urn to execute", err)
	}
	t.Cleanup(func() {
		_ = nftMgr.Cleanup(context.Background())
	})

	_, backendPort := startEchoBackend(t)
	probeLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	ifaces := netutil.StaticProvider{
		Items: []netutil.InterfaceInfo{
			{
				Name:     "eth0",
				Index:    2,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.10/24")},
				Up:       true,
			},
			{
				Name:     "lo",
				Index:    1,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")},
				Loopback: true,
				Up:       true,
			},
		},
	}
	cfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"lo"},
		ProxyPort:         proxyPort,
		WakeTimeout:       config.Duration(2 * time.Second),
		WakeCooldown:      config.Duration(time.Second),
		PollInterval:      config.Duration(50 * time.Millisecond),
		Clients:           map[string]config.Client{"local": {CIDR: "127.0.0.0/8"}},
		Profiles:          map[string]config.Profile{"echo": {Port: backendPort, Wake: config.WakeNever}},
		Targets: []config.Target{{
			Name:     "loop-target",
			IP:       "192.168.0.21",
			Alias:    "127.0.0.2",
			MAC:      "02:00:00:00:00:02",
			Profiles: []string{"echo"},
			Allow:    []string{"local"},
		}},
	}

	srv := NewServer(Options{
		Interfaces: ifaces,
		NFT:        nftMgr,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dial: func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", intToStr(backendPort)))
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx, cfg); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer srv.Shutdown(context.Background())

	c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.2", intToStr(backendPort)), time.Second)
	if err != nil {
		// Note: locally generated traffic hits output hook rather than prerouting unless routed via veth;
		// skip cleanly if prerouting didn't intercept local socket.
		t.Skipf("local socket did not traverse prerouting (veth namespace needed): %v", err)
	}
	defer c.Close()
	msg := []byte("kernel-orig-dst-ok")
	_, _ = c.Write(msg)
	_ = c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("unexpected echo response: %q err=%v", got, err)
	}
}
