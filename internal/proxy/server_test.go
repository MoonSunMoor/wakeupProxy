package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoonSunMoor/wakeupProxy/internal/config"
	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
)

type fakeNFT struct {
	mu       sync.Mutex
	rulesets []string
	cleaned  int
}

func (f *fakeNFT) Apply(_ context.Context, ruleset string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rulesets = append(f.rulesets, ruleset)
	return nil
}

func (f *fakeNFT) Cleanup(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleaned++
	return nil
}

type fakeWoLSender struct {
	packets atomic.Int32
}

func (w *fakeWoLSender) SendMagicPacket(_ context.Context, _ netip.Addr, _ net.HardwareAddr) error {
	w.packets.Add(1)
	return nil
}

func testProxyInterfaces() netutil.StaticProvider {
	return netutil.StaticProvider{
		Items: []netutil.InterfaceInfo{
			{
				Name:     "eth0",
				Index:    2,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.10/24")},
				Up:       true,
			},
			{
				Name:     "wg0",
				Index:    3,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
				Up:       true,
			},
		},
	}
}

func startEchoBackend(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
				if cw, ok := conn.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
			}(c)
		}
	}()
	return ln, ln.Addr().(*net.TCPAddr).Port
}

func TestProxyAwakeRelayHalfCloseAndAccessControl(t *testing.T) {
	_, backendPort := startEchoBackend(t)

	// Pick an ephemeral port for proxy_port
	probeLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	cfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         proxyPort,
		WakeTimeout:       config.Duration(2 * time.Second),
		WakeCooldown:      config.Duration(500 * time.Millisecond),
		PollInterval:      config.Duration(50 * time.Millisecond),
		Clients: map[string]config.Client{
			"laptop": {CIDR: "127.0.0.1/32"},
		},
		Profiles: map[string]config.Profile{
			"rdp": {Port: 3389, Wake: config.WakeAuto},
		},
		Targets: []config.Target{
			{
				Name:     "pc1",
				IP:       "192.168.0.21",
				Alias:    "10.66.1.12",
				MAC:      "aa:bb:cc:dd:ee:01",
				Profiles: []string{"rdp"},
				Allow:    []string{"laptop"},
			},
		},
	}

	var origDst atomic.Value
	origDst.Store(netip.MustParseAddrPort("10.66.1.12:3389")) // Connect via alias!

	nftMock := &fakeNFT{}
	wolMock := &fakeWoLSender{}

	srv := NewServer(Options{
		Interfaces: testProxyInterfaces(),
		NFT:        nftMock,
		WoLSender:  wolMock,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		OrigDst: func(_ net.Conn) (netip.AddrPort, error) {
			return origDst.Load().(netip.AddrPort), nil
		},
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			if addr != "192.168.0.21:3389" {
				return nil, errors.New("unexpected upstream target addr: " + addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", "0")[:10]+lnPortStr(backendPort))
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx, cfg); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer srv.Shutdown(context.Background())

	// 1. Allowed connection via alias -> relays to real IP with half-close intact
	c, err := net.Dial("tcp4", srv.ListenerAddrs()[0])
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("hello-through-wolproxy")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	_ = c.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("relay mismatch: got %q want %q", got, payload)
	}
	if wolMock.packets.Load() != 0 {
		t.Fatalf("expected 0 magic packets when target already awake, got %d", wolMock.packets.Load())
	}

	// 2. Unknown destination -> closed immediately without wake
	origDst.Store(netip.MustParseAddrPort("192.168.0.99:3389"))
	c2, err := net.Dial("tcp4", srv.ListenerAddrs()[0])
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	_ = c2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, rErr := c2.Read(buf)
	_ = c2.Close()
	if rErr == nil {
		t.Fatal("expected unknown destination connection to be closed immediately")
	}

	// 3. Disallowed client (reload removing laptop from allow) -> closed immediately without wake
	origDst.Store(netip.MustParseAddrPort("192.168.0.21:3389"))
	deniedCfg := cfg.Clone()
	deniedCfg.Targets[0].Allow = []string{}
	if err := srv.Reload(context.Background(), deniedCfg); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	c3, err := net.Dial("tcp4", srv.ListenerAddrs()[0])
	if err != nil {
		t.Fatal(err)
	}
	_ = c3.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, rErr = c3.Read(buf)
	_ = c3.Close()
	if rErr == nil {
		t.Fatal("expected unallowed client to be closed immediately")
	}
	if wolMock.packets.Load() != 0 {
		t.Fatal("disallowed client must never send magic packet")
	}
}

func lnPortStr(port int) string {
	return net.JoinHostPort("", intToStr(port))[1:]
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestProxyWakePollPreservesInitialClientBytesAndIdleTimeout(t *testing.T) {
	_, backendPort := startEchoBackend(t)

	probeLn, _ := net.Listen("tcp4", "127.0.0.1:0")
	proxyPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	cfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         proxyPort,
		WakeTimeout:       config.Duration(2 * time.Second),
		WakeCooldown:      config.Duration(500 * time.Millisecond),
		PollInterval:      config.Duration(50 * time.Millisecond),
		Clients: map[string]config.Client{
			"laptop": {CIDR: "127.0.0.1/32"},
		},
		Profiles: map[string]config.Profile{
			"ssh-idle": {
				Port:        22,
				Wake:        config.WakeAuto,
				IdleTimeout: config.Duration(180 * time.Millisecond),
				IdleBytes:   10,
			},
		},
		Targets: []config.Target{
			{
				Name:     "pc1",
				IP:       "192.168.0.21",
				MAC:      "aa:bb:cc:dd:ee:01",
				Profiles: []string{"ssh-idle"},
				Allow:    []string{"laptop"},
			},
		},
	}

	var awake atomic.Bool
	nftMock := &fakeNFT{}
	wolMock := &fakeWoLSender{}

	srv := NewServer(Options{
		Interfaces: testProxyInterfaces(),
		NFT:        nftMock,
		WoLSender:  wolMock,
		IdleTick:   30 * time.Millisecond,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		OrigDst: func(_ net.Conn) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("192.168.0.21:22"), nil
		},
		Dial: func(ctx context.Context, _ string) (net.Conn, error) {
			if !awake.Load() {
				return nil, errors.New("host sleeping")
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", intToStr(backendPort)))
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())

	c, err := net.Dial("tcp4", srv.ListenerAddrs()[0])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Send initial handshake bytes BEFORE target wakes up — must NOT be lost!
	greeting := []byte("SSH-2.0-OpenSSH_Client_Initial_Banner")
	if _, err := c.Write(greeting); err != nil {
		t.Fatal(err)
	}

	time.Sleep(110 * time.Millisecond)
	awake.Store(true)

	reply := make([]byte, len(greeting))
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("failed reading echoed initial banner after wake: %v", err)
	}
	if !bytes.Equal(reply, greeting) {
		t.Fatalf("initial client bytes corrupted/lost: got %q want %q", reply, greeting)
	}
	if wolMock.packets.Load() < 1 {
		t.Fatal("expected magic packet sent to wake sleeping target")
	}

	// Now send only 4 bytes (<= idle_bytes=10 across echoes = 8 bytes total) and wait for idle_timeout (180ms)
	_, _ = c.Write([]byte("ti"))
	smallEcho := make([]byte, 2)
	_, _ = io.ReadFull(c, smallEcho)

	_ = c.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	_, err = c.Read(make([]byte, 16))
	if err == nil {
		t.Fatal("expected idle_timeout to close connection when bidirectional bytes <= idle_bytes")
	}
}

func TestSIGHUPReloadKeepsValidConnAndClosesRevokedConn(t *testing.T) {
	_, backendPort := startEchoBackend(t)

	probeLn, _ := net.Listen("tcp4", "127.0.0.1:0")
	proxyPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	cfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         proxyPort,
		WakeTimeout:       config.Duration(2 * time.Second),
		WakeCooldown:      config.Duration(500 * time.Millisecond),
		PollInterval:      config.Duration(50 * time.Millisecond),
		Clients: map[string]config.Client{
			"laptop": {CIDR: "127.0.0.1/32"},
		},
		Profiles: map[string]config.Profile{
			"rdp": {Port: 3389, Wake: config.WakeAuto},
			"ssh": {Port: 22, Wake: config.WakeAuto},
		},
		Targets: []config.Target{
			{
				Name:     "pc1",
				IP:       "192.168.0.21",
				MAC:      "aa:bb:cc:dd:ee:01",
				Profiles: []string{"rdp", "ssh"},
				Allow:    []string{"laptop"},
			},
		},
	}

	var nextOrigDst atomic.Value
	srv := NewServer(Options{
		Interfaces: testProxyInterfaces(),
		NFT:        &fakeNFT{},
		WoLSender:  &fakeWoLSender{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		OrigDst: func(_ net.Conn) (netip.AddrPort, error) {
			return nextOrigDst.Load().(netip.AddrPort), nil
		},
		Dial: func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", intToStr(backendPort)))
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())

	// Open conn1 on rdp (3389) and conn2 on ssh (22)
	nextOrigDst.Store(netip.MustParseAddrPort("192.168.0.21:3389"))
	connRDP, err := net.Dial("tcp4", srv.ListenerAddrs()[0])
	if err != nil {
		t.Fatal(err)
	}
	defer connRDP.Close()
	_, _ = connRDP.Write([]byte("ping1"))
	tmp := make([]byte, 5)
	if _, err := io.ReadFull(connRDP, tmp); err != nil {
		t.Fatal(err)
	}

	nextOrigDst.Store(netip.MustParseAddrPort("192.168.0.21:22"))
	connSSH, err := net.Dial("tcp4", srv.ListenerAddrs()[0])
	if err != nil {
		t.Fatal(err)
	}
	defer connSSH.Close()
	_, _ = connSSH.Write([]byte("ping2"))
	if _, err := io.ReadFull(connSSH, tmp); err != nil {
		t.Fatal(err)
	}

	// Reload removing "ssh" profile from pc1 while keeping "rdp"
	reloadedCfg := cfg.Clone()
	reloadedCfg.Targets[0].Profiles = []string{"rdp"}
	if err := srv.Reload(context.Background(), reloadedCfg); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// connSSH must be closed immediately
	_ = connSSH.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := connSSH.Read(tmp); err == nil {
		t.Fatal("expected connSSH to be closed when ssh profile removed on SIGHUP reload")
	}

	// connRDP must STILL work!
	if _, err := connRDP.Write([]byte("alive")); err != nil {
		t.Fatalf("expected connRDP to stay alive: %v", err)
	}
	if _, err := io.ReadFull(connRDP, tmp); err != nil || string(tmp) != "alive" {
		t.Fatalf("expected connRDP echo 'alive', got %q err=%v", tmp, err)
	}
}

func TestClientDisconnectCancelsWakeWaitImmediately(t *testing.T) {
	probeLn, _ := net.Listen("tcp4", "127.0.0.1:0")
	proxyPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	cfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         proxyPort,
		WakeTimeout:       config.Duration(10 * time.Second),
		WakeCooldown:      config.Duration(250 * time.Millisecond),
		PollInterval:      config.Duration(60 * time.Millisecond),
		Clients: map[string]config.Client{
			"laptop": {CIDR: "127.0.0.1/32"},
		},
		Profiles: map[string]config.Profile{
			"rdp": {Port: 3389, Wake: config.WakeAuto},
		},
		Targets: []config.Target{
			{
				Name:     "pc1",
				IP:       "192.168.0.21",
				MAC:      "aa:bb:cc:dd:ee:01",
				Profiles: []string{"rdp"},
				Allow:    []string{"laptop"},
			},
		},
	}

	wolMock := &fakeWoLSender{}
	srv := NewServer(Options{
		Interfaces: testProxyInterfaces(),
		NFT:        &fakeNFT{},
		WoLSender:  wolMock,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		OrigDst: func(_ net.Conn) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("192.168.0.21:3389"), nil
		},
		Dial: func(_ context.Context, _ string) (net.Conn, error) {
			return nil, errors.New("still sleeping")
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())

	c, err := net.Dial("tcp4", srv.ListenerAddrs()[0])
	if err != nil {
		t.Fatal(err)
	}
	// Wait until initial magic packet is sent, then close client connection.
	time.Sleep(80 * time.Millisecond)
	_ = c.Close()

	// Wait past cooldown (250ms): since client disconnected, active conns must drop to 0 and no more magic packets sent!
	deadline := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(deadline) {
		srv.connsMu.Lock()
		n := len(srv.conns)
		srv.connsMu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	srv.connsMu.Lock()
	remaining := len(srv.conns)
	srv.connsMu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected waiting connection to abort when client disconnects, still have %d", remaining)
	}
	sentAtAbort := wolMock.packets.Load()
	time.Sleep(350 * time.Millisecond)
	if after := wolMock.packets.Load(); after != sentAtAbort {
		t.Fatalf("expected WoL resend loop to stop after client disconnect, got %d -> %d", sentAtAbort, after)
	}
}
