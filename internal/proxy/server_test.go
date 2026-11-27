package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
				return nil, context.DeadlineExceeded
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
			return nil, context.DeadlineExceeded
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

func TestClientHalfCloseDuringWakeCancelsImmediately(t *testing.T) {
	probeLn, _ := net.Listen("tcp4", "127.0.0.1:0")
	proxyPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	cfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         proxyPort,
		WakeTimeout:       config.Duration(10 * time.Second),
		WakeCooldown:      config.Duration(300 * time.Millisecond),
		PollInterval:      config.Duration(60 * time.Millisecond),
		Clients: map[string]config.Client{
			"laptop": {CIDR: "127.0.0.1/32"},
		},
		Profiles: map[string]config.Profile{
			"ssh": {Port: 22, Wake: config.WakeAuto},
		},
		Targets: []config.Target{
			{
				Name:     "pc1",
				IP:       "192.168.0.21",
				MAC:      "aa:bb:cc:dd:ee:01",
				Profiles: []string{"ssh"},
				Allow:    []string{"laptop"},
			},
		},
	}

	srv := NewServer(Options{
		Interfaces: testProxyInterfaces(),
		NFT:        &fakeNFT{},
		WoLSender:  &fakeWoLSender{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		OrigDst: func(_ net.Conn) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("192.168.0.21:22"), nil
		},
		Dial: func(_ context.Context, _ string) (net.Conn, error) {
			return nil, syscall.EHOSTUNREACH
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

	time.Sleep(60 * time.Millisecond)
	// TCP half-close (SHUT_WR -> FIN) while waiting for wake
	_ = c.(*net.TCPConn).CloseWrite()

	deadline := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(deadline) {
		srv.connsMu.Lock()
		n := len(srv.conns)
		w := srv.waitingTotal
		srv.connsMu.Unlock()
		if n == 0 && w == 0 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("expected TCP half-close during wake-up to cancel waiting connection and release wake slot")
}

func TestConcurrentAcceptAndACLReload(t *testing.T) {
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

	srv := NewServer(Options{
		Interfaces: testProxyInterfaces(),
		NFT:        &fakeNFT{},
		WoLSender:  &fakeWoLSender{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		OrigDst: func(_ net.Conn) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("192.168.0.21:3389"), nil
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

	listenAddr := srv.ListenerAddrs()[0]
	var openConnsMu sync.Mutex
	var openConns []net.Conn
	stopDialers := make(chan struct{})
	var dialersWG sync.WaitGroup

	for i := 0; i < 16; i++ {
		dialersWG.Add(1)
		go func() {
			defer dialersWG.Done()
			for {
				select {
				case <-stopDialers:
					return
				default:
				}
				c, err := net.DialTimeout("tcp4", listenAddr, 100*time.Millisecond)
				if err == nil {
					openConnsMu.Lock()
					openConns = append(openConns, c)
					openConnsMu.Unlock()
				}
				time.Sleep(time.Millisecond)
			}
		}()
	}

	// Let concurrent connections flood in, then revoke ACL via Reload while dialers are still active!
	time.Sleep(40 * time.Millisecond)
	revokedCfg := cfg.Clone()
	revokedCfg.Targets[0].Allow = []string{}
	if err := srv.Reload(context.Background(), revokedCfg); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	close(stopDialers)
	dialersWG.Wait()

	defer func() {
		openConnsMu.Lock()
		for _, c := range openConns {
			_ = c.Close()
		}
		openConnsMu.Unlock()
	}()

	// Every single tracked connection must have been rejected or evicted!
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		srv.connsMu.Lock()
		remaining := len(srv.conns)
		srv.connsMu.Unlock()
		if remaining == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv.connsMu.Lock()
	remaining := len(srv.conns)
	srv.connsMu.Unlock()
	if remaining != 0 {
		t.Fatalf("ACL reload race: %d unauthorized connections survived reload", remaining)
	}
}

func TestWaitingConnectionLimitsAndMACChangeEviction(t *testing.T) {
	probeLn, _ := net.Listen("tcp4", "127.0.0.1:0")
	proxyPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	cfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         proxyPort,
		WakeTimeout:       config.Duration(5 * time.Second),
		WakeCooldown:      config.Duration(time.Second),
		PollInterval:      config.Duration(100 * time.Millisecond),
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

	srv := NewServer(Options{
		Interfaces:          testProxyInterfaces(),
		NFT:                 &fakeNFT{},
		WoLSender:           &fakeWoLSender{},
		MaxWaitingPerTarget: 2,
		MaxWaitingGlobal:    4,
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		OrigDst: func(_ net.Conn) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("192.168.0.21:3389"), nil
		},
		Dial: func(_ context.Context, _ string) (net.Conn, error) {
			return nil, syscall.ENETUNREACH
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())

	addr := srv.ListenerAddrs()[0]
	c1, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	// Wait until both enter waiting state
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		srv.connsMu.Lock()
		w := srv.waitingByTarget["pc1"]
		srv.connsMu.Unlock()
		if w == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 3rd waiting connection to pc1 must be rejected immediately due to MaxWaitingPerTarget=2
	c3, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	_ = c3.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if _, err := c3.Read(make([]byte, 4)); err == nil {
		t.Fatal("expected 3rd waiting connection exceeding MaxWaitingPerTarget=2 to be closed")
	}

	// Reload changing pc1's MAC while keeping name="pc1" -> must evict c1 and c2!
	macChangedCfg := cfg.Clone()
	macChangedCfg.Targets[0].MAC = "aa:bb:cc:dd:ee:99"
	if err := srv.Reload(context.Background(), macChangedCfg); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	_ = c1.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if _, err := c1.Read(make([]byte, 4)); err == nil {
		t.Fatal("expected waiting connection to old MAC to be evicted on reload")
	}
}

func TestInitialECONNREFUSEDClosesWithoutWakeWhilePollToleratesRefused(t *testing.T) {
	_, backendPort := startEchoBackend(t)

	// Closed local port guaranteed to return real OS ECONNREFUSED / WSAECONNREFUSED
	closedLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closedLn.Addr().String()
	_ = closedLn.Close()

	probeLn, _ := net.Listen("tcp4", "127.0.0.1:0")
	proxyPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	cfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         proxyPort,
		WakeTimeout:       config.Duration(3 * time.Second),
		WakeCooldown:      config.Duration(time.Second),
		PollInterval:      config.Duration(35 * time.Millisecond),
		Clients:           map[string]config.Client{"laptop": {CIDR: "127.0.0.1/32"}},
		Profiles:          map[string]config.Profile{"ssh": {Port: 22, Wake: config.WakeAuto}},
		Targets: []config.Target{{
			Name:     "pc1",
			IP:       "192.168.0.21",
			MAC:      "aa:bb:cc:dd:ee:01",
			Profiles: []string{"ssh"},
			Allow:    []string{"laptop"},
		}},
	}

	// Phase: 0 = awake but service stopped (real ECONNREFUSED)
	//        1 = sleeping (EHOSTUNREACH)
	//        2 = booting (real ECONNREFUSED during poll)
	//        3 = service ready (backend echo)
	var phase atomic.Int32
	wolMock := &fakeWoLSender{}

	srv := NewServer(Options{
		Interfaces: testProxyInterfaces(),
		NFT:        &fakeNFT{},
		WoLSender:  wolMock,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		OrigDst: func(_ net.Conn) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("192.168.0.21:22"), nil
		},
		Dial: func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			switch phase.Load() {
			case 0, 2:
				return d.DialContext(ctx, "tcp4", closedAddr)
			case 1:
				return nil, syscall.EHOSTUNREACH
			default:
				return d.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", intToStr(backendPort)))
			}
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())

	// 1. Initial ECONNREFUSED (phase 0) -> closes immediately without sending magic packet!
	t0 := time.Now()
	cRefused, err := net.Dial("tcp4", srv.ListenerAddrs()[0])
	if err != nil {
		t.Fatal(err)
	}
	_ = cRefused.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, rErr := cRefused.Read(make([]byte, 4))
	_ = cRefused.Close()
	if rErr == nil {
		t.Fatal("expected initial ECONNREFUSED connection to close immediately")
	}
	if elapsed := time.Since(t0); elapsed > 400*time.Millisecond {
		t.Fatalf("initial ECONNREFUSED took too long to close: %v", elapsed)
	}
	if got := wolMock.packets.Load(); got != 0 {
		t.Fatalf("expected 0 magic packets on initial ECONNREFUSED, got %d", got)
	}

	// 2. Sleeping (phase 1 -> EHOSTUNREACH) enters wake, transitions to booting (phase 2 -> ECONNREFUSED on poll),
	//    and then ready (phase 3) -> succeeds!
	phase.Store(1)
	cWake, err := net.Dial("tcp4", srv.ListenerAddrs()[0])
	if err != nil {
		t.Fatal(err)
	}
	defer cWake.Close()

	time.Sleep(50 * time.Millisecond)
	phase.Store(2) // Poll now hits real ECONNREFUSED while OS boots before sshd starts
	time.Sleep(90 * time.Millisecond)
	phase.Store(3) // sshd is now up!

	msg := []byte("booted-ok")
	if _, err := cWake.Write(msg); err != nil {
		t.Fatalf("write after wake failed: %v", err)
	}
	got := make([]byte, len(msg))
	_ = cWake.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(cWake, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("expected relay after surviving ECONNREFUSED during poll, got %q err=%v", got, err)
	}
	if wolMock.packets.Load() < 1 {
		t.Fatal("expected magic packet sent for EHOSTUNREACH wake")
	}
}

type dynamicProvider struct {
	mu    sync.Mutex
	items []netutil.InterfaceInfo
}

func (p *dynamicProvider) Interfaces() ([]netutil.InterfaceInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return netutil.StaticProvider{Items: p.items}.Interfaces()
}

func (p *dynamicProvider) InterfaceByName(name string) (netutil.InterfaceInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return netutil.StaticProvider{Items: p.items}.InterfaceByName(name)
}

func TestReloadSucceedsAndKeepsListenerWhenIngressInterfaceMissing(t *testing.T) {
	_, backendPort := startEchoBackend(t)

	probeLn, _ := net.Listen("tcp4", "127.0.0.1:0")
	proxyPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	dynIfaces := &dynamicProvider{
		items: testProxyInterfaces().Items,
	}
	nftMock := &fakeNFT{}

	cfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         proxyPort,
		WakeTimeout:       config.Duration(2 * time.Second),
		WakeCooldown:      config.Duration(time.Second),
		PollInterval:      config.Duration(50 * time.Millisecond),
		Clients:           map[string]config.Client{"laptop": {CIDR: "127.0.0.1/32"}},
		Profiles:          map[string]config.Profile{"ssh": {Port: 22, Wake: config.WakeAuto}},
		Targets: []config.Target{{
			Name:     "pc1",
			IP:       "192.168.0.21",
			MAC:      "aa:bb:cc:dd:ee:01",
			Profiles: []string{"ssh"},
			Allow:    []string{"laptop"},
		}},
	}

	srv := NewServer(Options{
		Interfaces: dynIfaces,
		NFT:        nftMock,
		WoLSender:  &fakeWoLSender{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		OrigDst: func(_ net.Conn) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("192.168.0.22:22"), nil
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

	// Simulate `wg-quick down wg0`: remove wg0 from system interfaces!
	dynIfaces.mu.Lock()
	dynIfaces.items = []netutil.InterfaceInfo{dynIfaces.items[0]} // only eth0 remains
	dynIfaces.mu.Unlock()

	// Add pc2 and reload while wg0 is down -> must succeed with warning, update nft, and keep listener!
	newCfg := cfg.Clone()
	newCfg.Targets = append(newCfg.Targets, config.Target{
		Name:     "pc2",
		IP:       "192.168.0.22",
		MAC:      "aa:bb:cc:dd:ee:02",
		Profiles: []string{"ssh"},
		Allow:    []string{"laptop"},
	})
	if err := srv.Reload(context.Background(), newCfg); err != nil {
		t.Fatalf("expected Reload to succeed with warning when wg0 is down, got: %v", err)
	}

	nftMock.mu.Lock()
	lastRuleset := nftMock.rulesets[len(nftMock.rulesets)-1]
	nftMock.mu.Unlock()
	if !strings.Contains(lastRuleset, "192.168.0.22 . 22") {
		t.Fatalf("expected reloaded nft ruleset to include new target pc2:\n%s", lastRuleset)
	}
	if len(srv.ListenerAddrs()) != 1 {
		t.Fatalf("expected existing wg0 listener preserved while wg0 is down, got %v", srv.ListenerAddrs())
	}

	// Verify preserved listener routes to newly added pc2 immediately when traffic arrives!
	c, err := net.Dial("tcp4", srv.ListenerAddrs()[0])
	if err != nil {
		t.Fatalf("expected preserved listener to accept connection: %v", err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("wg-back"))
	got := make([]byte, 7)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "wg-back" {
		t.Fatalf("expected echo from newly reloaded target pc2, got %q err=%v", got, err)
	}
}

type trackingListener struct {
	net.Listener
	logicalAddr string
	closed      atomic.Bool
	onClose     func()
}

func (l *trackingListener) Close() error {
	if l.closed.CompareAndSwap(false, true) && l.onClose != nil {
		l.onClose()
	}
	return l.Listener.Close()
}

type orderedNFT struct {
	mu      sync.Mutex
	ops     []string
	failErr error
}

func (n *orderedNFT) Apply(_ context.Context, _ string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.failErr != nil {
		return n.failErr
	}
	n.ops = append(n.ops, "apply")
	return nil
}

func (n *orderedNFT) Cleanup(_ context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ops = append(n.ops, "cleanup")
	return nil
}

func TestConcurrentReloadAndShutdownNoPanicOrNFTLeak(t *testing.T) {
	_, backendPort := startEchoBackend(t)

	for iter := 0; iter < 25; iter++ {
		dynIfaces := &dynamicProvider{
			items: testProxyInterfaces().Items,
		}
		nftTracker := &orderedNFT{}
		var openListeners atomic.Int32

		listenFn := func(_ context.Context, addr string) (net.Listener, error) {
			rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			openListeners.Add(1)
			return &trackingListener{
				Listener:    rawLn,
				logicalAddr: addr,
				onClose:     func() { openListeners.Add(-1) },
			}, nil
		}

		cfg := &config.Config{
			LANInterface:      "eth0",
			IngressInterfaces: []string{"wg0"},
			ProxyPort:         13389,
			WakeTimeout:       config.Duration(2 * time.Second),
			WakeCooldown:      config.Duration(500 * time.Millisecond),
			PollInterval:      config.Duration(50 * time.Millisecond),
			Clients:           map[string]config.Client{"laptop": {CIDR: "127.0.0.1/32"}},
			Profiles:          map[string]config.Profile{"ssh": {Port: 22, Wake: config.WakeAuto}},
			Targets: []config.Target{{
				Name:     "pc1",
				IP:       "192.168.0.21",
				MAC:      "aa:bb:cc:dd:ee:01",
				Profiles: []string{"ssh"},
				Allow:    []string{"laptop"},
			}},
		}

		srv := NewServer(Options{
			Interfaces: dynIfaces,
			NFT:        nftTracker,
			WoLSender:  &fakeWoLSender{},
			Listen:     listenFn,
			Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
			OrigDst: func(_ net.Conn) (netip.AddrPort, error) {
				return netip.MustParseAddrPort("192.168.0.21:22"), nil
			},
			Dial: func(ctx context.Context, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", intToStr(backendPort)))
			},
		})

		ctx, cancel := context.WithCancel(context.Background())
		if err := srv.Start(ctx, cfg); err != nil {
			cancel()
			t.Fatalf("iter %d: Start failed: %v", iter, err)
		}

		// Update wg0's IPv4 so Reload binds a brand-new listener and spawns acceptLoop (s.wg.Add(1))
		dynIfaces.mu.Lock()
		dynIfaces.items = []netutil.InterfaceInfo{
			dynIfaces.items[0],
			{
				Name:     "wg0",
				Index:    3,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("10.66.0.99/32")},
				Up:       true,
			},
		}
		dynIfaces.mu.Unlock()

		startGate := make(chan struct{})
		var wg sync.WaitGroup
		for r := 0; r < 4; r++ {
			r := r
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-startGate
				nextCfg := cfg.Clone()
				nextCfg.WakeTimeout = config.Duration(time.Duration(30+r) * time.Second)
				_ = srv.Reload(context.Background(), nextCfg)
			}()
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startGate
			if err := srv.Shutdown(context.Background()); err != nil {
				t.Errorf("iter %d: Shutdown error: %v", iter, err)
			}
		}()

		close(startGate)
		wg.Wait()
		cancel()

		if gotOpen := openListeners.Load(); gotOpen != 0 {
			t.Fatalf("iter %d: leaked %d open listener(s) after concurrent Reload/Shutdown", iter, gotOpen)
		}
		nftTracker.mu.Lock()
		ops := append([]string(nil), nftTracker.ops...)
		nftTracker.mu.Unlock()
		if len(ops) == 0 || ops[len(ops)-1] != "cleanup" {
			t.Fatalf("iter %d: expected final NFT operation to be cleanup, got %v", iter, ops)
		}

		// Post-shutdown Reload must fail without touching NFT or listeners
		if err := srv.Reload(context.Background(), cfg.Clone()); err == nil {
			t.Fatalf("iter %d: expected Reload after Shutdown to fail", iter)
		}
		nftTracker.mu.Lock()
		opsAfter := append([]string(nil), nftTracker.ops...)
		nftTracker.mu.Unlock()
		if len(opsAfter) != len(ops) {
			t.Fatalf("iter %d: post-shutdown Reload touched NFT: %v -> %v", iter, ops, opsAfter)
		}
	}
}

func TestReloadRollbackOnNFTApplyAndBindFailurePreservesListenersAndState(t *testing.T) {
	_, backendPort := startEchoBackend(t)

	dynIfaces := &dynamicProvider{
		items: testProxyInterfaces().Items,
	}
	nftTracker := &orderedNFT{}

	var mu sync.Mutex
	byLogical := make(map[string]*trackingListener)
	var failBindAddr string

	listenFn := func(_ context.Context, addr string) (net.Listener, error) {
		mu.Lock()
		shouldFail := failBindAddr != "" && addr == failBindAddr
		mu.Unlock()
		if shouldFail {
			return nil, errors.New("simulated bind failure")
		}
		rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		tl := &trackingListener{Listener: rawLn, logicalAddr: addr}
		mu.Lock()
		byLogical[addr] = tl
		mu.Unlock()
		return tl, nil
	}

	cfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         13389,
		WakeTimeout:       config.Duration(2 * time.Second),
		WakeCooldown:      config.Duration(500 * time.Millisecond),
		PollInterval:      config.Duration(50 * time.Millisecond),
		Clients:           map[string]config.Client{"laptop": {CIDR: "127.0.0.1/32"}},
		Profiles:          map[string]config.Profile{"ssh": {Port: 22, Wake: config.WakeAuto}},
		Targets: []config.Target{{
			Name:     "pc1",
			IP:       "192.168.0.21",
			MAC:      "aa:bb:cc:dd:ee:01",
			Profiles: []string{"ssh"},
			Allow:    []string{"laptop"},
		}},
	}

	srv := NewServer(Options{
		Interfaces: dynIfaces,
		NFT:        nftTracker,
		WoLSender:  &fakeWoLSender{},
		Listen:     listenFn,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		OrigDst: func(_ net.Conn) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("192.168.0.21:22"), nil
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

	origListenAddr := srv.ListenerAddrs()[0]
	connExisting, err := net.Dial("tcp4", origListenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer connExisting.Close()

	// Case 1: wg0 IP changes (127.0.0.1 -> 10.66.0.2) AND pc1 is replaced by pc2, but NFT.Apply fails!
	dynIfaces.mu.Lock()
	dynIfaces.items = []netutil.InterfaceInfo{
		dynIfaces.items[0],
		{
			Name:     "wg0",
			Index:    3,
			Prefixes: []netip.Prefix{netip.MustParsePrefix("10.66.0.2/32")},
			Up:       true,
		},
	}
	dynIfaces.mu.Unlock()

	nftTracker.mu.Lock()
	nftTracker.failErr = errors.New("nft apply transaction failed")
	nftTracker.mu.Unlock()

	replacedCfg := cfg.Clone()
	replacedCfg.Targets = []config.Target{{
		Name:     "pc2",
		IP:       "192.168.0.22",
		MAC:      "aa:bb:cc:dd:ee:02",
		Profiles: []string{"ssh"},
		Allow:    []string{"laptop"},
	}}
	if err := srv.Reload(context.Background(), replacedCfg); err == nil {
		t.Fatal("expected Reload to return error when NFT.Apply fails")
	}

	mu.Lock()
	origTL := byLogical["127.0.0.1:13389"]
	newTL := byLogical["10.66.0.2:13389"]
	mu.Unlock()

	if origTL == nil || origTL.closed.Load() {
		t.Fatal("expected original listener 127.0.0.1:13389 to stay open when NFT.Apply fails")
	}
	if newTL == nil || !newTL.closed.Load() {
		t.Fatal("expected newly prepared listener 10.66.0.2:13389 to be closed (rolled back) when NFT.Apply fails")
	}

	// Active connection to pc1 must remain alive, and new connections to pc1 on original listener must still work!
	if _, err := connExisting.Write([]byte("still-ok")); err != nil {
		t.Fatalf("expected existing connection to survive failed Reload: %v", err)
	}
	reply := make([]byte, 8)
	if _, err := io.ReadFull(connExisting, reply); err != nil || string(reply) != "still-ok" {
		t.Fatalf("expected 'still-ok' echo on existing conn, got %q err=%v", reply, err)
	}

	connAfterRollback, err := net.Dial("tcp4", origListenAddr)
	if err != nil {
		t.Fatalf("expected original listener to still accept connections after rollback: %v", err)
	}
	defer connAfterRollback.Close()
	_, _ = connAfterRollback.Write([]byte("pc1-kept"))
	if _, err := io.ReadFull(connAfterRollback, reply); err != nil || string(reply) != "pc1-kept" {
		t.Fatalf("expected curState route to pc1 preserved after rollback, got %q err=%v", reply, err)
	}

	// Case 2: Partial listener bind failure across 2 new addresses rolls back newly bound listener cleanly
	dynIfaces.mu.Lock()
	dynIfaces.items = []netutil.InterfaceInfo{
		dynIfaces.items[0],
		{
			Name:  "wg0",
			Index: 3,
			Prefixes: []netip.Prefix{
				netip.MustParsePrefix("10.66.0.3/32"),
				netip.MustParsePrefix("10.66.0.4/32"),
			},
			Up: true,
		},
	}
	dynIfaces.mu.Unlock()
	mu.Lock()
	failBindAddr = "10.66.0.4:13389"
	mu.Unlock()
	nftTracker.mu.Lock()
	nftTracker.failErr = nil
	nftTracker.mu.Unlock()

	if err := srv.Reload(context.Background(), replacedCfg); err == nil {
		t.Fatal("expected Reload to fail when second new listener fails to bind")
	}
	mu.Lock()
	firstNew := byLogical["10.66.0.3:13389"]
	mu.Unlock()
	if firstNew == nil || !firstNew.closed.Load() {
		t.Fatal("expected partially bound new listener 10.66.0.3:13389 to be closed on bind failure")
	}
	if origTL.closed.Load() {
		t.Fatal("expected original listener to remain open on partial bind failure")
	}
}

func TestReloadRejectsRestartRequiredFieldChangesWithoutPartialApply(t *testing.T) {
	probeLn, _ := net.Listen("tcp4", "127.0.0.1:0")
	proxyPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	nftMock := &fakeNFT{}
	cfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         proxyPort,
		WakeTimeout:       config.Duration(2 * time.Second),
		WakeCooldown:      config.Duration(500 * time.Millisecond),
		PollInterval:      config.Duration(50 * time.Millisecond),
		Clients:           map[string]config.Client{"laptop": {CIDR: "127.0.0.1/32"}},
		Profiles:          map[string]config.Profile{"ssh": {Port: 22, Wake: config.WakeAuto}},
		Targets: []config.Target{{
			Name:     "pc1",
			IP:       "192.168.0.21",
			MAC:      "aa:bb:cc:dd:ee:01",
			Profiles: []string{"ssh"},
			Allow:    []string{"laptop"},
		}},
	}

	srv := NewServer(Options{
		Interfaces: testProxyInterfaces(),
		NFT:        nftMock,
		WoLSender:  &fakeWoLSender{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())

	cases := []struct {
		name      string
		mutate    func(c *config.Config)
		wantField string
	}{
		{
			name:      "lan_interface change",
			mutate:    func(c *config.Config) { c.LANInterface = "eth1" },
			wantField: "lan_interface",
		},
		{
			name:      "ingress_interfaces change",
			mutate:    func(c *config.Config) { c.IngressInterfaces = []string{"wg0", "wg1"} },
			wantField: "ingress_interfaces",
		},
		{
			name:      "proxy_port change",
			mutate:    func(c *config.Config) { c.ProxyPort = proxyPort + 10 },
			wantField: "proxy_port",
		},
	}

	for _, tc := range cases {
		next := cfg.Clone()
		tc.mutate(next)
		// Also add pc2 to ensure Reload does NOT partially apply targets/rulesets (no Split-Brain).
		next.Targets = append(next.Targets, config.Target{
			Name:     "pc2",
			IP:       "192.168.0.22",
			MAC:      "aa:bb:cc:dd:ee:02",
			Profiles: []string{"ssh"},
			Allow:    []string{"laptop"},
		})

		err := srv.Reload(context.Background(), next)
		if err == nil {
			t.Fatalf("%s: expected Reload to reject change with explicit error", tc.name)
		}
		if !strings.Contains(err.Error(), tc.wantField) || !strings.Contains(err.Error(), "systemctl restart wolproxy") {
			t.Fatalf("%s: expected error mentioning %q and 'systemctl restart wolproxy', got: %v", tc.name, tc.wantField, err)
		}

		nftMock.mu.Lock()
		applyCount := len(nftMock.rulesets)
		nftMock.mu.Unlock()
		if applyCount != 1 {
			t.Fatalf("%s: expected NFT.Apply count to stay 1 (initial Start only), got %d", tc.name, applyCount)
		}

		srv.connsMu.Lock()
		_, hasPC2 := srv.curState.routes[netip.MustParseAddrPort("192.168.0.22:22")]
		srv.connsMu.Unlock()
		if hasPC2 {
			t.Fatalf("%s: Reload partially applied pc2 despite rejecting restart-required change", tc.name)
		}
	}
}

func TestReloadAbortsWakingOnWakeNeverWhileKeepingRelayingAcrossMetadataChanges(t *testing.T) {
	_, backendPort := startEchoBackend(t)

	probeLn, _ := net.Listen("tcp4", "127.0.0.1:0")
	proxyPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	cfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         proxyPort,
		WakeTimeout:       config.Duration(10 * time.Second),
		WakeCooldown:      config.Duration(time.Second),
		PollInterval:      config.Duration(80 * time.Millisecond),
		Clients:           map[string]config.Client{"laptop": {CIDR: "127.0.0.1/32"}},
		Profiles:          map[string]config.Profile{"ssh": {Port: 22, Wake: config.WakeAuto}},
		Targets: []config.Target{
			{
				Name:     "pc-awake",
				IP:       "192.168.0.21",
				MAC:      "aa:bb:cc:dd:ee:01",
				Profiles: []string{"ssh"},
				Allow:    []string{"laptop"},
			},
			{
				Name:     "pc-sleep",
				IP:       "192.168.0.22",
				MAC:      "aa:bb:cc:dd:ee:02",
				Profiles: []string{"ssh"},
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
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			if addr == "192.168.0.22:22" {
				return nil, syscall.EHOSTUNREACH
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

	listenAddr := srv.ListenerAddrs()[0]

	// 1. Establish a relaying connection to pc-awake
	nextOrigDst.Store(netip.MustParseAddrPort("192.168.0.21:22"))
	connRelay, err := net.Dial("tcp4", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer connRelay.Close()
	if _, err := connRelay.Write([]byte("ping0")); err != nil {
		t.Fatal(err)
	}
	buf5 := make([]byte, 5)
	if _, err := io.ReadFull(connRelay, buf5); err != nil {
		t.Fatal(err)
	}

	// 2. Establish a waking connection to pc-sleep and wait until it enters waking phase
	nextOrigDst.Store(netip.MustParseAddrPort("192.168.0.22:22"))
	connWake, err := net.Dial("tcp4", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer connWake.Close()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		srv.connsMu.Lock()
		w := srv.waitingByTarget["pc-sleep"]
		srv.connsMu.Unlock()
		if w == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 3. Reload:
	//    - Rename profile "ssh" -> "ssh-manual" on port 22 with wake: auto -> never
	//    - Rename target "pc-awake" -> "pc-awake-renamed" and fix MAC typo
	//    - Keep pc-sleep on "ssh-manual" (wake: never)
	reloaded := cfg.Clone()
	reloaded.Profiles = map[string]config.Profile{
		"ssh-manual": {Port: 22, Wake: config.WakeNever},
	}
	reloaded.Targets = []config.Target{
		{
			Name:     "pc-awake-renamed",
			IP:       "192.168.0.21",
			MAC:      "aa:bb:cc:dd:ee:99",
			Profiles: []string{"ssh-manual"},
			Allow:    []string{"laptop"},
		},
		{
			Name:     "pc-sleep",
			IP:       "192.168.0.22",
			MAC:      "aa:bb:cc:dd:ee:02",
			Profiles: []string{"ssh-manual"},
			Allow:    []string{"laptop"},
		},
	}
	if err := srv.Reload(context.Background(), reloaded); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// Waking connection must be aborted immediately due to wake: auto -> never!
	_ = connWake.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := connWake.Read(make([]byte, 4)); err == nil {
		t.Fatal("expected waking connection to be aborted immediately when wake changed auto -> never")
	}

	// Relaying connection must stay alive despite target rename, profile rename, MAC change, and wake: never!
	_ = connRelay.SetDeadline(time.Now().Add(time.Second))
	if _, err := connRelay.Write([]byte("alive")); err != nil {
		t.Fatalf("expected relaying connection to survive metadata/wake/MAC reload: %v", err)
	}
	if _, err := io.ReadFull(connRelay, buf5); err != nil || string(buf5) != "alive" {
		t.Fatalf("expected relaying connection echo 'alive', got %q err=%v", buf5, err)
	}
}

func TestReloadReturnsValidationErrorsBeforeRestartRequiredError(t *testing.T) {
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
		Clients:           map[string]config.Client{"laptop": {CIDR: "127.0.0.1/32"}},
		Profiles:          map[string]config.Profile{"ssh": {Port: 22, Wake: config.WakeAuto}},
		Targets: []config.Target{{
			Name:     "pc1",
			IP:       "192.168.0.21",
			MAC:      "aa:bb:cc:dd:ee:01",
			Profiles: []string{"ssh"},
			Allow:    []string{"laptop"},
		}},
	}

	srv := NewServer(Options{
		Interfaces: testProxyInterfaces(),
		NFT:        &fakeNFT{},
		WoLSender:  &fakeWoLSender{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())

	// 1. Both proxy_port change AND invalid target MAC -> validation error must take precedence!
	badPortAndMAC := cfg.Clone()
	badPortAndMAC.ProxyPort = proxyPort + 10
	badPortAndMAC.Targets[0].MAC = "not-a-valid-mac"
	err := srv.Reload(context.Background(), badPortAndMAC)
	if err == nil {
		t.Fatal("expected Reload error for invalid MAC + changed proxy_port")
	}
	var valErrs config.ValidationErrorList
	if !errors.As(err, &valErrs) {
		t.Fatalf("expected ValidationErrorList before restart-required error, got %T: %v", err, err)
	}
	if strings.Contains(err.Error(), "systemctl restart wolproxy") {
		t.Fatalf("expected validation error rather than restart prompt for broken config, got: %v", err)
	}

	// 2. Both lan_interface change (missing interface -> warning under StrictInterfaces=false) AND duplicate target IP -> validation error takes precedence!
	badLANAndDupIP := cfg.Clone()
	badLANAndDupIP.LANInterface = "eth99"
	badLANAndDupIP.Targets = append(badLANAndDupIP.Targets, config.Target{
		Name:     "pc2",
		IP:       "192.168.0.21", // duplicate of pc1!
		MAC:      "aa:bb:cc:dd:ee:02",
		Profiles: []string{"ssh"},
		Allow:    []string{"laptop"},
	})
	err = srv.Reload(context.Background(), badLANAndDupIP)
	if !errors.As(err, &valErrs) {
		t.Fatalf("expected ValidationErrorList for duplicate IP even when lan_interface changed, got %T: %v", err, err)
	}

	// 3. Surrounding whitespace on unchanged LANInterface / IngressInterfaces does not falsely reject Reload
	trimmedSame := cfg.Clone()
	trimmedSame.LANInterface = " eth0 "
	trimmedSame.IngressInterfaces = []string{" wg0 "}
	if err := srv.Reload(context.Background(), trimmedSame); err != nil {
		t.Fatalf("expected Reload with surrounding whitespace on same interfaces to succeed, got: %v", err)
	}
}

type hookNFT struct {
	mu       sync.Mutex
	rulesets []string
	onApply  func(call int, ruleset string)
}

func (h *hookNFT) Apply(_ context.Context, ruleset string) error {
	h.mu.Lock()
	h.rulesets = append(h.rulesets, ruleset)
	call := len(h.rulesets)
	fn := h.onApply
	h.mu.Unlock()
	if fn != nil {
		fn(call, ruleset)
	}
	return nil
}

func (h *hookNFT) Cleanup(_ context.Context) error { return nil }

func TestConcurrentReloadFromFileAppliesLatestDiskSnapshot(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	probeLn, _ := net.Listen("tcp4", "127.0.0.1:0")
	proxyPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	baseCfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         proxyPort,
		WakeTimeout:       config.Duration(20 * time.Second),
		WakeCooldown:      config.Duration(time.Second),
		PollInterval:      config.Duration(100 * time.Millisecond),
		Clients:           map[string]config.Client{"laptop": {CIDR: "127.0.0.1/32"}},
		Profiles:          map[string]config.Profile{"ssh": {Port: 22, Wake: config.WakeAuto}},
		Targets: []config.Target{{
			Name:     "pc1",
			IP:       "192.168.0.21",
			MAC:      "aa:bb:cc:dd:ee:01",
			Profiles: []string{"ssh"},
			Allow:    []string{"laptop"},
		}},
	}
	if _, err := config.SaveAtomicChecked(cfgPath, baseCfg, nil); err != nil {
		t.Fatal(err)
	}

	inFirstReloadApply := make(chan struct{})
	releaseFirstReloadApply := make(chan struct{})
	nftHook := &hookNFT{
		onApply: func(call int, _ string) {
			// call == 1 is initial Start(); call == 2 is first ReloadFromFile()
			if call == 2 {
				close(inFirstReloadApply)
				<-releaseFirstReloadApply
			}
		},
	}

	srv := NewServer(Options{
		ConfigPath: cfgPath,
		Interfaces: testProxyInterfaces(),
		NFT:        nftHook,
		WoLSender:  &fakeWoLSender{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx, baseCfg); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())

	// Write v1 to disk and start first ReloadFromFile (which pauses inside NFT.Apply while holding lifecycleMu).
	v1 := baseCfg.Clone()
	v1.WakeTimeout = config.Duration(45 * time.Second)
	v1.Targets = append(v1.Targets, config.Target{
		Name:     "pc2",
		IP:       "192.168.0.22",
		MAC:      "aa:bb:cc:dd:ee:02",
		Profiles: []string{"ssh"},
		Allow:    []string{"laptop"},
	})
	if _, err := config.SaveAtomicChecked(cfgPath, v1, nil); err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 2)
	go func() {
		errCh <- srv.ReloadFromFile(context.Background())
	}()

	<-inFirstReloadApply

	// Start second ReloadFromFile BEFORE updating disk to v2? No: update disk to v2 while first holds lifecycleMu,
	// AND verify second ReloadFromFile reads v2 AFTER acquiring lifecycleMu (never reading stale v1 early if queued),
	// plus verify order of rulesets!
	// Even stronger: launch goroutine 2 BEFORE updating disk? Wait: if goroutine 2 blocks on lifecycleMu BEFORE config.Load,
	// then updating disk to v2 WHILE goroutine 2 is waiting on lifecycleMu means goroutine 2 WILL read v2 once unblocked —
	// whereas WITHOUT lifecycleMu around config.Load, goroutine 2 would have ALREADY read stale v1 before blocking on reloadMu!
	r2Started := make(chan struct{})
	go func() {
		close(r2Started)
		errCh <- srv.ReloadFromFile(context.Background())
	}()
	<-r2Started
	// Give goroutine 2 a moment to reach lifecycleMu.Lock() (if config.Load were outside lifecycleMu, it would read v1 right here!)
	time.Sleep(25 * time.Millisecond)

	v2 := v1.Clone()
	v2.WakeTimeout = config.Duration(95 * time.Second)
	v2.Targets = append(v2.Targets, config.Target{
		Name:     "pc3",
		IP:       "192.168.0.23",
		MAC:      "aa:bb:cc:dd:ee:03",
		Profiles: []string{"ssh"},
		Allow:    []string{"laptop"},
	})
	if _, err := config.SaveAtomicChecked(cfgPath, v2, nil); err != nil {
		t.Fatal(err)
	}

	close(releaseFirstReloadApply)

	for i := 0; i < 2; i++ {
		if rErr := <-errCh; rErr != nil {
			t.Fatalf("ReloadFromFile %d failed: %v", i+1, rErr)
		}
	}

	// Because config.Load runs inside lifecycleMu, the queued ReloadFromFile MUST have read v2!
	srv.connsMu.Lock()
	gotWakeTimeout := srv.curState.wakeTimeout
	_, hasPC3 := srv.curState.routes[netip.MustParseAddrPort("192.168.0.23:22")]
	srv.connsMu.Unlock()

	if !hasPC3 || gotWakeTimeout != 95*time.Second {
		t.Fatalf("expected queued ReloadFromFile to load latest v2 after acquiring lifecycleMu, got hasPC3=%v wakeTimeout=%v", hasPC3, gotWakeTimeout)
	}

	nftHook.mu.Lock()
	finalRuleset := nftHook.rulesets[len(nftHook.rulesets)-1]
	applyCountBeforeShutdown := len(nftHook.rulesets)
	nftHook.mu.Unlock()
	if !strings.Contains(finalRuleset, "192.168.0.23 . 22") {
		t.Fatalf("expected final nft ruleset to include pc3 from v2:\n%s", finalRuleset)
	}

	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := srv.ReloadFromFile(context.Background()); err == nil {
		t.Fatal("expected ReloadFromFile after Shutdown to fail")
	}
	nftHook.mu.Lock()
	applyCountAfter := len(nftHook.rulesets)
	nftHook.mu.Unlock()
	if applyCountAfter != applyCountBeforeShutdown {
		t.Fatalf("post-shutdown ReloadFromFile touched NFT: %d -> %d", applyCountBeforeShutdown, applyCountAfter)
	}
}

type recordingWoLSender struct {
	mu    sync.Mutex
	bcast map[string]netip.Addr
}

func (r *recordingWoLSender) SendMagicPacket(_ context.Context, broadcastAddr netip.Addr, mac net.HardwareAddr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bcast == nil {
		r.bcast = make(map[string]netip.Addr)
	}
	r.bcast[mac.String()] = broadcastAddr
	return nil
}

func TestMultiSubnetLANBroadcastAndUpstreamSourceIP(t *testing.T) {
	// Part 1: Verify per-target broadcast address selection on multi-subnet lan_interface
	probeLn, _ := net.Listen("tcp4", "127.0.0.1:0")
	proxyPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	multiLANIfaces := netutil.StaticProvider{
		Items: []netutil.InterfaceInfo{
			{
				Name:  "eth0",
				Index: 2,
				Prefixes: []netip.Prefix{
					netip.MustParsePrefix("192.168.0.10/24"),
					netip.MustParsePrefix("192.168.10.10/24"),
				},
				Up: true,
			},
			{
				Name:     "wg0",
				Index:    3,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
				Up:       true,
			},
		},
	}

	cfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         proxyPort,
		WakeTimeout:       config.Duration(180 * time.Millisecond),
		WakeCooldown:      config.Duration(time.Second),
		PollInterval:      config.Duration(40 * time.Millisecond),
		Clients:           map[string]config.Client{"laptop": {CIDR: "127.0.0.1/32"}},
		Profiles:          map[string]config.Profile{"ssh": {Port: 22, Wake: config.WakeAuto}},
		Targets: []config.Target{
			{
				Name:     "pc-sub1",
				IP:       "192.168.0.21",
				MAC:      "aa:bb:cc:dd:ee:01",
				Profiles: []string{"ssh"},
				Allow:    []string{"laptop"},
			},
			{
				Name:     "pc-sub2",
				IP:       "192.168.10.22",
				MAC:      "aa:bb:cc:dd:ee:02",
				Profiles: []string{"ssh"},
				Allow:    []string{"laptop"},
			},
		},
	}

	recWoL := &recordingWoLSender{}
	var origDst atomic.Value
	srv := NewServer(Options{
		Interfaces: multiLANIfaces,
		NFT:        &fakeNFT{},
		WoLSender:  recWoL,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		OrigDst: func(_ net.Conn) (netip.AddrPort, error) {
			return origDst.Load().(netip.AddrPort), nil
		},
		Dial: func(_ context.Context, _ string) (net.Conn, error) {
			return nil, syscall.EHOSTUNREACH
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())

	for _, dst := range []string{"192.168.0.21:22", "192.168.10.22:22"} {
		origDst.Store(netip.MustParseAddrPort(dst))
		c, err := net.Dial("tcp4", srv.ListenerAddrs()[0])
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = c.Read(make([]byte, 4))
		_ = c.Close()
	}

	recWoL.mu.Lock()
	bcast1 := recWoL.bcast["aa:bb:cc:dd:ee:01"]
	bcast2 := recWoL.bcast["aa:bb:cc:dd:ee:02"]
	recWoL.mu.Unlock()

	if bcast1 != netip.MustParseAddr("192.168.0.255") {
		t.Fatalf("expected pc-sub1 broadcast 192.168.0.255, got %v", bcast1)
	}
	if bcast2 != netip.MustParseAddr("192.168.10.255") {
		t.Fatalf("expected pc-sub2 broadcast 192.168.10.255, got %v", bcast2)
	}

	// Part 2: Verify dialUpstream binds matching subnet's local IPv4 address using 127.0.1.0/24 and 127.0.2.0/24
	lnSub2, err := net.Listen("tcp4", "127.0.2.20:0")
	if err != nil {
		t.Skipf("loopback secondary subnet 127.0.2.20 unavailable on this OS: %v", err)
	}
	defer lnSub2.Close()
	observedSrcCh := make(chan string, 1)
	go func() {
		c, err := lnSub2.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		observedSrcCh <- host
	}()

	srvRealDial := NewServer(Options{
		Interfaces: netutil.StaticProvider{
			Items: []netutil.InterfaceInfo{
				{
					Name:  "lan0",
					Index: 10,
					Prefixes: []netip.Prefix{
						netip.MustParsePrefix("127.0.1.10/24"),
						netip.MustParsePrefix("127.0.2.10/24"),
					},
					Up: true,
				},
			},
		},
		NFT:    &fakeNFT{},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	srvRealDial.connsMu.Lock()
	srvRealDial.curState = &compiledState{
		lanInterface: "lan0",
		lanSourceIP:  netip.MustParseAddr("127.0.1.10"),
		lanInfo: netutil.InterfaceInfo{
			Name: "lan0",
			Prefixes: []netip.Prefix{
				netip.MustParsePrefix("127.0.1.10/24"),
				netip.MustParsePrefix("127.0.2.10/24"),
			},
		},
	}
	srvRealDial.connsMu.Unlock()

	dConn, err := srvRealDial.dialUpstream(context.Background(), lnSub2.Addr().String())
	if err != nil {
		t.Fatalf("dialUpstream to second loopback subnet failed: %v", err)
	}
	_ = dConn.Close()
	if gotSrc := <-observedSrcCh; gotSrc != "127.0.2.10" {
		t.Fatalf("expected dialUpstream to bind second subnet source 127.0.2.10, got %s", gotSrc)
	}
}

func TestIdleStateRingBufferLongWindowAndZeroAlloc(t *testing.T) {
	t0 := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	timeout := 24 * time.Hour
	st := newIdleState(t0, timeout, 100)

	// Simulate 4,000 ticks before timeout with burst at +6h -> never fires before 24h
	cur := t0
	for i := 0; i < 4000; i++ {
		cur = cur.Add(15 * time.Second)
		if cur.Equal(t0.Add(6 * time.Hour)) {
			st.counter.Store(5000)
		}
		if st.check(cur) {
			t.Fatalf("idleState fired before timeout at +%v", cur.Sub(t0))
		}
	}

	// Advance to 29h59m (23h59m since the 5000-byte burst at +6h) -> still active in 24h window!
	for cur.Before(t0.Add(29*time.Hour + 59*time.Minute)) {
		cur = cur.Add(5 * time.Minute)
		if st.check(cur) {
			t.Fatalf("idleState fired prematurely at +%v while +6h burst was still inside 24h window", cur.Sub(t0))
		}
	}

	// Advance past 30h + step (more than 24h since +6h burst, 0 bytes since) -> must fire!
	fired := false
	for i := 0; i < 10; i++ {
		cur = cur.Add(5 * time.Minute)
		if st.check(cur) {
			fired = true
			break
		}
	}
	if !fired {
		t.Fatal("expected idleState to fire once 24h elapsed after +6h burst")
	}

	// Verify strictly 0 heap allocations per check() tick on long window
	allocTime := cur
	allocs := testing.AllocsPerRun(1000, func() {
		allocTime = allocTime.Add(250 * time.Millisecond)
		st.counter.Add(10)
		_ = st.check(allocTime)
	})
	if allocs != 0 {
		t.Fatalf("expected 0 allocs/op in idleState.check ring buffer, got %v", allocs)
	}
}

func TestMultiPortBootECONNREFUSEDJoinsActiveWakeWhileWakeNeverCloses(t *testing.T) {
	_, backendPort := startEchoBackend(t)

	// Closed local port guaranteed to return real OS ECONNREFUSED / WSAECONNREFUSED
	closedLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	_ = closedLn.Close()

	probeLn, _ := net.Listen("tcp4", "127.0.0.1:0")
	proxyPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	cfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         proxyPort,
		WakeTimeout:       config.Duration(3 * time.Second),
		WakeCooldown:      config.Duration(5 * time.Second),
		PollInterval:      config.Duration(40 * time.Millisecond),
		Clients:           map[string]config.Client{"laptop": {CIDR: "127.0.0.1/32"}},
		Profiles: map[string]config.Profile{
			"ssh":   {Port: 22, Wake: config.WakeAuto},
			"rdp":   {Port: 3389, Wake: config.WakeAuto},
			"admin": {Port: 8080, Wake: config.WakeNever},
		},
		Targets: []config.Target{{
			Name:     "pc1",
			IP:       "192.168.0.21",
			MAC:      "aa:bb:cc:dd:ee:01",
			Profiles: []string{"ssh", "rdp", "admin"},
			Allow:    []string{"laptop"},
		}},
	}

	// Phase: 0 = sleeping (EHOSTUNREACH)
	//        1 = OS booting (network stack up -> real ECONNREFUSED on all ports)
	//        2 = services ready (connects to echo backend)
	var phase atomic.Int32
	var nextOrigDst atomic.Value
	wolMock := &fakeWoLSender{}

	srv := NewServer(Options{
		Interfaces: testProxyInterfaces(),
		NFT:        &fakeNFT{},
		WoLSender:  wolMock,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		OrigDst: func(_ net.Conn) (netip.AddrPort, error) {
			return nextOrigDst.Load().(netip.AddrPort), nil
		},
		Dial: func(ctx context.Context, _ string) (net.Conn, error) {
			switch phase.Load() {
			case 0:
				return nil, syscall.EHOSTUNREACH
			case 1:
				var d net.Dialer
				return d.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", intToStr(closedPort)))
			default:
				var d net.Dialer
				return d.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", intToStr(backendPort)))
			}
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())

	listenAddr := srv.ListenerAddrs()[0]

	// 1. Port 22 (wake: auto) arrives while sleeping -> starts target wake cycle
	nextOrigDst.Store(netip.MustParseAddrPort("192.168.0.21:22"))
	cSSH, err := net.Dial("tcp4", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer cSSH.Close()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		srv.connsMu.Lock()
		w := srv.waitingByTarget["pc1"]
		srv.connsMu.Unlock()
		if w == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 2. Target enters boot transition (real ECONNREFUSED on initial 1s dial):
	//    - Port 8080 (wake: never) must close immediately without joining wake!
	//    - Port 3389 (wake: auto) must see HasActiveWake(pc1)==true and join wake wait!
	phase.Store(1)

	nextOrigDst.Store(netip.MustParseAddrPort("192.168.0.21:8080"))
	cNever, err := net.Dial("tcp4", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	_ = cNever.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if _, err := cNever.Read(make([]byte, 4)); err == nil {
		_ = cNever.Close()
		t.Fatal("expected wake:never port 8080 to close immediately on ECONNREFUSED even while pc1 wake is active")
	}
	_ = cNever.Close()

	nextOrigDst.Store(netip.MustParseAddrPort("192.168.0.21:3389"))
	cRDP, err := net.Dial("tcp4", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer cRDP.Close()

	deadline = time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		srv.connsMu.Lock()
		w := srv.waitingByTarget["pc1"]
		srv.connsMu.Unlock()
		if w == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv.connsMu.Lock()
	gotWaiting := srv.waitingByTarget["pc1"]
	srv.connsMu.Unlock()
	if gotWaiting != 2 {
		t.Fatalf("expected port 3389 (wake:auto) hitting boot ECONNREFUSED to join active pc1 wake (2 waiters), got %d", gotWaiting)
	}

	// 3. Services finish starting -> both SSH and RDP connections relay end-to-end!
	phase.Store(2)
	for name, conn := range map[string]net.Conn{"ssh": cSSH, "rdp": cRDP} {
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		payload := []byte("ok-" + name)
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("%s write after wake failed: %v", name, err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("%s relay mismatch: got %q err=%v", name, got, err)
		}
	}
	if got := wolMock.packets.Load(); got != 1 {
		t.Fatalf("expected single coalesced magic packet across SSH+RDP wake cycle, got %d", got)
	}
}
