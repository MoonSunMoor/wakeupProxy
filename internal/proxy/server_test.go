package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
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
