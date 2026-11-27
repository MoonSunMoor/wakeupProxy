package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/MoonSunMoor/wakeupProxy/internal/arp"
	"github.com/MoonSunMoor/wakeupProxy/internal/daemon"
	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
	"github.com/MoonSunMoor/wakeupProxy/internal/proxy"
)

func TestNoArgsNonTTYPrintsHelpAndExitsNonZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, strings.NewReader(""), &stdout, &stderr, func() bool { return false })
	if code == 0 {
		t.Fatal("expected non-zero exit code when stdin is not a TTY")
	}
	if !strings.Contains(stderr.String(), "사용법:") {
		t.Fatalf("expected usage help output on non-TTY, got %q", stderr.String())
	}
}

func TestCheckCommandExitCodes(t *testing.T) {
	ifaces, err := netutil.SystemProvider{}.Interfaces()
	if err != nil {
		t.Skipf("cannot list system interfaces: %v", err)
	}
	var usable []string
	for _, info := range ifaces {
		if len(info.Prefixes) > 0 {
			usable = append(usable, info.Name)
		}
	}
	if len(usable) == 0 {
		t.Skip("no IPv4 interface available on host")
	}
	lanIface := usable[0]
	ingIface := "nonexistent_wg0"
	if len(usable) >= 2 {
		ingIface = usable[1]
	} else if lanIface == ingIface {
		ingIface = "nonexistent_wg1"
	}

	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid.yaml")
	validYAML := `lan_interface: ` + lanIface + `
ingress_interfaces: [` + ingIface + `]
proxy_port: 13389
clients:
  laptop: { cidr: 10.66.0.2/32 }
profiles:
  ssh: { port: 22, wake: auto }
targets: []
`
	if err := os.WriteFile(validPath, []byte(validYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-c", validPath, "check"}, strings.NewReader(""), &stdout, &stderr, func() bool { return false }); code != 0 {
		t.Fatalf("expected valid config check to exit 0, got %d (%s)", code, stderr.String())
	}
	// Also test -c after subcommand
	if code := run([]string{"check", "-c", validPath}, strings.NewReader(""), &stdout, &stderr, func() bool { return false }); code != 0 {
		t.Fatalf("expected check -c <path> to exit 0, got %d (%s)", code, stderr.String())
	}

	// Same interface in lan_interface and ingress_interfaces must fail check
	sameIfacePath := filepath.Join(dir, "same_iface.yaml")
	sameIfaceYAML := `lan_interface: ` + lanIface + `
ingress_interfaces: [` + lanIface + `]
proxy_port: 13389
clients: {}
profiles: {}
targets: []
`
	if err := os.WriteFile(sameIfacePath, []byte(sameIfaceYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := run([]string{"-c", sameIfacePath, "check"}, strings.NewReader(""), &stdout, &stderr, func() bool { return false }); code == 0 {
		t.Fatal("expected check to exit non-zero when lan_interface equals ingress_interfaces")
	}

	// Missing interface (e.g. wg0 down) emits a warning and still exits 0 on check; omitted proxy_port defaults to 13389.
	warnPath := filepath.Join(dir, "missing_wg0.yaml")
	warnYAML := `lan_interface: ` + lanIface + `
ingress_interfaces: [nonexistent_wg99]
clients: {}
profiles: {}
targets: []
`
	if err := os.WriteFile(warnPath, []byte(warnYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := run([]string{"-c", warnPath, "check"}, strings.NewReader(""), &stdout, &stderr, func() bool { return false }); code != 0 {
		t.Fatalf("expected missing ingress interface on check to warn and exit 0, got %d (%s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "경고:") {
		t.Fatalf("expected warning message on stderr for missing interface, got %q", stderr.String())
	}

	invalidPath := filepath.Join(dir, "invalid.yaml")
	_ = os.WriteFile(invalidPath, []byte("lan_interface: nonexistent_iface_xyz\nproxy_port: 99999\n"), 0o644)
	stderr.Reset()
	if code := run([]string{"-c", invalidPath, "check"}, strings.NewReader(""), &stdout, &stderr, func() bool { return false }); code == 0 {
		t.Fatal("expected invalid config check to exit non-zero")
	}
}

func TestReloadCommandBlocksMismatchedConfigPath(t *testing.T) {
	rtDir, err := os.MkdirTemp("", "wprt-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(filepath.Clean(rtDir))
	t.Setenv(daemon.RuntimeDirEnv, rtDir)

	cfgDir := t.TempDir()
	daemonCfg := filepath.Join(cfgDir, "daemon.yaml")
	otherCfg := filepath.Join(cfgDir, "other.yaml")
	_ = os.WriteFile(daemonCfg, []byte("proxy_port: 13389\n"), 0o644)
	_ = os.WriteFile(otherCfg, []byte("proxy_port: 13389\n"), 0o644)

	st := daemon.NewRuntimeState(daemonCfg, proxy.RuntimeSnapshot{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         13389,
	}, time.Time{})
	if err := daemon.WriteRuntimeState(rtDir, st); err != nil {
		t.Fatal(err)
	}

	var reloadCount atomic.Int32
	cs, err := daemon.StartControlServer(rtDir, func(_ context.Context) error {
		reloadCount.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	var stdout, stderr bytes.Buffer
	// 1. Mismatched -c path -> rejected before hitting control socket!
	code := run([]string{"-c", otherCfg, "reload"}, strings.NewReader(""), &stdout, &stderr, func() bool { return false })
	if code == 0 {
		t.Fatal("expected non-zero exit code when -c path differs from running daemon config_path")
	}
	if !strings.Contains(stderr.String(), "다릅니다") {
		t.Fatalf("expected mismatch error on stderr, got: %q", stderr.String())
	}
	if reloadCount.Load() != 0 {
		t.Fatalf("expected 0 daemon reload invocations on path mismatch, got %d", reloadCount.Load())
	}

	// 2. Normalized equivalent relative path -> succeeds!
	subDir := filepath.Join(cfgDir, "sub")
	_ = os.MkdirAll(subDir, 0o755)
	equivPath := filepath.Join(subDir, "..", "daemon.yaml")
	stderr.Reset()
	code = run([]string{"-c", equivPath, "reload"}, strings.NewReader(""), &stdout, &stderr, func() bool { return false })
	if code != 0 || reloadCount.Load() != 1 {
		t.Fatalf("expected equivalent normalized -c path to reload (code=%d, count=%d, stderr=%q)", code, reloadCount.Load(), stderr.String())
	}

	// 3. Omitted -c -> reloads running daemon regardless of custom daemonCfg!
	stderr.Reset()
	code = run([]string{"reload"}, strings.NewReader(""), &stdout, &stderr, func() bool { return false })
	if code != 0 || reloadCount.Load() != 2 {
		t.Fatalf("expected reload without -c to succeed (code=%d, count=%d, stderr=%q)", code, reloadCount.Load(), stderr.String())
	}
}

type stubNFT struct {
	cleaned   atomic.Int32
	onCleanup func()
}

func (s *stubNFT) Apply(_ context.Context, _ string) error { return nil }
func (s *stubNFT) Cleanup(_ context.Context) error {
	if s.onCleanup != nil {
		s.onCleanup()
	}
	s.cleaned.Add(1)
	return nil
}

func TestServeFailsUnderSystemdWhenControlOrStateInitFailsAndWarnsWhenUnmanaged(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgYAML := `lan_interface: eth0
ingress_interfaces: [wg0]
proxy_port: 13389
clients: {}
profiles: {}
targets: []
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	ephemeralListen := func(_ context.Context, _ string) (net.Listener, error) {
		return net.Listen("tcp4", "127.0.0.1:0")
	}
	ifaces := netutil.StaticProvider{
		Items: []netutil.InterfaceInfo{
			{Name: "eth0", Index: 2, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.10/24")}, Up: true},
			{Name: "wg0", Index: 3, Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, Up: true},
		},
	}

	// 1. Managed by systemd (INVOCATION_ID set) + WriteRuntimeState fails -> Shutdown + exit 1!
	badRtFile := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(badRtFile, []byte("file"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(daemon.RuntimeDirEnv, badRtFile)
	t.Setenv("INVOCATION_ID", "systemd-unit-test-id")
	t.Setenv("NOTIFY_SOCKET", "")

	nftManaged := &stubNFT{}
	code := serveWithOptions(cfgPath, io.Discard, proxy.Options{
		ConfigPath: cfgPath,
		Interfaces: ifaces,
		NFT:        nftManaged,
		Listen:     ephemeralListen,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, make(chan os.Signal, 1))
	if code != 1 || nftManaged.cleaned.Load() != 1 {
		t.Fatalf("expected exit 1 and NFT cleanup on WriteRuntimeState failure under INVOCATION_ID, got code=%d cleaned=%d", code, nftManaged.cleaned.Load())
	}

	// 2. Managed by systemd (NOTIFY_SOCKET set) + StartControlServer fails after WriteRuntimeState succeeds -> Shutdown + remove state.json + exit 1!
	rtDirSockBlocked := filepath.Join(dir, "rtsockblocked")
	if err := os.MkdirAll(filepath.Join(rtDirSockBlocked, "control.sock", "nonempty"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(daemon.RuntimeDirEnv, rtDirSockBlocked)
	t.Setenv("INVOCATION_ID", "")
	t.Setenv("NOTIFY_SOCKET", filepath.Join(dir, "fake-notify.sock"))

	nftSockFail := &stubNFT{}
	code = serveWithOptions(cfgPath, io.Discard, proxy.Options{
		ConfigPath: cfgPath,
		Interfaces: ifaces,
		NFT:        nftSockFail,
		Listen:     ephemeralListen,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, make(chan os.Signal, 1))
	if code != 1 || nftSockFail.cleaned.Load() != 1 {
		t.Fatalf("expected exit 1 and NFT cleanup on StartControlServer failure under NOTIFY_SOCKET, got code=%d cleaned=%d", code, nftSockFail.cleaned.Load())
	}
	if _, ok, _ := daemon.ReadRuntimeState(rtDirSockBlocked); ok {
		t.Fatal("expected state.json removed after StartControlServer failure under systemd")
	}

	// 3. Unmanaged manual execution -> warns, keeps running until SIGTERM, and exits 0!
	t.Setenv(daemon.RuntimeDirEnv, badRtFile)
	t.Setenv("INVOCATION_ID", "")
	t.Setenv("NOTIFY_SOCKET", "")
	nftUnmanaged := &stubNFT{}
	sigCh := make(chan os.Signal, 1)
	sigCh <- syscall.SIGTERM
	code = serveWithOptions(cfgPath, io.Discard, proxy.Options{
		ConfigPath: cfgPath,
		Interfaces: ifaces,
		NFT:        nftUnmanaged,
		Listen:     ephemeralListen,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, sigCh)
	if code != 0 || nftUnmanaged.cleaned.Load() != 1 {
		t.Fatalf("expected exit 0 and NFT cleanup in unmanaged mode on SIGTERM, got code=%d cleaned=%d", code, nftUnmanaged.cleaned.Load())
	}

	// 4. On SIGTERM, control socket is closed BEFORE srv.Shutdown() executes!
	validRtDir, err := os.MkdirTemp("", "wpsrv-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(filepath.Clean(validRtDir))
	t.Setenv(daemon.RuntimeDirEnv, validRtDir)

	inCleanup := make(chan struct{})
	releaseCleanup := make(chan struct{})
	nftOrder := &stubNFT{
		onCleanup: func() {
			close(inCleanup)
			<-releaseCleanup
		},
	}
	sigChOrder := make(chan os.Signal, 1)
	doneCode := make(chan int, 1)
	go func() {
		doneCode <- serveWithOptions(cfgPath, io.Discard, proxy.Options{
			ConfigPath: cfgPath,
			Interfaces: ifaces,
			NFT:        nftOrder,
			Listen:     ephemeralListen,
			Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		}, sigChOrder)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for !daemon.HasControlSocket(validRtDir) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !daemon.HasControlSocket(validRtDir) {
		t.Fatal("control.sock did not appear after serve startup")
	}

	sigChOrder <- syscall.SIGTERM
	select {
	case <-inCleanup:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for srv.Shutdown() NFT.Cleanup")
	}

	if daemon.HasControlSocket(validRtDir) {
		close(releaseCleanup)
		t.Fatal("expected control.sock to be closed and removed BEFORE srv.Shutdown() runs")
	}
	if err := daemon.RequestReload(context.Background(), validRtDir); err == nil {
		close(releaseCleanup)
		t.Fatal("expected RequestReload to fail once shutdown starts before srv.Shutdown() completes")
	}
	close(releaseCleanup)
	if gotCode := <-doneCode; gotCode != 0 {
		t.Fatalf("expected clean exit code 0 after SIGTERM, got %d", gotCode)
	}
}

type recordedMagic struct {
	bcast netip.Addr
	mac   string
}

type recordingSender struct {
	packets []recordedMagic
}

func (r *recordingSender) SendMagicPacket(_ context.Context, bcast netip.Addr, mac net.HardwareAddr) error {
	r.packets = append(r.packets, recordedMagic{bcast: bcast, mac: mac.String()})
	return nil
}

func TestRunWakeMultiSubnetBroadcastAndDialer(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "multi_subnet.yaml")
	cfgYAML := `lan_interface: eth0
ingress_interfaces: [wg0]
proxy_port: 13389
wake_timeout: 1s
wake_cooldown: 500ms
poll_interval: 20ms
clients: {}
profiles:
  app: { port: ` + strings.TrimPrefix(net.JoinHostPort("", "0"), ":")[:0] + filepath.Base(net.JoinHostPort("x", string(rune('0'))))[:0] + func() string {
		return strings.Split(ln.Addr().String(), ":")[1]
	}() + `, wake: auto }
targets:
  - name: pc-sub1
    ip: 192.168.0.21
    mac: "aa:bb:cc:dd:ee:01"
    profiles: [app]
    allow: []
  - name: pc-sub2
    ip: 192.168.10.22
    mac: "aa:bb:cc:dd:ee:02"
    profiles: [app]
    allow: []
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	ifaces := netutil.StaticProvider{
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
		},
	}

	sender := &recordingSender{}
	dialedTargets := make(map[string]bool)
	var stderr bytes.Buffer
	code := runWakeWithDeps(
		cfgPath,
		[]string{"pc-sub1", "pc-sub2", "--wait"},
		&stderr,
		ifaces,
		sender,
		func(ctx context.Context, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			dialedTargets[host] = true
			var d net.Dialer
			return d.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strings.Split(ln.Addr().String(), ":")[1]))
		},
		nil,
	)
	_ = port
	if code != 0 {
		t.Fatalf("expected runWakeWithDeps exit 0, got %d (%s)", code, stderr.String())
	}
	if len(sender.packets) != 2 {
		t.Fatalf("expected 2 magic packets, got %+v", sender.packets)
	}
	if sender.packets[0].bcast != netip.MustParseAddr("192.168.0.255") {
		t.Fatalf("expected pc-sub1 broadcast 192.168.0.255, got %v", sender.packets[0].bcast)
	}
	if sender.packets[1].bcast != netip.MustParseAddr("192.168.10.255") {
		t.Fatalf("expected pc-sub2 broadcast 192.168.10.255, got %v", sender.packets[1].bcast)
	}
	if !dialedTargets["192.168.0.21"] || !dialedTargets["192.168.10.22"] {
		t.Fatalf("expected both targets polled during --wait, got %v", dialedTargets)
	}
}

type probeTrackingARP struct {
	isAwakeCalls    atomic.Int32
	probeAwakeCalls atomic.Int32
}

func (p *probeTrackingARP) IsAwake(_ context.Context, _ netutil.InterfaceInfo, _ netip.Addr) (bool, error) {
	p.isAwakeCalls.Add(1)
	return true, nil
}

func (p *probeTrackingARP) ProbeAwake(_ context.Context, _ netutil.InterfaceInfo, _ netip.Addr) (bool, error) {
	return p.probeAwakeCalls.Add(1) >= 2, nil
}

func (p *probeTrackingARP) LookupMAC(_ context.Context, _ netutil.InterfaceInfo, _ netip.Addr) (string, string) {
	return "", ""
}

func (p *probeTrackingARP) ScanSubnet(_ context.Context, _ netutil.InterfaceInfo) ([]arp.DiscoveredHost, error) {
	return nil, nil
}

func TestRunWakeWaitUsesProbeAwakeForProfilelessTarget(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "profileless.yaml")
	cfgYAML := `lan_interface: eth0
ingress_interfaces: [wg0]
proxy_port: 13389
wake_timeout: 1s
wake_cooldown: 500ms
poll_interval: 20ms
clients: {}
profiles: {}
targets:
  - name: nas-only
    ip: 192.168.0.50
    mac: "aa:bb:cc:dd:ee:50"
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	ifaces := netutil.StaticProvider{
		Items: []netutil.InterfaceInfo{
			{Name: "eth0", Index: 2, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.10/24")}, Up: true},
		},
	}
	arpStub := &probeTrackingARP{}
	sender := &recordingSender{}
	var stderr bytes.Buffer
	code := runWakeWithDeps(cfgPath, []string{"nas-only", "--wait"}, &stderr, ifaces, sender, nil, arpStub)
	if code != 0 {
		t.Fatalf("expected runWakeWithDeps --wait to succeed via ProbeAwake, got %d (%s)", code, stderr.String())
	}
	if arpStub.isAwakeCalls.Load() != 0 {
		t.Fatalf("expected wake --wait NOT to call passive IsAwake, got %d", arpStub.isAwakeCalls.Load())
	}
	if arpStub.probeAwakeCalls.Load() < 2 {
		t.Fatalf("expected wake --wait to poll via ProbeAwake, got %d", arpStub.probeAwakeCalls.Load())
	}
}
