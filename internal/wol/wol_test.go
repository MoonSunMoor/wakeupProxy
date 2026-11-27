package wol

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
)

func TestBuildMagicPacket(t *testing.T) {
	mac, err := net.ParseMAC("aa:bb:cc:dd:ee:01")
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := BuildMagicPacket(mac)
	if err != nil {
		t.Fatalf("BuildMagicPacket error: %v", err)
	}
	if !bytes.Equal(pkt[:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Fatalf("expected 6 0xFF header bytes, got %x", pkt[:6])
	}
	for i := 0; i < 16; i++ {
		seg := pkt[6+i*6 : 6+(i+1)*6]
		if !bytes.Equal(seg, mac) {
			t.Fatalf("repetition %d mismatch: %x vs %x", i, seg, mac)
		}
	}
}

type fakeSender struct {
	count atomic.Int32
}

func (f *fakeSender) SendMagicPacket(_ context.Context, _ netip.Addr, _ net.HardwareAddr) error {
	f.count.Add(1)
	return nil
}

func TestSingleflightCoalescesAndSurvivesPartialCancel(t *testing.T) {
	sender := &fakeSender{}
	var portOpen atomic.Bool
	var dialCalls atomic.Int32

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	tcpAddr := ln.Addr().(*net.TCPAddr)

	dialFn := func(ctx context.Context, addr string) (net.Conn, error) {
		dialCalls.Add(1)
		if !portOpen.Load() {
			return nil, errors.New("connection refused")
		}
		return DefaultDialFunc(ctx, ln.Addr().String())
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	coord := NewCoordinator(sender, dialFn, logger)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	req := WakeRequest{
		TargetName:    "pc1",
		TargetIP:      netip.MustParseAddr("127.0.0.1"),
		MAC:           mac,
		BroadcastAddr: netip.MustParseAddr("127.0.0.255"),
		Port:          tcpAddr.Port,
		WakeTimeout:   2 * time.Second,
		WakeCooldown:  500 * time.Millisecond,
		PollInterval:  40 * time.Millisecond,
		DialTimeout:   50 * time.Millisecond,
	}

	// Client 1 disconnects early; Clients 2 and 3 keep waiting until port opens.
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2 := context.Background()
	ctx3 := context.Background()

	var wg sync.WaitGroup
	var conn2, conn3 net.Conn
	var err1, err2, err3 error

	wg.Add(3)
	go func() {
		defer wg.Done()
		_, _, err1 = coord.WaitAndDial(ctx1, req)
	}()
	go func() {
		defer wg.Done()
		conn2, _, err2 = coord.WaitAndDial(ctx2, req)
	}()
	go func() {
		defer wg.Done()
		conn3, _, err3 = coord.WaitAndDial(ctx3, req)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel1() // Client 1 cancels while 2 and 3 are still waiting!
	time.Sleep(60 * time.Millisecond)
	portOpen.Store(true)

	wg.Wait()
	if err1 == nil {
		t.Fatal("expected cancelled client 1 to return error")
	}
	if err2 != nil || conn2 == nil {
		t.Fatalf("expected client 2 to succeed, got conn=%v err=%v", conn2, err2)
	}
	defer conn2.Close()
	if err3 != nil || conn3 == nil {
		t.Fatalf("expected client 3 to succeed, got conn=%v err=%v", conn3, err3)
	}
	defer conn3.Close()

	if got := sender.count.Load(); got != 1 {
		t.Fatalf("expected exactly 1 magic packet sent via singleflight, got %d", got)
	}
}

func TestWakeTargetsCLIWaitWithARP(t *testing.T) {
	sender := &fakeSender{}
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	var probes atomic.Int32

	arpProbe := func(_ context.Context, _ netip.Addr) (bool, error) {
		return probes.Add(1) >= 2, nil
	}

	err := WakeTargets(
		context.Background(),
		sender,
		nil,
		arpProbe,
		netip.MustParseAddr("192.168.0.255"),
		[]CLIWakeTarget{{
			Name:  "nas",
			IP:    netip.MustParseAddr("192.168.0.50"),
			MAC:   mac,
			Ports: nil, // no profiles -> ARP mode
		}},
		true,
		time.Second,
		200*time.Millisecond,
		30*time.Millisecond,
	)
	if err != nil {
		t.Fatalf("WakeTargets --wait failed: %v", err)
	}
	if sender.count.Load() < 1 {
		t.Fatal("expected magic packet sent")
	}
}

type closeTrackingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackingConn) Close() error {
	c.closed.Store(true)
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

func TestLastWaiterCancelConcurrentWithPollSuccessDoesNotLeakConn(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Run multiple iterations covering both interleavings:
	// 1) waiter cancels right before dial returns a connection
	// 2) dial returns right as waiter cancels
	for iter := 0; iter < 30; iter++ {
		sender := &fakeSender{}
		dialStarted := make(chan struct{}, 1)
		releaseDial := make(chan struct{})
		c1, c2 := net.Pipe()
		_ = c2.Close()
		tracked := &closeTrackingConn{Conn: c1}

		coord := NewCoordinator(sender, func(_ context.Context, _ string) (net.Conn, error) {
			select {
			case dialStarted <- struct{}{}:
			default:
			}
			<-releaseDial
			return tracked, nil
		}, logger)

		req := WakeRequest{
			TargetName:    "pc1",
			TargetIP:      netip.MustParseAddr("192.168.0.21"),
			MAC:           mac,
			BroadcastAddr: netip.MustParseAddr("192.168.0.255"),
			Port:          3389,
			WakeTimeout:   2 * time.Second,
			WakeCooldown:  time.Second,
			PollInterval:  5 * time.Millisecond,
			DialTimeout:   time.Second,
		}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, _, err := coord.WaitAndDial(ctx, req)
			if err == nil && conn != nil {
				// Even if WaitAndDial returned before ctx cancel took effect, closing conn cleans it up.
				_ = conn.Close()
			}
		}()

		<-dialStarted
		if iter%2 == 0 {
			cancel()
			close(releaseDial)
		} else {
			close(releaseDial)
			cancel()
		}
		<-done

		// Wait briefly for runPortPoll goroutine to finish cleanup.
		deadline := time.Now().Add(200 * time.Millisecond)
		for !tracked.closed.Load() && time.Now().Before(deadline) {
			time.Sleep(2 * time.Millisecond)
		}
		if !tracked.closed.Load() {
			t.Fatalf("iteration %d: leaked firstConn when last waiter cancelled concurrently with poll success", iter)
		}
	}
}

func TestCoordinatorSeparatesChangedTargetMACOrIP(t *testing.T) {
	var sentMACs sync.Map
	sender := senderFunc(func(_ context.Context, _ netip.Addr, mac net.HardwareAddr) error {
		sentMACs.Store(mac.String(), true)
		return nil
	})

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	var allowNewIP atomic.Bool
	coord := NewCoordinator(sender, func(ctx context.Context, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		if host == "192.168.0.22" && allowNewIP.Load() {
			return DefaultDialFunc(ctx, ln.Addr().String())
		}
		return nil, errors.New("sleeping")
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:99")

	// Start a slow wake for pc1 with old IP/MAC
	ctxOld, cancelOld := context.WithCancel(context.Background())
	defer cancelOld()
	go func() {
		_, _, _ = coord.WaitAndDial(ctxOld, WakeRequest{
			TargetName:    "pc1",
			TargetIP:      netip.MustParseAddr("192.168.0.21"),
			MAC:           mac1,
			BroadcastAddr: netip.MustParseAddr("192.168.0.255"),
			Port:          22,
			WakeTimeout:   2 * time.Second,
			WakeCooldown:  time.Second,
			PollInterval:  50 * time.Millisecond,
			DialTimeout:   50 * time.Millisecond,
		})
	}()
	time.Sleep(30 * time.Millisecond)

	// Now pc1's IP and MAC changed on reload; new wake must NOT attach to old IP/MAC wake!
	allowNewIP.Store(true)
	conn, _, err := coord.WaitAndDial(context.Background(), WakeRequest{
		TargetName:    "pc1",
		TargetIP:      netip.MustParseAddr("192.168.0.22"),
		MAC:           mac2,
		BroadcastAddr: netip.MustParseAddr("192.168.0.255"),
		Port:          22,
		WakeTimeout:   time.Second,
		WakeCooldown:  time.Second,
		PollInterval:  20 * time.Millisecond,
		DialTimeout:   50 * time.Millisecond,
	})
	if err != nil || conn == nil {
		t.Fatalf("expected updated pc1 wake to succeed independently, got err=%v", err)
	}
	_ = conn.Close()
	if _, ok := sentMACs.Load(mac2.String()); !ok {
		t.Fatalf("expected magic packet sent to updated MAC %s", mac2)
	}
}

type senderFunc func(ctx context.Context, broadcastAddr netip.Addr, mac net.HardwareAddr) error

func (f senderFunc) SendMagicPacket(ctx context.Context, broadcastAddr netip.Addr, mac net.HardwareAddr) error {
	return f(ctx, broadcastAddr, mac)
}

func TestNewLANDialerBindsSourceIP(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	remoteIPCh := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		remoteIPCh <- host
	}()

	dial := NewLANDialer(netip.MustParseAddr("127.0.0.1"))
	c, err := dial(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("NewLANDialer failed: %v", err)
	}
	_ = c.Close()

	if got := <-remoteIPCh; got != "127.0.0.1" {
		t.Fatalf("expected bound source IP 127.0.0.1, got %s", got)
	}
}

func TestTargetScopedWakeDeadlineSharingRetryAndPioneerCap(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	targetIP := netip.MustParseAddr("192.168.0.21")
	bcast := netip.MustParseAddr("192.168.0.255")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// Case 1: Joining another port when remaining >= wake_timeout/4 shares target deadline without extra retry
	senderShare := &fakeSender{}
	coordShare := NewCoordinator(senderShare, func(context.Context, string) (net.Conn, error) {
		return nil, errors.New("sleeping")
	}, logger)

	wakeTimeout := 240 * time.Millisecond
	req22 := WakeRequest{
		TargetName:    "pc1",
		TargetIP:      targetIP,
		MAC:           mac,
		BroadcastAddr: bcast,
		Port:          22,
		WakeTimeout:   wakeTimeout,
		WakeCooldown:  5 * time.Second,
		PollInterval:  20 * time.Millisecond,
		DialTimeout:   20 * time.Millisecond,
	}
	req3389 := req22
	req3389.Port = 3389

	var wgShare sync.WaitGroup
	wgShare.Add(1)
	go func() {
		defer wgShare.Done()
		_, _, _ = coordShare.WaitAndDial(context.Background(), req22)
	}()

	time.Sleep(60 * time.Millisecond) // remaining ~180ms >= 240ms/4 (60ms)
	if !coordShare.HasActiveWake(req3389) {
		t.Fatal("expected HasActiveWake to be true across different ports of the same target")
	}

	joinStart := time.Now()
	_, _, err3389 := coordShare.WaitAndDial(context.Background(), req3389)
	joinDur := time.Since(joinStart)
	wgShare.Wait()

	if !errors.Is(err3389, ErrWakeTimeout) {
		t.Fatalf("expected ErrWakeTimeout on shared deadline, got %v", err3389)
	}
	if joinDur >= wakeTimeout {
		t.Fatalf("expected second port to share remaining target deadline (<%v), waited %v", wakeTimeout, joinDur)
	}
	if got := senderShare.count.Load(); got != 1 {
		t.Fatalf("expected 1 magic packet when remaining >= wake_timeout/4, got %d", got)
	}
	if coordShare.HasActiveWake(req22) {
		t.Fatal("expected HasActiveWake false once wake cycle finished")
	}

	// Case 2: Remaining < wake_timeout/4:
	// - Same port arrival does NOT trigger retry.
	// - Unawaited OTHER port triggers 1-time retry (immediate magic packet + reset cooldown + deadline = now + wake_timeout),
	//   while pioneer connection on port 22 STILL caps at its original wake_timeout, and a 3rd port cannot trigger a 2nd retry!
	var sentTimesMu sync.Mutex
	var sentTimes []time.Time
	senderRetry := senderFunc(func(_ context.Context, _ netip.Addr, _ net.HardwareAddr) error {
		sentTimesMu.Lock()
		sentTimes = append(sentTimes, time.Now())
		sentTimesMu.Unlock()
		return nil
	})

	var open3389 atomic.Bool
	coordRetry := NewCoordinator(senderRetry, func(ctx context.Context, addr string) (net.Conn, error) {
		_, portStr, _ := net.SplitHostPort(addr)
		if portStr == "3389" && open3389.Load() {
			return DefaultDialFunc(ctx, ln.Addr().String())
		}
		return nil, errors.New("booting")
	}, logger)

	wt := 280 * time.Millisecond
	cooldown := 220 * time.Millisecond
	r22 := WakeRequest{
		TargetName:    "pc1",
		TargetIP:      targetIP,
		MAC:           mac,
		BroadcastAddr: bcast,
		Port:          22,
		WakeTimeout:   wt,
		WakeCooldown:  cooldown,
		PollInterval:  20 * time.Millisecond,
		DialTimeout:   20 * time.Millisecond,
	}
	r3389 := r22
	r3389.Port = 3389
	r8080 := r22
	r8080.Port = 8080

	pioneerStart := time.Now()
	pioneerDone := make(chan time.Duration, 1)
	var pioneerErr error
	go func() {
		_, _, pioneerErr = coordRetry.WaitAndDial(context.Background(), r22)
		pioneerDone <- time.Since(pioneerStart)
	}()

	// Wait until remaining < wt/4 (70ms): at ~225ms, remaining is ~55ms (< 70ms),
	// and periodic resend at 220ms has already occurred once (initial + 1 periodic = 2 packets).
	time.Sleep(230 * time.Millisecond)
	sentTimesMu.Lock()
	beforeSamePort := len(sentTimes)
	sentTimesMu.Unlock()

	// Same-port join (portWaiters[22] > 0) must NOT trigger < wt/4 retry!
	ctxSame, cancelSame := context.WithCancel(context.Background())
	go func() {
		_, _, _ = coordRetry.WaitAndDial(ctxSame, r22)
	}()
	time.Sleep(10 * time.Millisecond)
	cancelSame()
	sentTimesMu.Lock()
	afterSamePort := len(sentTimes)
	sentTimesMu.Unlock()
	if afterSamePort != beforeSamePort {
		t.Fatalf("expected same-port join in < wake_timeout/4 window NOT to send retry packet, got %d -> %d", beforeSamePort, afterSamePort)
	}

	// Now unawaited OTHER port (3389) arrives in < wt/4 window -> triggers immediate 1-time retry!
	retryDone := make(chan error, 1)
	var conn3389 net.Conn
	go func() {
		var err error
		conn3389, _, err = coordRetry.WaitAndDial(context.Background(), r3389)
		retryDone <- err
	}()

	time.Sleep(20 * time.Millisecond)
	sentTimesMu.Lock()
	afterOtherPort := len(sentTimes)
	sentTimesMu.Unlock()
	if afterOtherPort != afterSamePort+1 {
		t.Fatalf("expected immediate retry magic packet when other port arrived with < wake_timeout/4 left, got %d -> %d", afterSamePort, afterOtherPort)
	}

	// Pioneer connection on port 22 MUST still finish around its original wt (~280ms), NOT ~510ms!
	pioneerDur := <-pioneerDone
	if !errors.Is(pioneerErr, ErrWakeTimeout) {
		t.Fatalf("expected pioneer port 22 to time out with ErrWakeTimeout, got %v", pioneerErr)
	}
	if pioneerDur > wt+120*time.Millisecond {
		t.Fatalf("expected pioneer port 22 wait capped at original wake_timeout (%v), got %v", wt, pioneerDur)
	}

	// Wait past original deadline (~340ms total) while port 3389 is still within its reset wt (230ms + 280ms = 510ms),
	// and also verify cooldown timer was reset at 230ms (so no periodic packet before ~450ms)!
	time.Sleep(70 * time.Millisecond) // now ~130ms after retry (< 220ms cooldown)
	sentTimesMu.Lock()
	midRetryCount := len(sentTimes)
	sentTimesMu.Unlock()
	if midRetryCount != afterOtherPort {
		t.Fatalf("expected cooldown timer reset after retry (no resend before %v), got %d -> %d", cooldown, afterOtherPort, midRetryCount)
	}

	// Open port 3389 after pioneer timed out -> port 3389 succeeds!
	open3389.Store(true)
	if err := <-retryDone; err != nil || conn3389 == nil {
		t.Fatalf("expected port 3389 to succeed using reset target deadline, got conn=%v err=%v", conn3389, err)
	}
	_ = conn3389.Close()

	// Verify 3rd port in a single cycle cannot trigger a 2nd retry
	senderOnce := &fakeSender{}
	coordOnce := NewCoordinator(senderOnce, func(context.Context, string) (net.Conn, error) {
		return nil, errors.New("sleeping")
	}, logger)
	shortWT := 160 * time.Millisecond
	q1 := r22
	q1.WakeTimeout = shortWT
	q1.WakeCooldown = 5 * time.Second
	q2 := q1
	q2.Port = 3389
	q3 := q1
	q3.Port = 8080

	var wgOnce sync.WaitGroup
	wgOnce.Add(2)
	go func() {
		defer wgOnce.Done()
		_, _, _ = coordOnce.WaitAndDial(context.Background(), q1)
	}()
	time.Sleep(130 * time.Millisecond) // rem ~30ms < 40ms -> q2 triggers the 1 allowed retry (new deadline = 130+160 = 290ms)
	go func() {
		defer wgOnce.Done()
		_, _, _ = coordOnce.WaitAndDial(context.Background(), q2)
	}()
	time.Sleep(135 * time.Millisecond) // now at ~265ms, rem ~25ms < 40ms -> q3 must NOT trigger a 2nd retry!
	_, _, _ = coordOnce.WaitAndDial(context.Background(), q3)
	wgOnce.Wait()

	if got := senderOnce.count.Load(); got != 2 {
		t.Fatalf("expected at most 2 magic packets (1 initial + 1 retry) across 3 ports, got %d", got)
	}
	_ = r8080
}

func TestWakeTargetsCLIParallelMultiPortAnyAndRefusedRetry(t *testing.T) {
	sender := &fakeSender{}
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:03")

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// Port 22 and 8080 block until context cancellation (1s timeout if not cancelled),
	// Port 3389 returns ECONNREFUSED on initial check, then opens on first poll tick!
	var port3389Checks atomic.Int32
	dialFn := func(ctx context.Context, addr string) (net.Conn, error) {
		_, portStr, _ := net.SplitHostPort(addr)
		if portStr == "3389" {
			if port3389Checks.Add(1) == 1 {
				return nil, errors.New("connection refused")
			}
			return DefaultDialFunc(ctx, ln.Addr().String())
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}

	start := time.Now()
	err = WakeTargets(
		context.Background(),
		sender,
		dialFn,
		nil,
		netip.MustParseAddr("192.168.0.255"),
		[]CLIWakeTarget{{
			Name:  "pc-multi",
			IP:    netip.MustParseAddr("192.168.0.21"),
			MAC:   mac,
			Ports: []int{22, 3389, 8080},
		}},
		true,
		4*time.Second,
		5*time.Second,
		80*time.Millisecond,
	)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("expected WakeTargets --wait to succeed when any port opens after initial refused, got %v", err)
	}
	// Initial parallel check takes ~1s (NOT 2s+ sequential!), then next poll at +80ms succeeds and cancels siblings immediately (< 1.6s total).
	if elapsed >= 1900*time.Millisecond {
		t.Fatalf("expected parallel multi-port dial + early cancel on open (<1.9s), took %v", elapsed)
	}
}
