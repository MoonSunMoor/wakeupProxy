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
