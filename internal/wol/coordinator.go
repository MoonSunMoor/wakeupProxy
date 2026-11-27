package wol

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
)

var ErrWakeTimeout = errors.New("타깃 깨우기 시간 초과")

// DialFunc dials a TCP endpoint with the provided context.
type DialFunc func(ctx context.Context, addr string) (net.Conn, error)

// DefaultDialFunc dials TCP4 using standard net.Dialer.
func DefaultDialFunc(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	d.KeepAlive = 30 * time.Second
	return d.DialContext(ctx, "tcp4", addr)
}

// NewLANDialer returns a DialFunc that binds outbound TCP connections to localIP
// so targets always observe the homeserver's LAN IPv4 address as the source.
func NewLANDialer(localIP netip.Addr) DialFunc {
	if !localIP.IsValid() || !localIP.Is4() {
		return DefaultDialFunc
	}
	localTCP := &net.TCPAddr{
		IP:   net.IP(localIP.AsSlice()),
		Port: 0,
	}
	return func(ctx context.Context, addr string) (net.Conn, error) {
		d := net.Dialer{
			LocalAddr: localTCP,
			KeepAlive: 30 * time.Second,
		}
		return d.DialContext(ctx, "tcp4", addr)
	}
}

// NewInterfaceDialer returns a DialFunc that binds each outbound TCP connection to
// the local IPv4 address of the subnet on lanInfo matching the destination IP
// (falling back to lanInfo.PrimaryPrefix() when no subnet matches).
func NewInterfaceDialer(lanInfo netutil.InterfaceInfo) DialFunc {
	if len(lanInfo.Prefixes) == 0 {
		return DefaultDialFunc
	}
	return func(ctx context.Context, addr string) (net.Conn, error) {
		var localIP netip.Addr
		if host, _, err := net.SplitHostPort(addr); err == nil {
			if dstIP, pErr := netip.ParseAddr(host); pErr == nil {
				if pfx, ok := lanInfo.ResolvePrefix(dstIP); ok {
					localIP = pfx.Addr()
				}
			}
		}
		if !localIP.IsValid() {
			if pfx, ok := lanInfo.PrimaryPrefix(); ok {
				localIP = pfx.Addr()
			}
		}
		return NewLANDialer(localIP)(ctx, addr)
	}
}

// WakeRequest describes a target and TCP port to wake and wait for.
type WakeRequest struct {
	TargetName    string
	TargetIP      netip.Addr
	MAC           net.HardwareAddr
	BroadcastAddr netip.Addr
	Port          int
	WakeTimeout   time.Duration
	WakeCooldown  time.Duration
	PollInterval  time.Duration
	DialTimeout   time.Duration
}

type targetBeacon struct {
	cancel      context.CancelFunc
	waiters     int
	portWaiters map[int]int
	deadline    time.Time
	retried     bool
	retryCh     chan time.Duration
}

type portWakeCall struct {
	done      chan struct{}
	cancel    context.CancelFunc
	waiters   int
	startedAt time.Time
	deadline  time.Time

	// Protected by Coordinator.mu so waiter cancellation and poll completion
	// synchronize atomically and never leak an unclaimed connection.
	firstConn net.Conn
	err       error
	elapsed   time.Duration
}

func isCallDone(call *portWakeCall) bool {
	select {
	case <-call.done:
		return true
	default:
		return false
	}
}

func makeBeaconKey(req WakeRequest) string {
	return fmt.Sprintf("%s|%s|%s|%s", req.TargetName, req.TargetIP.String(), req.MAC.String(), req.BroadcastAddr.String())
}

func makeCallKey(req WakeRequest) string {
	return fmt.Sprintf("%s|%s|%s|%s|%d", req.TargetName, req.TargetIP.String(), req.MAC.String(), req.BroadcastAddr.String(), req.Port)
}

// Coordinator deduplicates Wake-on-LAN magic packet streams per target and
// port polling per (target, port) across concurrent client connections (singleflight
// with reference-counted cancellation so one client disconnecting never aborts other
// waiting clients, while all clients disconnecting cancels immediately).
type Coordinator struct {
	sender Sender
	dial   DialFunc
	logger *slog.Logger

	mu      sync.Mutex
	beacons map[string]*targetBeacon
	calls   map[string]*portWakeCall
}

func NewCoordinator(sender Sender, dial DialFunc, logger *slog.Logger) *Coordinator {
	if sender == nil {
		sender = UDPSender{}
	}
	if dial == nil {
		dial = DefaultDialFunc
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Coordinator{
		sender:  sender,
		dial:    dial,
		logger:  logger,
		beacons: make(map[string]*targetBeacon),
		calls:   make(map[string]*portWakeCall),
	}
}

func (c *Coordinator) acquireBeaconLocked(bKey string, req WakeRequest, now time.Time) (*targetBeacon, time.Duration) {
	if b, ok := c.beacons[bKey]; ok {
		if b.waiters > 0 && now.Before(b.deadline) {
			rem := b.deadline.Sub(now)
			// When remaining target deadline < wake_timeout/4 and a request arrives on
			// another port with 0 active waiters while other port waiter(s) are active,
			// allow at most one retry per target wake cycle: reset target deadline to
			// now + wake_timeout and immediately transmit 1 magic packet + reset cooldown.
			if !b.retried && b.portWaiters[req.Port] == 0 && rem < req.WakeTimeout/4 {
				b.retried = true
				b.deadline = now.Add(req.WakeTimeout)
				rem = req.WakeTimeout
				select {
				case b.retryCh <- req.WakeCooldown:
				default:
				}
			}
			b.waiters++
			b.portWaiters[req.Port]++
			return b, rem
		}
		// Expired beacon racing right before cleanup: replace with a fresh wake cycle.
		delete(c.beacons, bKey)
		b.cancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	b := &targetBeacon{
		cancel:      cancel,
		waiters:     1,
		portWaiters: map[int]int{req.Port: 1},
		deadline:    now.Add(req.WakeTimeout),
		retryCh:     make(chan time.Duration, 1),
	}
	c.beacons[bKey] = b

	macCopy := append(net.HardwareAddr(nil), req.MAC...)
	go c.runBeacon(ctx, req.TargetName, req.BroadcastAddr, macCopy, req.WakeCooldown, b.retryCh)
	return b, req.WakeTimeout
}

func (c *Coordinator) releaseBeaconLocked(bKey string, b *targetBeacon, port int) {
	if b == nil {
		return
	}
	if pw := b.portWaiters[port]; pw <= 1 {
		delete(b.portWaiters, port)
	} else {
		b.portWaiters[port] = pw - 1
	}
	b.waiters--
	if b.waiters <= 0 {
		if cur, ok := c.beacons[bKey]; ok && cur == b {
			delete(c.beacons, bKey)
		}
		b.cancel()
	}
}

func (c *Coordinator) runBeacon(
	ctx context.Context,
	targetName string,
	bcast netip.Addr,
	mac net.HardwareAddr,
	cooldown time.Duration,
	retryCh <-chan time.Duration,
) {
	if cooldown <= 0 {
		cooldown = 10 * time.Second
	}
	send := func(initial bool) {
		sendCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := c.sender.SendMagicPacket(sendCtx, bcast, mac); err != nil {
			if ctx.Err() == nil {
				c.logger.Error("매직 패킷 송신 실패",
					"target", targetName,
					"broadcast", bcast.String(),
					"mac", mac.String(),
					"error", err,
				)
			}
			return
		}
		c.logger.Info("매직 패킷 송신",
			"target", targetName,
			"broadcast", bcast.String(),
			"mac", mac.String(),
			"resend", !initial,
		)
	}

	send(true)
	ticker := time.NewTicker(cooldown)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case nextCooldown := <-retryCh:
			if ctx.Err() != nil {
				return
			}
			if nextCooldown > 0 {
				cooldown = nextCooldown
			}
			send(false)
			ticker.Reset(cooldown)
			select {
			case <-ticker.C:
			default:
			}
		case <-ticker.C:
			send(false)
		}
	}
}

// HasActiveWake reports whether an in-flight wake cycle already exists for req's target.
func (c *Coordinator) HasActiveWake(req WakeRequest) bool {
	bKey := makeBeaconKey(req)
	now := time.Now()
	c.mu.Lock()
	b, ok := c.beacons[bKey]
	active := ok && b.waiters > 0 && now.Before(b.deadline)
	c.mu.Unlock()
	return active
}

// WaitAndDial triggers (or joins) the in-flight wake operation for req.TargetName
// and returns a connected TCP net.Conn to req.TargetIP:req.Port once it wakes up.
func (c *Coordinator) WaitAndDial(ctx context.Context, req WakeRequest) (net.Conn, time.Duration, error) {
	if req.DialTimeout <= 0 {
		req.DialTimeout = time.Second
	}
	if req.PollInterval <= 0 {
		req.PollInterval = 2 * time.Second
	}
	if req.WakeTimeout <= 0 {
		req.WakeTimeout = 120 * time.Second
	}
	if req.WakeCooldown <= 0 {
		req.WakeCooldown = 10 * time.Second
	}

	bKey := makeBeaconKey(req)
	callKey := makeCallKey(req)

	now := time.Now()
	c.mu.Lock()
	beacon, rem := c.acquireBeaconLocked(bKey, req, now)
	call, exists := c.calls[callKey]
	if exists && ((isCallDone(call) && call.err != nil) || !now.Before(call.deadline)) {
		delete(c.calls, callKey)
		call.cancel()
		exists = false
	}
	if exists {
		call.waiters++
	} else {
		pollTimeout := min(rem, req.WakeTimeout)
		callCtx, cancel := context.WithTimeout(context.Background(), pollTimeout)
		call = &portWakeCall{
			done:      make(chan struct{}),
			cancel:    cancel,
			waiters:   1,
			startedAt: now,
			deadline:  now.Add(pollTimeout),
		}
		c.calls[callKey] = call
		go c.runPortPoll(callCtx, callKey, call, req)
	}
	c.mu.Unlock()

	joinedAt := now
	defer func() {
		var orphan net.Conn
		c.mu.Lock()
		c.releaseBeaconLocked(bKey, beacon, req.Port)
		call.waiters--
		if call.waiters <= 0 {
			if current, ok := c.calls[callKey]; ok && current == call {
				delete(c.calls, callKey)
			}
			call.cancel()
			if call.firstConn != nil {
				orphan = call.firstConn
				call.firstConn = nil
			}
		}
		c.mu.Unlock()
		if orphan != nil {
			_ = orphan.Close()
		}
	}()

	select {
	case <-ctx.Done():
		return nil, time.Since(joinedAt), ctx.Err()
	case <-call.done:
		c.mu.Lock()
		callErr := call.err
		var claimed net.Conn
		if callErr == nil && ctx.Err() == nil && call.firstConn != nil {
			claimed = call.firstConn
			call.firstConn = nil
		}
		c.mu.Unlock()

		if callErr != nil {
			return nil, time.Since(joinedAt), callErr
		}
		if ctx.Err() != nil {
			if claimed != nil {
				_ = claimed.Close()
			}
			return nil, time.Since(joinedAt), ctx.Err()
		}
		if claimed != nil {
			return claimed, time.Since(joinedAt), nil
		}

		// Additional concurrent waiter: dial now that target port is open.
		dialCtx, cancel := context.WithTimeout(ctx, req.DialTimeout)
		defer cancel()
		addr := net.JoinHostPort(req.TargetIP.String(), strconv.Itoa(req.Port))
		conn, err := c.dial(dialCtx, addr)
		return conn, time.Since(joinedAt), err
	}
}

func (c *Coordinator) runPortPoll(ctx context.Context, callKey string, call *portWakeCall, req WakeRequest) {
	defer func() {
		var orphan net.Conn
		c.mu.Lock()
		if current, ok := c.calls[callKey]; ok && current == call {
			delete(c.calls, callKey)
		}
		if call.waiters <= 0 && call.firstConn != nil {
			orphan = call.firstConn
			call.firstConn = nil
		}
		c.mu.Unlock()
		if orphan != nil {
			_ = orphan.Close()
		}
		call.cancel()
		close(call.done)
	}()

	addr := net.JoinHostPort(req.TargetIP.String(), strconv.Itoa(req.Port))
	ticker := time.NewTicker(req.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			elapsed := time.Since(call.startedAt)
			isTimeout := errors.Is(ctx.Err(), context.DeadlineExceeded)
			c.mu.Lock()
			call.elapsed = elapsed
			if isTimeout {
				call.err = ErrWakeTimeout
			} else if call.err == nil {
				call.err = ctx.Err()
			}
			c.mu.Unlock()
			if isTimeout {
				c.logger.Warn("타깃 깨우기 타임아웃",
					"target", req.TargetName,
					"ip", req.TargetIP.String(),
					"port", req.Port,
					"wait_duration", elapsed.Round(time.Millisecond),
				)
			}
			return
		case <-ticker.C:
			dialCtx, cancel := context.WithTimeout(ctx, req.DialTimeout)
			conn, err := c.dial(dialCtx, addr)
			cancel()
			if err == nil {
				elapsed := time.Since(call.startedAt)
				c.mu.Lock()
				if call.waiters <= 0 || ctx.Err() != nil {
					if call.err == nil {
						if ctx.Err() != nil {
							call.err = ctx.Err()
						} else {
							call.err = context.Canceled
						}
					}
					c.mu.Unlock()
					_ = conn.Close()
					return
				}
				call.elapsed = elapsed
				call.firstConn = conn
				c.mu.Unlock()
				c.logger.Info("타깃 깨우기 완료",
					"target", req.TargetName,
					"ip", req.TargetIP.String(),
					"port", req.Port,
					"wait_duration", elapsed.Round(time.Millisecond),
				)
				return
			}
		}
	}
}

// CLIWakeTarget describes a target for `wolproxy wake`.
type CLIWakeTarget struct {
	Name          string
	IP            netip.Addr
	MAC           net.HardwareAddr
	BroadcastAddr netip.Addr // optional per-target broadcast; falls back to WakeTargets bcast when invalid
	Ports         []int      // empty when target has no profiles (falls back to ARP awake check)
}

// AwakeProbeFunc reports whether a profile-less target IP has responded via ARP.
type AwakeProbeFunc func(ctx context.Context, ip netip.Addr) (bool, error)

func targetBroadcast(t CLIWakeTarget, fallback netip.Addr) netip.Addr {
	if t.BroadcastAddr.IsValid() {
		return t.BroadcastAddr
	}
	return fallback
}

// WakeTargets sends magic packets to targets, and when wait is true, polls until
// every target wakes up (via TCP profile port if present, otherwise ARP) or timeout expires.
func WakeTargets(
	ctx context.Context,
	sender Sender,
	dial DialFunc,
	arpProbe AwakeProbeFunc,
	bcast netip.Addr,
	targets []CLIWakeTarget,
	wait bool,
	wakeTimeout, wakeCooldown, pollInterval time.Duration,
) error {
	if sender == nil {
		sender = UDPSender{}
	}
	if dial == nil {
		dial = DefaultDialFunc
	}
	if len(targets) == 0 {
		return errors.New("깨울 타깃을 하나 이상 지정해야 합니다")
	}

	for _, t := range targets {
		if err := sender.SendMagicPacket(ctx, targetBroadcast(t, bcast), t.MAC); err != nil {
			return fmt.Errorf("타깃 %s 매직 패킷 송신 실패: %w", t.Name, err)
		}
	}
	if !wait {
		return nil
	}

	waitCtx, cancel := context.WithTimeout(ctx, wakeTimeout)
	defer cancel()

	errCh := make(chan error, len(targets))
	var wg sync.WaitGroup
	for _, t := range targets {
		t := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- waitSingleTargetCLI(waitCtx, sender, dial, arpProbe, targetBroadcast(t, bcast), t, wakeCooldown, pollInterval)
		}()
	}
	wg.Wait()
	close(errCh)

	var errs []error
	for err := range errCh {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func checkAnyPortOpen(ctx context.Context, dial DialFunc, ip netip.Addr, ports []int) bool {
	if len(ports) == 0 {
		return false
	}
	ipStr := ip.String()
	if len(ports) == 1 {
		dCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		conn, err := dial(dCtx, net.JoinHostPort(ipStr, strconv.Itoa(ports[0])))
		if err == nil {
			_ = conn.Close()
			return true
		}
		return false
	}

	dCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	var opened atomic.Bool
	var wg sync.WaitGroup
	for _, p := range ports {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := dial(dCtx, net.JoinHostPort(ipStr, strconv.Itoa(p)))
			if err == nil {
				_ = conn.Close()
				if opened.CompareAndSwap(false, true) {
					cancel()
				}
			}
		}()
	}
	wg.Wait()
	return opened.Load()
}

func waitSingleTargetCLI(
	ctx context.Context,
	sender Sender,
	dial DialFunc,
	arpProbe AwakeProbeFunc,
	bcast netip.Addr,
	target CLIWakeTarget,
	wakeCooldown, pollInterval time.Duration,
) error {
	checkAwake := func() bool {
		if len(target.Ports) > 0 {
			return checkAnyPortOpen(ctx, dial, target.IP, target.Ports)
		}
		if arpProbe == nil {
			return false
		}
		ok, err := arpProbe(ctx, target.IP)
		return err == nil && ok
	}

	// Quick initial check in case target was already awake.
	if checkAwake() {
		return nil
	}

	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	if wakeCooldown <= 0 {
		wakeCooldown = 10 * time.Second
	}

	pollTicker := time.NewTicker(pollInterval)
	defer pollTicker.Stop()
	resendTicker := time.NewTicker(wakeCooldown)
	defer resendTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("타깃 %s 깨우기 타임아웃 (%s)", target.Name, target.IP)
			}
			return ctx.Err()
		case <-resendTicker.C:
			_ = sender.SendMagicPacket(ctx, bcast, target.MAC)
		case <-pollTicker.C:
			if checkAwake() {
				return nil
			}
		}
	}
}
