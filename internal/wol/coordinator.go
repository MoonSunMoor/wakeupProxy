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
	"time"
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
	cancel  context.CancelFunc
	waiters int
}

type portWakeCall struct {
	done      chan struct{}
	cancel    context.CancelFunc
	waiters   int
	startedAt time.Time

	// Protected by Coordinator.mu so waiter cancellation and poll completion
	// synchronize atomically and never leak an unclaimed connection.
	firstConn net.Conn
	err       error
	elapsed   time.Duration
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

func (c *Coordinator) acquireBeaconLocked(bKey string, req WakeRequest) {
	if b, ok := c.beacons[bKey]; ok {
		b.waiters++
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &targetBeacon{
		cancel:  cancel,
		waiters: 1,
	}
	c.beacons[bKey] = b

	macCopy := append(net.HardwareAddr(nil), req.MAC...)
	go c.runBeacon(ctx, req.TargetName, req.BroadcastAddr, macCopy, req.WakeCooldown)
}

func (c *Coordinator) releaseBeaconLocked(bKey string) {
	b, ok := c.beacons[bKey]
	if !ok {
		return
	}
	b.waiters--
	if b.waiters <= 0 {
		delete(c.beacons, bKey)
		b.cancel()
	}
}

func (c *Coordinator) runBeacon(ctx context.Context, targetName string, bcast netip.Addr, mac net.HardwareAddr, cooldown time.Duration) {
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
		case <-ticker.C:
			send(false)
		}
	}
}

// HasActiveWake reports whether an in-flight wake/poll operation already exists for req.
func (c *Coordinator) HasActiveWake(req WakeRequest) bool {
	callKey := makeCallKey(req)
	c.mu.Lock()
	_, ok := c.calls[callKey]
	c.mu.Unlock()
	return ok
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

	c.mu.Lock()
	c.acquireBeaconLocked(bKey, req)
	call, exists := c.calls[callKey]
	if exists {
		call.waiters++
	} else {
		callCtx, cancel := context.WithTimeout(context.Background(), req.WakeTimeout)
		call = &portWakeCall{
			done:      make(chan struct{}),
			cancel:    cancel,
			waiters:   1,
			startedAt: time.Now(),
		}
		c.calls[callKey] = call
		go c.runPortPoll(callCtx, callKey, call, req)
	}
	c.mu.Unlock()

	joinedAt := time.Now()
	defer func() {
		var orphan net.Conn
		c.mu.Lock()
		c.releaseBeaconLocked(bKey)
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
	Name  string
	IP    netip.Addr
	MAC   net.HardwareAddr
	Ports []int // empty when target has no profiles (falls back to ARP awake check)
}

// AwakeProbeFunc reports whether a profile-less target IP has responded via ARP.
type AwakeProbeFunc func(ctx context.Context, ip netip.Addr) (bool, error)

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
		if err := sender.SendMagicPacket(ctx, bcast, t.MAC); err != nil {
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
			errCh <- waitSingleTargetCLI(waitCtx, sender, dial, arpProbe, bcast, t, wakeCooldown, pollInterval)
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
			for _, p := range target.Ports {
				dCtx, cancel := context.WithTimeout(ctx, time.Second)
				conn, err := dial(dCtx, net.JoinHostPort(target.IP.String(), strconv.Itoa(p)))
				cancel()
				if err == nil {
					_ = conn.Close()
					return true
				}
			}
			return false
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
