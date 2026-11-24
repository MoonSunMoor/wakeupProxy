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

	firstMu   sync.Mutex
	firstConn net.Conn
	err       error
	elapsed   time.Duration
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

func (c *Coordinator) acquireBeaconLocked(req WakeRequest) {
	if b, ok := c.beacons[req.TargetName]; ok {
		b.waiters++
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &targetBeacon{
		cancel:  cancel,
		waiters: 1,
	}
	c.beacons[req.TargetName] = b

	macCopy := append(net.HardwareAddr(nil), req.MAC...)
	go c.runBeacon(ctx, req.TargetName, req.BroadcastAddr, macCopy, req.WakeCooldown)
}

func (c *Coordinator) releaseBeaconLocked(targetName string) {
	b, ok := c.beacons[targetName]
	if !ok {
		return
	}
	b.waiters--
	if b.waiters <= 0 {
		delete(c.beacons, targetName)
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

	callKey := fmt.Sprintf("%s:%d", req.TargetName, req.Port)

	c.mu.Lock()
	c.acquireBeaconLocked(req)
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
		c.mu.Lock()
		c.releaseBeaconLocked(req.TargetName)
		if current, ok := c.calls[callKey]; ok && current == call {
			call.waiters--
			if call.waiters <= 0 {
				delete(c.calls, callKey)
				call.cancel()
			}
		} else {
			call.waiters--
			if call.waiters <= 0 {
				call.cancel()
			}
		}
		// If the poll succeeded right as the last waiter cancelled, ensure any unclaimed conn is closed.
		if call.waiters <= 0 {
			call.firstMu.Lock()
			if call.firstConn != nil {
				_ = call.firstConn.Close()
				call.firstConn = nil
			}
			call.firstMu.Unlock()
		}
		c.mu.Unlock()
	}()

	select {
	case <-ctx.Done():
		return nil, time.Since(joinedAt), ctx.Err()
	case <-call.done:
		if call.err != nil {
			return nil, time.Since(joinedAt), call.err
		}
		// Claim the connection already established by the poll if available.
		call.firstMu.Lock()
		claimed := call.firstConn
		call.firstConn = nil
		call.firstMu.Unlock()
		if claimed != nil {
			// Re-check caller ctx in case both became ready simultaneously.
			if ctx.Err() != nil {
				_ = claimed.Close()
				return nil, time.Since(joinedAt), ctx.Err()
			}
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
		c.mu.Lock()
		if current, ok := c.calls[callKey]; ok && current == call {
			delete(c.calls, callKey)
		}
		c.mu.Unlock()
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
			call.elapsed = elapsed
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				call.err = ErrWakeTimeout
				c.logger.Warn("타깃 깨우기 타임아웃",
					"target", req.TargetName,
					"ip", req.TargetIP.String(),
					"port", req.Port,
					"wait_duration", elapsed.Round(time.Millisecond),
				)
			} else {
				call.err = ctx.Err()
			}
			return
		case <-ticker.C:
			dialCtx, cancel := context.WithTimeout(ctx, req.DialTimeout)
			conn, err := c.dial(dialCtx, addr)
			cancel()
			if err == nil {
				elapsed := time.Since(call.startedAt)
				call.elapsed = elapsed
				call.firstMu.Lock()
				call.firstConn = conn
				call.firstMu.Unlock()
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
