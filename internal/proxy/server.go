package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MoonSunMoor/wakeupProxy/internal/config"
	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
	"github.com/MoonSunMoor/wakeupProxy/internal/nft"
	"github.com/MoonSunMoor/wakeupProxy/internal/wol"
)

const initialDialTimeout = 1 * time.Second

// OriginalDstFunc extracts the pre-redirect destination IP:port from an accepted TCP connection.
type OriginalDstFunc func(conn net.Conn) (netip.AddrPort, error)

// ListenFunc creates a TCP listener for an ingress address:port.
type ListenFunc func(ctx context.Context, addr string) (net.Listener, error)

type compiledClient struct {
	name   string
	prefix netip.Prefix
}

type routeEntry struct {
	targetName    string
	targetIP      netip.Addr
	usedAlias     bool
	origDstIP     netip.Addr
	mac           net.HardwareAddr
	broadcastAddr netip.Addr
	profileName   string
	port          int
	wake          string
	idleTimeout   time.Duration
	idleBytes     int64
	allowed       []compiledClient
}

func (r *routeEntry) matchClient(ip netip.Addr) (string, bool) {
	for _, cl := range r.allowed {
		if cl.prefix.Contains(ip) {
			return cl.name, true
		}
	}
	return "", false
}

type compiledState struct {
	cfg               *config.Config
	lanInterface      string
	ingressInterfaces []string
	proxyPort         int
	wakeTimeout       time.Duration
	wakeCooldown      time.Duration
	pollInterval      time.Duration
	routes            map[netip.AddrPort]*routeEntry
}

func compileState(
	cfg *config.Config,
	ifaces netutil.Provider,
	fixedLAN string,
	fixedIngress []string,
	fixedProxyPort int,
) (*compiledState, error) {
	if errs := config.Validate(cfg, ifaces); len(errs) > 0 {
		return nil, errs
	}

	lanName := cfg.LANInterface
	if fixedLAN != "" {
		lanName = fixedLAN
	}
	ingNames := cfg.IngressInterfaces
	if len(fixedIngress) > 0 {
		ingNames = fixedIngress
	}
	proxyPort := cfg.ProxyPort
	if fixedProxyPort > 0 {
		proxyPort = fixedProxyPort
	}

	lanInfo, err := ifaces.InterfaceByName(lanName)
	if err != nil {
		return nil, err
	}
	lanPrefix, ok := lanInfo.PrimaryPrefix()
	if !ok {
		return nil, fmt.Errorf("LAN 인터페이스(%s)에 IPv4 서브넷이 없습니다", lanName)
	}
	bcast, err := netutil.BroadcastAddr(lanPrefix)
	if err != nil {
		return nil, err
	}

	compiledClients := make(map[string]compiledClient, len(cfg.Clients))
	for name, cl := range cfg.Clients {
		pfx, err := netutil.ParseIPv4OrCIDR(cl.CIDR)
		if err != nil {
			return nil, err
		}
		compiledClients[name] = compiledClient{name: name, prefix: pfx}
	}

	routes := make(map[netip.AddrPort]*routeEntry)
	for _, t := range cfg.Targets {
		tIP, err := netutil.ParseIPv4Host(t.IP)
		if err != nil {
			return nil, err
		}
		_, macHW, err := netutil.NormalizeMAC(t.MAC)
		if err != nil {
			return nil, err
		}
		var aliasIP netip.Addr
		hasAlias := strings.TrimSpace(t.Alias) != ""
		if hasAlias {
			aliasIP, err = netutil.ParseIPv4Host(t.Alias)
			if err != nil {
				return nil, err
			}
		}

		allowed := make([]compiledClient, 0, len(t.Allow))
		for _, cn := range t.Allow {
			if cc, ok := compiledClients[cn]; ok {
				allowed = append(allowed, cc)
			}
		}

		for _, pn := range t.Profiles {
			pr := cfg.Profiles[pn]
			port := uint16(pr.Port)

			primaryRoute := &routeEntry{
				targetName:    t.Name,
				targetIP:      tIP,
				usedAlias:     false,
				origDstIP:     tIP,
				mac:           macHW,
				broadcastAddr: bcast,
				profileName:   pn,
				port:          pr.Port,
				wake:          pr.Wake,
				idleTimeout:   pr.IdleTimeout.Std(),
				idleBytes:     pr.IdleBytes,
				allowed:       allowed,
			}
			routes[netip.AddrPortFrom(tIP, port)] = primaryRoute

			if hasAlias {
				aliasRoute := *primaryRoute
				aliasRoute.usedAlias = true
				aliasRoute.origDstIP = aliasIP
				routes[netip.AddrPortFrom(aliasIP, port)] = &aliasRoute
			}
		}
	}

	return &compiledState{
		cfg:               cfg.Clone(),
		lanInterface:      lanName,
		ingressInterfaces: append([]string(nil), ingNames...),
		proxyPort:         proxyPort,
		wakeTimeout:       cfg.WakeTimeout.Std(),
		wakeCooldown:      cfg.WakeCooldown.Std(),
		pollInterval:      cfg.PollInterval.Std(),
		routes:            routes,
	}, nil
}

type trackedConn struct {
	id          uint64
	clientIP    netip.Addr
	clientName  string
	origDst     netip.AddrPort
	targetName  string
	targetIP    netip.Addr
	usedAlias   bool
	profileName string
	port        int

	cancel context.CancelFunc

	mu         sync.Mutex
	clientConn net.Conn
	targetConn net.Conn
	reason     string
	idle       *idleState
}

func (tc *trackedConn) abort(reason string) {
	tc.mu.Lock()
	if tc.reason == "" {
		tc.reason = reason
	}
	cConn := tc.clientConn
	tConn := tc.targetConn
	tc.mu.Unlock()

	tc.cancel()
	if cConn != nil {
		_ = cConn.Close()
	}
	if tConn != nil {
		_ = tConn.Close()
	}
}

func (tc *trackedConn) getReason(fallback string) string {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.reason != "" {
		return tc.reason
	}
	return fallback
}

// Options configures a proxy Server instance.
type Options struct {
	ConfigPath string
	Interfaces netutil.Provider
	NFT        nft.Manager
	WoLSender  wol.Sender
	Dial       wol.DialFunc
	Listen     ListenFunc
	OrigDst    OriginalDstFunc
	Logger     *slog.Logger
	IdleTick   time.Duration
}

// Server is the TCP Wake-on-LAN transparent proxy daemon.
type Server struct {
	opts       Options
	coord      *wol.Coordinator
	state      atomic.Pointer[compiledState]
	nextConnID atomic.Uint64

	listenersMu sync.Mutex
	listeners   []net.Listener
	stopSweeper context.CancelFunc

	connsMu sync.Mutex
	conns   map[uint64]*trackedConn

	wg sync.WaitGroup
}

func NewServer(opts Options) *Server {
	if opts.Interfaces == nil {
		opts.Interfaces = netutil.SystemProvider{}
	}
	if opts.NFT == nil {
		opts.NFT = nft.CLIManager{}
	}
	if opts.Dial == nil {
		opts.Dial = wol.DefaultDialFunc
	}
	if opts.Listen == nil {
		opts.Listen = ListenTCPFreebind
	}
	if opts.OrigDst == nil {
		opts.OrigDst = func(conn net.Conn) (netip.AddrPort, error) {
			tc, ok := conn.(*net.TCPConn)
			if !ok {
				return netip.AddrPort{}, errors.New("TCP 연결이 아닙니다")
			}
			return GetOriginalDst(tc)
		}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.IdleTick <= 0 {
		opts.IdleTick = 250 * time.Millisecond
	}

	coord := wol.NewCoordinator(opts.WoLSender, opts.Dial, opts.Logger)
	return &Server{
		opts:  opts,
		coord: coord,
		conns: make(map[uint64]*trackedConn),
	}
}

// Start loads and validates the initial configuration, binds ingress listeners with
// IP_FREEBIND, installs the atomic nftables ruleset, and starts accepting connections.
func (s *Server) Start(ctx context.Context, cfg *config.Config) error {
	st, err := compileState(cfg, s.opts.Interfaces, "", nil, 0)
	if err != nil {
		return err
	}
	s.state.Store(st)

	// Bind proxy_port on every IPv4 address of each ingress interface.
	var listenAddrs []string
	seenAddr := make(map[netip.AddrPort]bool)
	for _, ifName := range st.ingressInterfaces {
		info, err := s.opts.Interfaces.InterfaceByName(ifName)
		if err != nil {
			return err
		}
		for _, ip := range info.IPv4Addrs() {
			ap := netip.AddrPortFrom(ip, uint16(st.proxyPort))
			if !seenAddr[ap] {
				seenAddr[ap] = true
				listenAddrs = append(listenAddrs, ap.String())
			}
		}
	}
	if len(listenAddrs) == 0 {
		return errors.New("바인드할 유입 인터페이스 IPv4 주소가 없습니다")
	}

	var bound []net.Listener
	for _, addr := range listenAddrs {
		ln, err := s.opts.Listen(ctx, addr)
		if err != nil {
			for _, prev := range bound {
				_ = prev.Close()
			}
			return fmt.Errorf("리스너 바인드 실패(%s): %w", addr, err)
		}
		bound = append(bound, ln)
	}

	ruleset, err := nft.BuildRuleset(st.ingressInterfaces, st.proxyPort, st.cfg)
	if err != nil {
		for _, ln := range bound {
			_ = ln.Close()
		}
		return err
	}
	if err := s.opts.NFT.Apply(ctx, ruleset); err != nil {
		for _, ln := range bound {
			_ = ln.Close()
		}
		return err
	}

	s.listenersMu.Lock()
	s.listeners = bound
	s.listenersMu.Unlock()

	s.opts.Logger.Info("wolproxy 데몬 시작",
		"listen", listenAddrs,
		"lan_interface", st.lanInterface,
		"ingress_interfaces", st.ingressInterfaces,
		"targets", len(st.cfg.Targets),
	)

	sweepCtx, sweepCancel := context.WithCancel(ctx)
	s.listenersMu.Lock()
	s.stopSweeper = sweepCancel
	s.listenersMu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runIdleSweeper(sweepCtx)
	}()

	for _, ln := range bound {
		ln := ln
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.acceptLoop(ln)
		}()
	}

	go func() {
		<-ctx.Done()
		sweepCancel()
	}()

	return nil
}

// ListenerAddrs returns the bound listener addresses (useful for testing).
func (s *Server) ListenerAddrs() []string {
	s.listenersMu.Lock()
	defer s.listenersMu.Unlock()
	out := make([]string, len(s.listeners))
	for i, ln := range s.listeners {
		out[i] = ln.Addr().String()
	}
	return out
}

// Shutdown stops accepting new connections, closes all active connections, and deletes
// the nftables table cleanly (SIGTERM behavior).
func (s *Server) Shutdown(ctx context.Context) error {
	s.listenersMu.Lock()
	lns := s.listeners
	s.listeners = nil
	stopSweep := s.stopSweeper
	s.stopSweeper = nil
	s.listenersMu.Unlock()

	if stopSweep != nil {
		stopSweep()
	}

	for _, ln := range lns {
		_ = ln.Close()
	}

	s.connsMu.Lock()
	active := make([]*trackedConn, 0, len(s.conns))
	for _, tc := range s.conns {
		active = append(active, tc)
	}
	s.connsMu.Unlock()

	for _, tc := range active {
		tc.abort("shutdown")
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}

	if err := s.opts.NFT.Cleanup(ctx); err != nil {
		s.opts.Logger.Error("종료 시 nftables 정리 실패", "error", err)
		return err
	}
	s.opts.Logger.Info("wolproxy 데몬 종료 완료")
	return nil
}

// Reload validates and applies a new Config (SIGHUP behavior):
// - On validation or nftables failure: keeps previous config and logs error.
// - Replaces nftables ruleset atomically in a single transaction.
// - Keeps valid existing connections alive, while immediately closing connections whose
//   target was deleted, profile was removed, or client IP is no longer allowed.
// - Logs a warning if proxy_port, ingress_interfaces, or lan_interface changed (requires restart).
func (s *Server) Reload(ctx context.Context, newCfg *config.Config) error {
	cur := s.state.Load()
	if cur == nil {
		return errors.New("서버가 아직 시작되지 않았습니다")
	}

	next, err := compileState(newCfg, s.opts.Interfaces, cur.lanInterface, cur.ingressInterfaces, cur.proxyPort)
	if err != nil {
		s.opts.Logger.Error("설정 재적재 실패 (기존 설정 유지)", "error", err)
		return err
	}

	if newCfg.LANInterface != cur.lanInterface ||
		!slices.Equal(newCfg.IngressInterfaces, cur.ingressInterfaces) ||
		newCfg.ProxyPort != cur.proxyPort {
		s.opts.Logger.Warn("proxy_port, ingress_interfaces, lan_interface 변경은 서비스 재시작 후 반영됩니다",
			"running_lan_interface", cur.lanInterface,
			"new_lan_interface", newCfg.LANInterface,
			"running_ingress_interfaces", cur.ingressInterfaces,
			"new_ingress_interfaces", newCfg.IngressInterfaces,
			"running_proxy_port", cur.proxyPort,
			"new_proxy_port", newCfg.ProxyPort,
		)
	}

	ruleset, err := nft.BuildRuleset(next.ingressInterfaces, next.proxyPort, next.cfg)
	if err != nil {
		s.opts.Logger.Error("설정 재적재 규칙 생성 실패 (기존 설정 유지)", "error", err)
		return err
	}
	if err := s.opts.NFT.Apply(ctx, ruleset); err != nil {
		s.opts.Logger.Error("설정 재적재 nft 적용 실패 (기존 설정 유지)", "error", err)
		return err
	}

	s.state.Store(next)
	evicted := s.evictRevokedConnections(next)
	s.opts.Logger.Info("설정 재적재 완료",
		"targets", len(next.cfg.Targets),
		"closed_connections", evicted,
	)
	return nil
}

// ReloadFromFile reads opts.ConfigPath and calls Reload.
func (s *Server) ReloadFromFile(ctx context.Context) error {
	cfg, _, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		s.opts.Logger.Error("설정 파일 읽기 실패 (기존 설정 유지)", "path", s.opts.ConfigPath, "error", err)
		return err
	}
	return s.Reload(ctx, cfg)
}

func (s *Server) evictRevokedConnections(next *compiledState) int {
	s.connsMu.Lock()
	snapshot := make([]*trackedConn, 0, len(s.conns))
	for _, tc := range s.conns {
		snapshot = append(snapshot, tc)
	}
	s.connsMu.Unlock()

	evicted := 0
	for _, tc := range snapshot {
		route, ok := next.routes[tc.origDst]
		if !ok {
			tc.abort("config_reload")
			evicted++
			continue
		}
		if route.targetName != tc.targetName ||
			route.targetIP != tc.targetIP ||
			route.usedAlias != tc.usedAlias ||
			route.profileName != tc.profileName ||
			route.port != tc.port {
			tc.abort("config_reload")
			evicted++
			continue
		}
		if _, allowed := route.matchClient(tc.clientIP); !allowed {
			tc.abort("config_reload")
			evicted++
			continue
		}
	}
	return evicted
}

func (s *Server) runIdleSweeper(ctx context.Context) {
	ticker := time.NewTicker(s.opts.IdleTick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.connsMu.Lock()
			var candidates []*trackedConn
			for _, tc := range s.conns {
				if tc.idle != nil {
					candidates = append(candidates, tc)
				}
			}
			s.connsMu.Unlock()

			for _, tc := range candidates {
				if tc.idle.check(now) {
					tc.abort("idle_timeout")
				}
			}
		}
	}
}

func (s *Server) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConn(c)
		}(conn)
	}
}

func extractRemoteIPv4(addr net.Addr) (netip.Addr, bool) {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		ip, ok := netip.AddrFromSlice(tcpAddr.IP)
		if !ok {
			return netip.Addr{}, false
		}
		ip = ip.Unmap()
		return ip, ip.Is4()
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.Addr{}, false
	}
	ip := ap.Addr().Unmap()
	return ip, ip.Is4()
}

func (s *Server) handleConn(clientConn net.Conn) {
	startedAt := time.Now()
	st := s.state.Load()
	if st == nil {
		_ = clientConn.Close()
		return
	}

	clientIP, ok := extractRemoteIPv4(clientConn.RemoteAddr())
	if !ok {
		_ = clientConn.Close()
		return
	}

	origDst, err := s.opts.OrigDst(clientConn)
	if err != nil {
		s.opts.Logger.Warn("연결 거부: 원래 목적지 확인 실패",
			"client_ip", clientIP.String(),
			"error", err,
		)
		_ = clientConn.Close()
		return
	}

	// Reject direct non-redirected connections where original dst equals listener's own IP:port
	// unless explicitly routed.
	if localTCP, ok := clientConn.LocalAddr().(*net.TCPAddr); ok {
		if localIP, ipOK := netip.AddrFromSlice(localTCP.IP); ipOK {
			localAP := netip.AddrPortFrom(localIP.Unmap(), uint16(localTCP.Port))
			if origDst == localAP {
				if _, routed := st.routes[origDst]; !routed {
					s.opts.Logger.Warn("연결 거부: 알 수 없는 목적지(직접 접속)",
						"client_ip", clientIP.String(),
						"orig_dst", origDst.String(),
					)
					_ = clientConn.Close()
					return
				}
			}
		}
	}

	route, ok := st.routes[origDst]
	if !ok {
		s.opts.Logger.Warn("연결 거부: 등록되지 않은 목적지",
			"client_ip", clientIP.String(),
			"orig_dst", origDst.String(),
		)
		_ = clientConn.Close()
		return
	}

	clientName, allowed := route.matchClient(clientIP)
	if !allowed {
		s.opts.Logger.Warn("연결 거부: 허용 목록 밖 출발지",
			"client_ip", clientIP.String(),
			"target", route.targetName,
			"port", route.port,
			"orig_dst", origDst.String(),
		)
		_ = clientConn.Close()
		return
	}

	connCtx, cancel := context.WithCancel(context.Background())
	tc := &trackedConn{
		id:          s.nextConnID.Add(1),
		clientIP:    clientIP,
		clientName:  clientName,
		origDst:     origDst,
		targetName:  route.targetName,
		targetIP:    route.targetIP,
		usedAlias:   route.usedAlias,
		profileName: route.profileName,
		port:        route.port,
		cancel:      cancel,
		clientConn:  clientConn,
	}

	s.connsMu.Lock()
	s.conns[tc.id] = tc
	s.connsMu.Unlock()

	defer func() {
		cancel()
		s.connsMu.Lock()
		delete(s.conns, tc.id)
		s.connsMu.Unlock()
		_ = clientConn.Close()
	}()

	// Step 2: Initial connection attempt to real target IP:port with 1s timeout.
	upstreamAddr := net.JoinHostPort(route.targetIP.String(), strconv.Itoa(route.port))
	dialCtx, dialCancel := context.WithTimeout(connCtx, initialDialTimeout)
	targetConn, dialErr := s.opts.Dial(dialCtx, upstreamAddr)
	dialCancel()

	if dialErr != nil {
		if connCtx.Err() != nil {
			s.logConnClosed(tc, 0, time.Since(startedAt), tc.getReason("aborted"))
			return
		}
		if route.wake != config.WakeAuto {
			s.logConnClosed(tc, 0, time.Since(startedAt), "wake_never")
			return
		}

		// Watch for client disconnecting while waiting for target to wake up.
		watchCtx, watchCancel := context.WithCancel(connCtx)
		clientGone := WatchClientDisconnect(watchCtx, clientConn)

		waitCtx, waitCancel := context.WithCancel(connCtx)
		go func() {
			select {
			case <-clientGone:
				tc.mu.Lock()
				if tc.reason == "" && watchCtx.Err() == nil {
					tc.reason = "client_disconnected"
				}
				tc.mu.Unlock()
				waitCancel()
			case <-watchCtx.Done():
			}
		}()

		wokenConn, _, wakeErr := s.coord.WaitAndDial(waitCtx, wol.WakeRequest{
			TargetName:    route.targetName,
			TargetIP:      route.targetIP,
			MAC:           route.mac,
			BroadcastAddr: route.broadcastAddr,
			Port:          route.port,
			WakeTimeout:   st.wakeTimeout,
			WakeCooldown:  st.wakeCooldown,
			PollInterval:  st.pollInterval,
			DialTimeout:   initialDialTimeout,
		})
		watchCancel()
		waitCancel()

		if wakeErr != nil {
			fallback := "wake_failed"
			if errors.Is(wakeErr, wol.ErrWakeTimeout) {
				fallback = "wake_timeout"
			}
			s.logConnClosed(tc, 0, time.Since(startedAt), tc.getReason(fallback))
			return
		}
		targetConn = wokenConn
	}

	tc.mu.Lock()
	if tc.reason != "" {
		// Aborted concurrently (e.g. SIGHUP or SIGTERM) just as target connected.
		reason := tc.reason
		tc.mu.Unlock()
		_ = targetConn.Close()
		s.logConnClosed(tc, 0, time.Since(startedAt), reason)
		return
	}
	tc.targetConn = targetConn
	if route.idleTimeout > 0 {
		tc.idle = newIdleState(time.Now(), route.idleTimeout, route.idleBytes)
	}
	idle := tc.idle
	tc.mu.Unlock()

	totalBytes, upErr, downErr := relayBidirectional(clientConn, targetConn, idle)

	fallbackReason := "normal"
	if upErr != nil || downErr != nil {
		fallbackReason = "io_error"
	}
	s.logConnClosed(tc, totalBytes, time.Since(startedAt), tc.getReason(fallbackReason))
}

func (s *Server) logConnClosed(tc *trackedConn, totalBytes int64, dur time.Duration, reason string) {
	s.opts.Logger.Info("연결 종료",
		"client", tc.clientName,
		"client_ip", tc.clientIP.String(),
		"target", tc.targetName,
		"target_ip", tc.targetIP.String(),
		"profile", tc.profileName,
		"port", tc.port,
		"bytes", totalBytes,
		"duration", dur.Round(time.Millisecond),
		"reason", reason,
	)
}
