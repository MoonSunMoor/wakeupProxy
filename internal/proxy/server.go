package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sort"
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

const (
	initialDialTimeout = 1 * time.Second

	DefaultMaxWaitingGlobal    = 256
	DefaultMaxWaitingPerTarget = 32
)

// RuntimeSnapshot describes the active listener/interface configuration bound by a running Server.
type RuntimeSnapshot struct {
	LANInterface      string   `json:"lan_interface"`
	IngressInterfaces []string `json:"ingress_interfaces"`
	ProxyPort         int      `json:"proxy_port"`
	ListenAddrs       []string `json:"listen_addrs"`
}

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
	lanSourceIP       netip.Addr
	lanBroadcast      netip.Addr
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
	strictInterfaces bool,
	prev *compiledState,
) (*compiledState, config.ValidationErrorList, error) {
	rep := config.ValidateWithOptions(cfg, ifaces, config.ValidateOptions{
		StrictInterfaces: strictInterfaces,
	})
	if len(rep.Errors) > 0 {
		return nil, rep.Warnings, rep.Errors
	}

	lanName := cfg.LANInterface
	ingNames := cfg.IngressInterfaces
	proxyPort := cfg.ProxyPort
	if prev != nil {
		lanName = prev.lanInterface
		ingNames = prev.ingressInterfaces
		proxyPort = prev.proxyPort
	}

	var lanSourceIP netip.Addr
	var bcast netip.Addr
	if lanInfo, err := ifaces.InterfaceByName(lanName); err == nil {
		if lanPrefix, ok := lanInfo.PrimaryPrefix(); ok {
			bAddr, bErr := netutil.BroadcastAddr(lanPrefix)
			if bErr != nil {
				return nil, rep.Warnings, bErr
			}
			lanSourceIP = lanPrefix.Addr()
			bcast = bAddr
		}
	}
	if !bcast.IsValid() {
		if prev != nil && prev.lanBroadcast.IsValid() {
			lanSourceIP = prev.lanSourceIP
			bcast = prev.lanBroadcast
		} else {
			return nil, rep.Warnings, fmt.Errorf("LAN 인터페이스(%s)에 IPv4 서브넷이 없습니다", lanName)
		}
	}

	compiledClients := make(map[string]compiledClient, len(cfg.Clients))
	for name, cl := range cfg.Clients {
		pfx, err := netutil.ParseIPv4OrCIDR(cl.CIDR)
		if err != nil {
			return nil, rep.Warnings, err
		}
		compiledClients[name] = compiledClient{name: name, prefix: pfx}
	}

	routes := make(map[netip.AddrPort]*routeEntry)
	for _, t := range cfg.Targets {
		tIP, err := netutil.ParseIPv4Host(t.IP)
		if err != nil {
			return nil, rep.Warnings, err
		}
		_, macHW, err := netutil.NormalizeMAC(t.MAC)
		if err != nil {
			return nil, rep.Warnings, err
		}
		var aliasIP netip.Addr
		hasAlias := strings.TrimSpace(t.Alias) != ""
		if hasAlias {
			aliasIP, err = netutil.ParseIPv4Host(t.Alias)
			if err != nil {
				return nil, rep.Warnings, err
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
		lanSourceIP:       lanSourceIP,
		lanBroadcast:      bcast,
		ingressInterfaces: append([]string(nil), ingNames...),
		proxyPort:         proxyPort,
		wakeTimeout:       cfg.WakeTimeout.Std(),
		wakeCooldown:      cfg.WakeCooldown.Std(),
		pollInterval:      cfg.PollInterval.Std(),
		routes:            routes,
	}, rep.Warnings, nil
}

type trackedConn struct {
	id          uint64
	clientIP    netip.Addr
	clientName  string
	origDst     netip.AddrPort
	targetName  string
	targetIP    netip.Addr
	mac         net.HardwareAddr
	usedAlias   bool
	profileName string
	port        int

	cancel context.CancelFunc
	idle   atomic.Pointer[idleState]

	mu         sync.Mutex
	clientConn net.Conn
	targetConn net.Conn
	reason     string
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
	ConfigPath          string
	Interfaces          netutil.Provider
	NFT                 nft.Manager
	WoLSender           wol.Sender
	Dial                wol.DialFunc
	Listen              ListenFunc
	OrigDst             OriginalDstFunc
	Logger              *slog.Logger
	IdleTick            time.Duration
	MaxWaitingGlobal    int
	MaxWaitingPerTarget int
}

type boundListener struct {
	ln    net.Listener
	iface string
}

// Server is the TCP Wake-on-LAN transparent proxy daemon.
type Server struct {
	opts       Options
	customDial wol.DialFunc
	coord      *wol.Coordinator
	nextConnID atomic.Uint64

	listenersMu     sync.Mutex
	listenersByAddr map[string]boundListener
	stopSweeper     context.CancelFunc

	reloadMu sync.Mutex

	// connsMu serializes active compiledState swaps, ACL evaluation + connection
	// registration, revoked-connection eviction on reload, waiting-connection quotas,
	// and shutdown admission gating so no connection can slip past an ACL reload or shutdown.
	connsMu         sync.Mutex
	curState        *compiledState
	closing         bool
	conns           map[uint64]*trackedConn
	waitingTotal    int
	waitingByTarget map[string]int

	wg sync.WaitGroup
}

func NewServer(opts Options) *Server {
	if opts.Interfaces == nil {
		opts.Interfaces = netutil.SystemProvider{}
	}
	if opts.NFT == nil {
		opts.NFT = nft.CLIManager{}
	}
	customDial := opts.Dial
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
	if opts.MaxWaitingGlobal <= 0 {
		opts.MaxWaitingGlobal = DefaultMaxWaitingGlobal
	}
	if opts.MaxWaitingPerTarget <= 0 {
		opts.MaxWaitingPerTarget = DefaultMaxWaitingPerTarget
	}

	srv := &Server{
		opts:            opts,
		customDial:      customDial,
		listenersByAddr: make(map[string]boundListener),
		conns:           make(map[uint64]*trackedConn),
		waitingByTarget: make(map[string]int),
	}
	srv.coord = wol.NewCoordinator(opts.WoLSender, srv.dialUpstream, opts.Logger)
	return srv
}

func (s *Server) dialUpstream(ctx context.Context, addr string) (net.Conn, error) {
	if s.customDial != nil {
		return s.customDial(ctx, addr)
	}
	s.connsMu.Lock()
	var lanIP netip.Addr
	if s.curState != nil {
		lanIP = s.curState.lanSourceIP
	}
	s.connsMu.Unlock()
	return wol.NewLANDialer(lanIP)(ctx, addr)
}

func (s *Server) syncIngressListeners(ctx context.Context, ingNames []string, proxyPort int, strict bool, startAccept bool) ([]net.Listener, error) {
	var orderedAddrs []string
	desiredOwner := make(map[string]string)
	missingIfaces := make(map[string]bool)

	for _, ifName := range ingNames {
		info, err := s.opts.Interfaces.InterfaceByName(ifName)
		if err != nil {
			if strict {
				return nil, err
			}
			missingIfaces[ifName] = true
			s.opts.Logger.Warn("유입 인터페이스를 찾을 수 없어 기존 리스너를 유지합니다",
				"interface", ifName,
				"error", err,
			)
			continue
		}
		ipAddrs := info.IPv4Addrs()
		if len(ipAddrs) == 0 {
			if strict {
				return nil, fmt.Errorf("유입 인터페이스(%s)에 IPv4 주소가 없습니다", ifName)
			}
			missingIfaces[ifName] = true
			s.opts.Logger.Warn("유입 인터페이스에 IPv4 주소가 없어 기존 리스너를 유지합니다",
				"interface", ifName,
			)
			continue
		}
		for _, ip := range ipAddrs {
			addrStr := netip.AddrPortFrom(ip, uint16(proxyPort)).String()
			if _, seen := desiredOwner[addrStr]; !seen {
				desiredOwner[addrStr] = ifName
				orderedAddrs = append(orderedAddrs, addrStr)
			}
		}
	}

	if strict && len(orderedAddrs) == 0 {
		return nil, errors.New("바인드할 유입 인터페이스 IPv4 주소가 없습니다")
	}

	s.listenersMu.Lock()
	var toBind []string
	for _, a := range orderedAddrs {
		if _, exists := s.listenersByAddr[a]; !exists {
			toBind = append(toBind, a)
		}
	}
	s.listenersMu.Unlock()

	newlyBound := make(map[string]net.Listener, len(toBind))
	for _, addr := range toBind {
		ln, err := s.opts.Listen(ctx, addr)
		if err != nil {
			for _, prev := range newlyBound {
				_ = prev.Close()
			}
			return nil, fmt.Errorf("리스너 바인드 실패(%s): %w", addr, err)
		}
		newlyBound[addr] = ln
	}

	var stale []net.Listener
	var startList []net.Listener

	s.listenersMu.Lock()
	for _, addr := range orderedAddrs {
		if ln, isNew := newlyBound[addr]; isNew {
			s.listenersByAddr[addr] = boundListener{ln: ln, iface: desiredOwner[addr]}
			if startAccept {
				startList = append(startList, ln)
			}
		} else if existing, ok := s.listenersByAddr[addr]; ok {
			existing.iface = desiredOwner[addr]
			s.listenersByAddr[addr] = existing
		}
	}
	for addr, bl := range s.listenersByAddr {
		if _, wanted := desiredOwner[addr]; !wanted && !missingIfaces[bl.iface] {
			delete(s.listenersByAddr, addr)
			stale = append(stale, bl.ln)
		}
	}
	s.listenersMu.Unlock()

	for _, ln := range stale {
		_ = ln.Close()
	}
	for _, ln := range startList {
		ln := ln
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.acceptLoop(ln)
		}()
	}

	out := make([]net.Listener, 0, len(newlyBound))
	for _, addr := range toBind {
		out = append(out, newlyBound[addr])
	}
	return out, nil
}

// Start loads and validates the initial configuration, binds ingress listeners with
// IP_FREEBIND, installs the atomic nftables ruleset, and starts accepting connections.
func (s *Server) Start(ctx context.Context, cfg *config.Config) error {
	st, _, err := compileState(cfg, s.opts.Interfaces, true, nil)
	if err != nil {
		return err
	}

	bound, err := s.syncIngressListeners(ctx, st.ingressInterfaces, st.proxyPort, true, false)
	if err != nil {
		return err
	}

	closeBound := func() {
		s.listenersMu.Lock()
		for k, bl := range s.listenersByAddr {
			_ = bl.ln.Close()
			delete(s.listenersByAddr, k)
		}
		s.listenersMu.Unlock()
	}

	ruleset, err := nft.BuildRuleset(st.ingressInterfaces, st.proxyPort, st.cfg)
	if err != nil {
		closeBound()
		return err
	}
	if err := s.opts.NFT.Apply(ctx, ruleset); err != nil {
		closeBound()
		return err
	}

	s.connsMu.Lock()
	s.closing = false
	s.curState = st
	s.connsMu.Unlock()

	s.opts.Logger.Info("wolproxy 데몬 시작",
		"listen", s.ListenerAddrs(),
		"lan_interface", st.lanInterface,
		"lan_source_ip", st.lanSourceIP.String(),
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

	return nil
}

// ListenerAddrs returns the bound listener addresses sorted consistently.
func (s *Server) ListenerAddrs() []string {
	s.listenersMu.Lock()
	defer s.listenersMu.Unlock()
	out := make([]string, 0, len(s.listenersByAddr))
	for _, bl := range s.listenersByAddr {
		out = append(out, bl.ln.Addr().String())
	}
	sort.Strings(out)
	return out
}

// Snapshot returns the currently active interface/port configuration of the running Server.
func (s *Server) Snapshot() (RuntimeSnapshot, bool) {
	s.connsMu.Lock()
	st := s.curState
	closing := s.closing
	s.connsMu.Unlock()
	if st == nil || closing {
		return RuntimeSnapshot{}, false
	}
	return RuntimeSnapshot{
		LANInterface:      st.lanInterface,
		IngressInterfaces: append([]string(nil), st.ingressInterfaces...),
		ProxyPort:         st.proxyPort,
		ListenAddrs:       s.ListenerAddrs(),
	}, true
}

// Shutdown stops accepting new connections, closes all active connections, and deletes
// the nftables table cleanly (SIGTERM behavior).
func (s *Server) Shutdown(ctx context.Context) error {
	// Mark closing under connsMu first so any accepted socket racing with listener Close
	// is rejected immediately and cannot register after active snapshot.
	s.connsMu.Lock()
	s.closing = true
	active := make([]*trackedConn, 0, len(s.conns))
	for _, tc := range s.conns {
		active = append(active, tc)
	}
	s.connsMu.Unlock()

	s.listenersMu.Lock()
	lns := make([]net.Listener, 0, len(s.listenersByAddr))
	for k, bl := range s.listenersByAddr {
		lns = append(lns, bl.ln)
		delete(s.listenersByAddr, k)
	}
	stopSweep := s.stopSweeper
	s.stopSweeper = nil
	s.listenersMu.Unlock()

	if stopSweep != nil {
		stopSweep()
	}

	for _, ln := range lns {
		_ = ln.Close()
	}

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

// Reload validates and applies a new Config (SIGHUP / synchronous reload behavior):
// - On validation or nftables failure: keeps previous config and logs error.
// - Rebinds ingress listeners if an ingress interface's IPv4 address changed.
// - Replaces nftables ruleset atomically in a single transaction.
// - Atomically swaps state and evicts connections whose target was deleted, IP/MAC changed,
//   profile was removed, or client IP is no longer allowed.
// - Logs a warning if proxy_port, ingress_interfaces, or lan_interface changed (requires restart).
func (s *Server) Reload(ctx context.Context, newCfg *config.Config) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	s.connsMu.Lock()
	cur := s.curState
	closing := s.closing
	s.connsMu.Unlock()

	if cur == nil || closing {
		return errors.New("서버가 실행 중이 아닙니다")
	}

	next, warns, err := compileState(newCfg, s.opts.Interfaces, false, cur)
	for _, w := range warns {
		s.opts.Logger.Warn("설정 재적재 검증 경고", "detail", w.Error())
	}
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

	// Re-sync ingress IPv4 listeners in case an ingress interface changed its IPv4 address;
	// if an ingress interface is temporarily absent (e.g. wg-quick down), log a warning and keep existing listeners.
	if _, err := s.syncIngressListeners(ctx, next.ingressInterfaces, next.proxyPort, false, true); err != nil {
		s.opts.Logger.Error("설정 재적재 리스너 동기화 실패 (기존 설정 유지)", "error", err)
		return err
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

	// Swap active state and collect revoked connections under the same connsMu critical section
	// used by handleConn's ACL check + registration.
	s.connsMu.Lock()
	if s.closing {
		s.connsMu.Unlock()
		return errors.New("서버가 종료 중입니다")
	}
	s.curState = next
	var revoked []*trackedConn
	for _, tc := range s.conns {
		if !isConnStillAuthorized(next, tc) {
			revoked = append(revoked, tc)
		}
	}
	s.connsMu.Unlock()

	for _, tc := range revoked {
		tc.abort("config_reload")
	}

	s.opts.Logger.Info("설정 재적재 완료",
		"targets", len(next.cfg.Targets),
		"closed_connections", len(revoked),
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

func isConnStillAuthorized(next *compiledState, tc *trackedConn) bool {
	route, ok := next.routes[tc.origDst]
	if !ok {
		return false
	}
	if route.targetName != tc.targetName ||
		route.targetIP != tc.targetIP ||
		!bytes.Equal(route.mac, tc.mac) ||
		route.usedAlias != tc.usedAlias ||
		route.profileName != tc.profileName ||
		route.port != tc.port {
		return false
	}
	_, allowed := route.matchClient(tc.clientIP)
	return allowed
}

func (s *Server) acquireWakeSlot(targetName string) bool {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if s.closing {
		return false
	}
	if s.waitingTotal >= s.opts.MaxWaitingGlobal {
		return false
	}
	if s.waitingByTarget[targetName] >= s.opts.MaxWaitingPerTarget {
		return false
	}
	s.waitingTotal++
	s.waitingByTarget[targetName]++
	return true
}

func (s *Server) releaseWakeSlot(targetName string) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if s.waitingTotal > 0 {
		s.waitingTotal--
	}
	if cur := s.waitingByTarget[targetName]; cur <= 1 {
		delete(s.waitingByTarget, targetName)
	} else {
		s.waitingByTarget[targetName] = cur - 1
	}
}

func (s *Server) runIdleSweeper(ctx context.Context) {
	ticker := time.NewTicker(s.opts.IdleTick)
	defer ticker.Stop()

	type idleCandidate struct {
		tc   *trackedConn
		idle *idleState
	}

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.connsMu.Lock()
			candidates := make([]idleCandidate, 0, len(s.conns))
			for _, tc := range s.conns {
				if st := tc.idle.Load(); st != nil {
					candidates = append(candidates, idleCandidate{tc: tc, idle: st})
				}
			}
			s.connsMu.Unlock()

			for _, cand := range candidates {
				if cand.idle.check(now) {
					cand.tc.abort("idle_timeout")
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

	var localAP netip.AddrPort
	var hasLocalAP bool
	if localTCP, ok := clientConn.LocalAddr().(*net.TCPAddr); ok {
		if localIP, ipOK := netip.AddrFromSlice(localTCP.IP); ipOK {
			localAP = netip.AddrPortFrom(localIP.Unmap(), uint16(localTCP.Port))
			hasLocalAP = true
		}
	}

	// Atomically check server state, route, ACL, and register trackedConn under connsMu
	// so Reload() and Shutdown() never race with connection admission.
	s.connsMu.Lock()
	if s.closing || s.curState == nil {
		s.connsMu.Unlock()
		_ = clientConn.Close()
		return
	}
	st := s.curState

	if hasLocalAP && origDst == localAP {
		if _, routed := st.routes[origDst]; !routed {
			s.connsMu.Unlock()
			s.opts.Logger.Warn("연결 거부: 알 수 없는 목적지(직접 접속)",
				"client_ip", clientIP.String(),
				"orig_dst", origDst.String(),
			)
			_ = clientConn.Close()
			return
		}
	}

	route, ok := st.routes[origDst]
	if !ok {
		s.connsMu.Unlock()
		s.opts.Logger.Warn("연결 거부: 등록되지 않은 목적지",
			"client_ip", clientIP.String(),
			"orig_dst", origDst.String(),
		)
		_ = clientConn.Close()
		return
	}

	clientName, allowed := route.matchClient(clientIP)
	if !allowed {
		targetName := route.targetName
		port := route.port
		s.connsMu.Unlock()
		s.opts.Logger.Warn("연결 거부: 허용 목록 밖 출발지",
			"client_ip", clientIP.String(),
			"target", targetName,
			"port", port,
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
		mac:         append(net.HardwareAddr(nil), route.mac...),
		usedAlias:   route.usedAlias,
		profileName: route.profileName,
		port:        route.port,
		cancel:      cancel,
		clientConn:  clientConn,
	}
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
	targetConn, dialErr := s.dialUpstream(dialCtx, upstreamAddr)
	dialCancel()

	if dialErr != nil {
		if connCtx.Err() != nil {
			s.logConnClosed(tc, 0, time.Since(startedAt), tc.getReason("aborted"))
			return
		}
		if route.wake != config.WakeAuto {
			reason := "wake_never"
			if isConnRefused(dialErr) {
				reason = "conn_refused"
			}
			s.logConnClosed(tc, 0, time.Since(startedAt), reason)
			return
		}

		wakeReq := wol.WakeRequest{
			TargetName:    route.targetName,
			TargetIP:      route.targetIP,
			MAC:           route.mac,
			BroadcastAddr: route.broadcastAddr,
			Port:          route.port,
			WakeTimeout:   st.wakeTimeout,
			WakeCooldown:  st.wakeCooldown,
			PollInterval:  st.pollInterval,
			DialTimeout:   initialDialTimeout,
		}
		// Only wake on timeout / EHOSTUNREACH / ENETUNREACH (or join if a wake for this target+port
		// is already in progress). If the target responded with ECONNREFUSED and no wake is active,
		// the host is already awake with the service closed, so close immediately without waking.
		if !shouldWakeOnDialError(dialErr) && !s.coord.HasActiveWake(wakeReq) {
			s.logConnClosed(tc, 0, time.Since(startedAt), tc.getReason(dialFailureReason(dialErr)))
			return
		}

		if !s.acquireWakeSlot(route.targetName) {
			s.opts.Logger.Warn("연결 거부: 깨우기 대기 연결 수 제한 초과",
				"client_ip", clientIP.String(),
				"target", route.targetName,
				"port", route.port,
			)
			s.logConnClosed(tc, 0, time.Since(startedAt), "wake_limit_exceeded")
			return
		}

		targetConn = func() net.Conn {
			defer s.releaseWakeSlot(route.targetName)

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

			wokenConn, _, wakeErr := s.coord.WaitAndDial(waitCtx, wakeReq)
			watchCancel()
			waitCancel()

			if wakeErr != nil {
				fallback := "wake_failed"
				if errors.Is(wakeErr, wol.ErrWakeTimeout) {
					fallback = "wake_timeout"
				}
				s.logConnClosed(tc, 0, time.Since(startedAt), tc.getReason(fallback))
				return nil
			}
			return wokenConn
		}()
		if targetConn == nil {
			return
		}
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
	tc.mu.Unlock()

	var idle *idleState
	if route.idleTimeout > 0 {
		idle = newIdleState(time.Now(), route.idleTimeout, route.idleBytes)
		tc.idle.Store(idle)
	}

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
