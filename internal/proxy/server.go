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

func trimStrings(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.TrimSpace(s)
	}
	return out
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
	st, err := buildCompiledState(cfg, ifaces, prev)
	return st, rep.Warnings, err
}

func buildCompiledState(
	cfg *config.Config,
	ifaces netutil.Provider,
	prev *compiledState,
) (*compiledState, error) {
	lanName := strings.TrimSpace(cfg.LANInterface)
	ingNames := trimStrings(cfg.IngressInterfaces)
	proxyPort := cfg.ProxyPort

	var lanSourceIP netip.Addr
	var bcast netip.Addr
	if lanInfo, err := ifaces.InterfaceByName(lanName); err == nil {
		if lanPrefix, ok := lanInfo.PrimaryPrefix(); ok {
			bAddr, bErr := netutil.BroadcastAddr(lanPrefix)
			if bErr != nil {
				return nil, bErr
			}
			lanSourceIP = lanPrefix.Addr()
			bcast = bAddr
		}
	}
	if !bcast.IsValid() {
		if prev != nil && strings.TrimSpace(prev.lanInterface) == lanName && prev.lanBroadcast.IsValid() {
			lanSourceIP = prev.lanSourceIP
			bcast = prev.lanBroadcast
		} else {
			return nil, fmt.Errorf("LAN 인터페이스(%s)에 IPv4 서브넷이 없습니다", lanName)
		}
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

	normalizedCfg := cfg.Clone()
	normalizedCfg.LANInterface = lanName
	normalizedCfg.IngressInterfaces = append([]string(nil), ingNames...)

	return &compiledState{
		cfg:               normalizedCfg,
		lanInterface:      lanName,
		lanSourceIP:       lanSourceIP,
		lanBroadcast:      bcast,
		ingressInterfaces: append([]string(nil), ingNames...),
		proxyPort:         proxyPort,
		wakeTimeout:       cfg.WakeTimeout.Std(),
		wakeCooldown:      cfg.WakeCooldown.Std(),
		pollInterval:      cfg.PollInterval.Std(),
		routes:            routes,
	}, nil
}

type connPhase uint8

const (
	connPhaseDialing connPhase = iota
	connPhaseWaking
	connPhaseRelaying
)

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

	// phase is read and updated exclusively under Server.connsMu.
	phase connPhase

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
	ln     net.Listener
	iface  string
	closed *atomic.Bool
}

type preparedListeners struct {
	orderedAddrs  []string
	desiredOwner  map[string]string
	missingIfaces map[string]bool
	newlyBound    map[string]net.Listener
}

func (p *preparedListeners) rollback() {
	if p == nil {
		return
	}
	for _, ln := range p.newlyBound {
		_ = ln.Close()
	}
}

// Server is the TCP Wake-on-LAN transparent proxy daemon.
type Server struct {
	opts       Options
	customDial wol.DialFunc
	coord      *wol.Coordinator
	nextConnID atomic.Uint64

	// lifecycleMu serializes Start, Reload, and Shutdown so listener binding,
	// WaitGroup Add/Wait, and NFT Apply/Cleanup can never race with each other.
	lifecycleMu sync.Mutex
	started     bool
	stopped     bool

	listenersMu     sync.Mutex
	listenersByAddr map[string]boundListener
	stopSweeper     context.CancelFunc

	// connsMu serializes active compiledState swaps, ACL evaluation + connection
	// registration, connection phase transitions, revoked-connection eviction on reload,
	// waiting-connection quotas, and shutdown admission gating.
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

// prepareIngressListeners binds only newly added ingress listener addresses without
// modifying s.listenersByAddr or closing any existing listeners. On error, any newly
// bound listeners from this call are closed before returning.
func (s *Server) prepareIngressListeners(ctx context.Context, ingNames []string, proxyPort int, strict bool) (*preparedListeners, error) {
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

	return &preparedListeners{
		orderedAddrs:  orderedAddrs,
		desiredOwner:  desiredOwner,
		missingIfaces: missingIfaces,
		newlyBound:    newlyBound,
	}, nil
}

// commitIngressListeners registers newly bound listeners, starts their acceptLoops,
// and closes stale listeners that are no longer needed. Must be called under lifecycleMu.
func (s *Server) commitIngressListeners(prep *preparedListeners) {
	if prep == nil {
		return
	}

	var stale []boundListener
	var startList []boundListener

	s.listenersMu.Lock()
	for _, addr := range prep.orderedAddrs {
		if ln, isNew := prep.newlyBound[addr]; isNew {
			bl := boundListener{
				ln:     ln,
				iface:  prep.desiredOwner[addr],
				closed: &atomic.Bool{},
			}
			s.listenersByAddr[addr] = bl
			startList = append(startList, bl)
		} else if existing, ok := s.listenersByAddr[addr]; ok {
			existing.iface = prep.desiredOwner[addr]
			s.listenersByAddr[addr] = existing
		}
	}
	for addr, bl := range s.listenersByAddr {
		if _, wanted := prep.desiredOwner[addr]; !wanted && !prep.missingIfaces[bl.iface] {
			delete(s.listenersByAddr, addr)
			stale = append(stale, bl)
		}
	}
	s.listenersMu.Unlock()

	for _, bl := range startList {
		bl := bl
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.acceptLoop(bl.ln, bl.closed)
		}()
	}

	for _, bl := range stale {
		if bl.closed != nil {
			bl.closed.Store(true)
		}
		_ = bl.ln.Close()
	}
}

// Start loads and validates the initial configuration, binds ingress listeners with
// IP_FREEBIND, installs the atomic nftables ruleset, and starts accepting connections.
func (s *Server) Start(ctx context.Context, cfg *config.Config) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	if s.stopped {
		return errors.New("이미 종료된 서버는 다시 시작할 수 없습니다")
	}
	if s.started {
		return errors.New("서버가 이미 시작되었습니다")
	}

	st, _, err := compileState(cfg, s.opts.Interfaces, true, nil)
	if err != nil {
		return err
	}

	prep, err := s.prepareIngressListeners(ctx, st.ingressInterfaces, st.proxyPort, true)
	if err != nil {
		return err
	}

	ruleset, err := nft.BuildRuleset(st.ingressInterfaces, st.proxyPort, st.cfg)
	if err != nil {
		prep.rollback()
		return err
	}
	if err := s.opts.NFT.Apply(ctx, ruleset); err != nil {
		prep.rollback()
		return err
	}

	s.connsMu.Lock()
	s.closing = false
	s.curState = st
	s.connsMu.Unlock()

	sweepCtx, sweepCancel := context.WithCancel(ctx)
	s.listenersMu.Lock()
	s.stopSweeper = sweepCancel
	s.listenersMu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runIdleSweeper(sweepCtx)
	}()

	s.commitIngressListeners(prep)
	s.started = true

	s.opts.Logger.Info("wolproxy 데몬 시작",
		"listen", s.ListenerAddrs(),
		"lan_interface", st.lanInterface,
		"lan_source_ip", st.lanSourceIP.String(),
		"ingress_interfaces", st.ingressInterfaces,
		"targets", len(st.cfg.Targets),
	)

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
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	if !s.started || s.stopped {
		return nil
	}
	s.stopped = true

	// Mark closing under connsMu first so any accepted socket racing with listener Close
	// is rejected immediately and cannot register after active snapshot.
	s.connsMu.Lock()
	s.closing = true
	s.curState = nil
	active := make([]*trackedConn, 0, len(s.conns))
	for _, tc := range s.conns {
		active = append(active, tc)
	}
	s.connsMu.Unlock()

	s.listenersMu.Lock()
	lns := make([]boundListener, 0, len(s.listenersByAddr))
	for k, bl := range s.listenersByAddr {
		if bl.closed != nil {
			bl.closed.Store(true)
		}
		lns = append(lns, bl)
		delete(s.listenersByAddr, k)
	}
	stopSweep := s.stopSweeper
	s.stopSweeper = nil
	s.listenersMu.Unlock()

	if stopSweep != nil {
		stopSweep()
	}

	for _, bl := range lns {
		_ = bl.ln.Close()
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

func checkNoRestartRequiredChanges(cur *compiledState, newCfg *config.Config) error {
	if newCfg == nil {
		return nil
	}
	var changed []string
	if strings.TrimSpace(newCfg.LANInterface) != strings.TrimSpace(cur.lanInterface) {
		changed = append(changed, "lan_interface")
	}
	if !slices.Equal(trimStrings(newCfg.IngressInterfaces), trimStrings(cur.ingressInterfaces)) {
		changed = append(changed, "ingress_interfaces")
	}
	if newCfg.ProxyPort != cur.proxyPort {
		changed = append(changed, "proxy_port")
	}
	if len(changed) == 0 {
		return nil
	}
	return fmt.Errorf(
		"%s 변경은 무중단 재적재(reload)로 적용할 수 없습니다. 반영하려면 서비스를 재시작(systemctl restart wolproxy)하세요",
		strings.Join(changed, ", "),
	)
}

func (s *Server) currentRunningState() (*compiledState, error) {
	s.connsMu.Lock()
	cur := s.curState
	closing := s.closing
	s.connsMu.Unlock()
	if !s.started || s.stopped || closing || cur == nil {
		return nil, errors.New("서버가 실행 중이 아닙니다")
	}
	return cur, nil
}

// Reload validates and applies a new Config transactionally (SIGHUP / synchronous reload):
//   - Validates newCfg first; on validation errors, keeps previous config and returns them.
//   - Explicitly rejects changes to lan_interface, ingress_interfaces, or proxy_port (requires restart).
//   - Phase 1 (Prepare): binds only newly added ingress IPv4 listener addresses.
//   - Phase 2 (Apply): builds and applies the nftables ruleset; on error, closes only newly bound
//     listeners and preserves existing listeners, curState, and active connections intact.
//   - Phase 3 (Commit): swaps curState, registers & starts new listeners, closes stale listeners,
//     and evicts connections that are no longer authorized for their current phase (waking vs relaying).
func (s *Server) Reload(ctx context.Context, newCfg *config.Config) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	return s.reloadLocked(ctx, newCfg)
}

// ReloadFromFile reads opts.ConfigPath and applies it atomically under lifecycleMu
// so concurrent SIGHUP / control-socket reloads cannot apply a stale pre-read snapshot.
func (s *Server) ReloadFromFile(ctx context.Context) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	if _, err := s.currentRunningState(); err != nil {
		return err
	}

	cfg, _, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		s.opts.Logger.Error("설정 파일 읽기 실패 (기존 설정 유지)", "path", s.opts.ConfigPath, "error", err)
		return err
	}
	return s.reloadLocked(ctx, cfg)
}

func (s *Server) reloadLocked(ctx context.Context, newCfg *config.Config) error {
	cur, err := s.currentRunningState()
	if err != nil {
		return err
	}

	rep := config.ValidateWithOptions(newCfg, s.opts.Interfaces, config.ValidateOptions{
		StrictInterfaces: false,
	})
	for _, w := range rep.Warnings {
		s.opts.Logger.Warn("설정 재적재 검증 경고", "detail", w.Error())
	}
	if len(rep.Errors) > 0 {
		s.opts.Logger.Error("설정 재적재 실패 (기존 설정 유지)", "error", rep.Errors)
		return rep.Errors
	}

	if err := checkNoRestartRequiredChanges(cur, newCfg); err != nil {
		s.opts.Logger.Error("설정 재적재 거부 (서비스 재시작 필요)",
			"error", err,
			"running_lan_interface", cur.lanInterface,
			"new_lan_interface", newCfg.LANInterface,
			"running_ingress_interfaces", cur.ingressInterfaces,
			"new_ingress_interfaces", newCfg.IngressInterfaces,
			"running_proxy_port", cur.proxyPort,
			"new_proxy_port", newCfg.ProxyPort,
		)
		return err
	}

	next, err := buildCompiledState(newCfg, s.opts.Interfaces, cur)
	if err != nil {
		s.opts.Logger.Error("설정 재적재 실패 (기존 설정 유지)", "error", err)
		return err
	}

	// Phase 1: Prepare new ingress IPv4 listeners without touching existing listeners.
	prep, err := s.prepareIngressListeners(ctx, next.ingressInterfaces, next.proxyPort, false)
	if err != nil {
		s.opts.Logger.Error("설정 재적재 리스너 준비 실패 (기존 설정 유지)", "error", err)
		return err
	}

	// Phase 2: Build and apply nftables ruleset; roll back newly bound listeners on failure.
	ruleset, err := nft.BuildRuleset(next.ingressInterfaces, next.proxyPort, next.cfg)
	if err != nil {
		prep.rollback()
		s.opts.Logger.Error("설정 재적재 규칙 생성 실패 (기존 설정 유지)", "error", err)
		return err
	}
	if err := s.opts.NFT.Apply(ctx, ruleset); err != nil {
		prep.rollback()
		s.opts.Logger.Error("설정 재적재 nft 적용 실패 (기존 설정 유지)", "error", err)
		return err
	}

	// Phase 3: Commit active state, start newly bound listeners, close stale listeners, and evict revoked conns.
	s.connsMu.Lock()
	s.curState = next
	var revoked []*trackedConn
	for _, tc := range s.conns {
		if !isConnStillAuthorized(next, tc) {
			revoked = append(revoked, tc)
		}
	}
	s.connsMu.Unlock()

	s.commitIngressListeners(prep)

	for _, tc := range revoked {
		tc.abort("config_reload")
	}

	s.opts.Logger.Info("설정 재적재 완료",
		"targets", len(next.cfg.Targets),
		"closed_connections", len(revoked),
	)
	return nil
}

func isRelayingConnAuthorized(st *compiledState, tc *trackedConn) bool {
	if st == nil {
		return false
	}
	route, ok := st.routes[tc.origDst]
	if !ok {
		return false
	}
	if route.targetIP != tc.targetIP ||
		route.port != tc.port ||
		route.usedAlias != tc.usedAlias {
		return false
	}
	_, allowed := route.matchClient(tc.clientIP)
	return allowed
}

func isConnStillAuthorized(next *compiledState, tc *trackedConn) bool {
	if !isRelayingConnAuthorized(next, tc) {
		return false
	}
	if tc.phase == connPhaseWaking {
		route := next.routes[tc.origDst]
		if !bytes.Equal(route.mac, tc.mac) {
			return false
		}
		if route.wake != config.WakeAuto {
			return false
		}
	}
	return true
}

func (s *Server) enterWakePhase(tc *trackedConn) (string, string) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if s.closing || s.curState == nil {
		return "", "shutdown"
	}
	route, ok := s.curState.routes[tc.origDst]
	if !ok || !isRelayingConnAuthorized(s.curState, tc) || !bytes.Equal(route.mac, tc.mac) {
		return "", "config_reload"
	}
	if route.wake != config.WakeAuto {
		return "", "wake_never"
	}
	slotKey := tc.targetName
	if s.waitingTotal >= s.opts.MaxWaitingGlobal || s.waitingByTarget[slotKey] >= s.opts.MaxWaitingPerTarget {
		return "", "wake_limit_exceeded"
	}
	s.waitingTotal++
	s.waitingByTarget[slotKey]++
	tc.phase = connPhaseWaking
	return slotKey, ""
}

func (s *Server) enterRelayPhase(tc *trackedConn) (*routeEntry, string) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if s.closing || s.curState == nil {
		return nil, "shutdown"
	}
	if !isRelayingConnAuthorized(s.curState, tc) {
		return nil, "config_reload"
	}
	tc.phase = connPhaseRelaying
	return s.curState.routes[tc.origDst], ""
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

func (s *Server) acceptLoop(ln net.Listener, closed *atomic.Bool) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || (closed != nil && closed.Load()) {
				return
			}
			s.connsMu.Lock()
			closing := s.closing
			s.connsMu.Unlock()
			if closing {
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
		phase:       connPhaseDialing,
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

		s.connsMu.Lock()
		cur := s.curState
		closing := s.closing
		var curRoute *routeEntry
		var wakeAuthOK bool
		var wakeDisabled bool
		if !closing && cur != nil {
			if r, ok := cur.routes[tc.origDst]; ok && isRelayingConnAuthorized(cur, tc) {
				curRoute = r
				if r.wake != config.WakeAuto {
					wakeDisabled = true
				} else if bytes.Equal(r.mac, tc.mac) {
					wakeAuthOK = true
				}
			}
		}
		s.connsMu.Unlock()

		if closing || cur == nil {
			s.logConnClosed(tc, 0, time.Since(startedAt), tc.getReason("shutdown"))
			return
		}
		if wakeDisabled {
			reason := "wake_never"
			if isConnRefused(dialErr) {
				reason = "conn_refused"
			}
			s.logConnClosed(tc, 0, time.Since(startedAt), tc.getReason(reason))
			return
		}
		if !wakeAuthOK || curRoute == nil {
			s.logConnClosed(tc, 0, time.Since(startedAt), tc.getReason("config_reload"))
			return
		}

		wakeReq := wol.WakeRequest{
			TargetName:    curRoute.targetName,
			TargetIP:      curRoute.targetIP,
			MAC:           curRoute.mac,
			BroadcastAddr: curRoute.broadcastAddr,
			Port:          curRoute.port,
			WakeTimeout:   cur.wakeTimeout,
			WakeCooldown:  cur.wakeCooldown,
			PollInterval:  cur.pollInterval,
			DialTimeout:   initialDialTimeout,
		}
		// Only wake on timeout / EHOSTUNREACH / ENETUNREACH (or join if a wake for this target+port
		// is already in progress). If the target responded with ECONNREFUSED and no wake is active,
		// the host is already awake with the service closed, so close immediately without waking.
		if !shouldWakeOnDialError(dialErr) && !s.coord.HasActiveWake(wakeReq) {
			s.logConnClosed(tc, 0, time.Since(startedAt), tc.getReason(dialFailureReason(dialErr)))
			return
		}

		slotKey, rejectReason := s.enterWakePhase(tc)
		if rejectReason != "" {
			if rejectReason == "wake_limit_exceeded" {
				s.opts.Logger.Warn("연결 거부: 깨우기 대기 연결 수 제한 초과",
					"client_ip", clientIP.String(),
					"target", tc.targetName,
					"port", tc.port,
				)
			}
			s.logConnClosed(tc, 0, time.Since(startedAt), tc.getReason(rejectReason))
			return
		}

		targetConn = func() net.Conn {
			defer s.releaseWakeSlot(slotKey)

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

	activeRoute, abortReason := s.enterRelayPhase(tc)
	if abortReason != "" {
		_ = targetConn.Close()
		s.logConnClosed(tc, 0, time.Since(startedAt), tc.getReason(abortReason))
		return
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
	if activeRoute != nil && activeRoute.idleTimeout > 0 {
		idle = newIdleState(time.Now(), activeRoute.idleTimeout, activeRoute.idleBytes)
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
