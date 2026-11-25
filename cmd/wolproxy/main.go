package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/MoonSunMoor/wakeupProxy/internal/arp"
	"github.com/MoonSunMoor/wakeupProxy/internal/config"
	"github.com/MoonSunMoor/wakeupProxy/internal/daemon"
	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
	"github.com/MoonSunMoor/wakeupProxy/internal/nft"
	"github.com/MoonSunMoor/wakeupProxy/internal/proxy"
	"github.com/MoonSunMoor/wakeupProxy/internal/tui"
	"github.com/MoonSunMoor/wakeupProxy/internal/wol"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

var version = "0.1.0"

func main() {
	code := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, func() bool {
		return term.IsTerminal(int(os.Stdin.Fd()))
	})
	os.Exit(code)
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `wolproxy %s - TCP Wake-on-LAN 투명 프록시 및 설정 편집기

사용법:
  wolproxy [-c <경로>]                     대화형 TUI 설정 편집기 실행 (TTY 필요)
  wolproxy [-c <경로>] serve               프록시 데몬 실행 (systemd 서비스 전용)
  wolproxy [-c <경로>] reload              실행 중인 데몬에 동기식 설정 재적재 요청
  wolproxy [-c <경로>] wake <타깃>... [--wait]
                                           타깃에 매직 패킷 송신 (--wait: 깨어날 때까지 대기)
  wolproxy [-c <경로>] check               설정 파일 검증

공통 옵션:
  -c <경로>    설정 파일 경로 지정 (기본값: %s)
  -h, --help   도움말 표시
`, version, config.DefaultConfigPath)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, isStdinTTY func() bool) int {
	cfgPath := config.DefaultConfigPath
	var cfgPathExplicit bool
	var rest []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help" || arg == "help":
			printUsage(stdout)
			return 0
		case arg == "-v" || arg == "--version" || arg == "version":
			fmt.Fprintf(stdout, "wolproxy %s\n", version)
			return 0
		case arg == "-c":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "오류: -c 옵션에 설정 파일 경로가 필요합니다.")
				printUsage(stderr)
				return 2
			}
			cfgPath = args[i+1]
			cfgPathExplicit = true
			i++
		case strings.HasPrefix(arg, "-c="):
			cfgPath = strings.TrimPrefix(arg, "-c=")
			cfgPathExplicit = true
		default:
			rest = append(rest, arg)
		}
	}

	if len(rest) == 0 {
		if !isStdinTTY() {
			printUsage(stderr)
			return 1
		}
		return runTUI(cfgPath, stdin, stdout, stderr)
	}

	subcmd := rest[0]
	subArgs := rest[1:]

	switch subcmd {
	case "serve":
		if len(subArgs) > 0 {
			fmt.Fprintf(stderr, "오류: 알 수 없는 인자입니다: %s\n", strings.Join(subArgs, " "))
			return 2
		}
		return runServe(cfgPath, stderr)

	case "reload":
		if len(subArgs) > 0 {
			fmt.Fprintf(stderr, "오류: 알 수 없는 인자입니다: %s\n", strings.Join(subArgs, " "))
			return 2
		}
		return runReload(cfgPath, cfgPathExplicit, stderr)

	case "wake":
		return runWake(cfgPath, subArgs, stderr)

	case "check":
		if len(subArgs) > 0 {
			fmt.Fprintf(stderr, "오류: 알 수 없는 인자입니다: %s\n", strings.Join(subArgs, " "))
			return 2
		}
		return runCheck(cfgPath, stderr)

	default:
		fmt.Fprintf(stderr, "오류: 알 수 없는 명령입니다: %s\n\n", subcmd)
		printUsage(stderr)
		return 2
	}
}

func runTUI(cfgPath string, stdin io.Reader, stdout, stderr io.Writer) int {
	deps := tui.DefaultDependencies(cfgPath)
	m, err := tui.NewModel(deps)
	if err != nil {
		fmt.Fprintf(stderr, "오류: %v\n", err)
		return 1
	}
	p := tea.NewProgram(
		m,
		tea.WithAltScreen(),
		tea.WithInput(stdin),
		tea.WithOutput(stdout),
	)
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(stderr, "TUI 실행 오류: %v\n", err)
		return 1
	}
	return 0
}

func newDaemonLogger(w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if os.Getenv("INVOCATION_ID") != "" {
		// Under systemd/journald, journald timestamps each entry automatically.
		opts.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

func runCheck(cfgPath string, stderr io.Writer) int {
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "설정 읽기 실패 (%s): %v\n", cfgPath, err)
		return 1
	}
	rep := config.ValidateWithOptions(cfg, netutil.SystemProvider{}, config.ValidateOptions{
		StrictInterfaces: false,
	})
	for _, w := range rep.Warnings {
		fmt.Fprintf(stderr, "경고: %s\n", w.Error())
	}
	if len(rep.Errors) > 0 {
		fmt.Fprintf(stderr, "설정 검증 실패 (%d건):\n%s\n", len(rep.Errors), rep.Errors.Error())
		return 1
	}
	return 0
}

func runWake(cfgPath string, args []string, stderr io.Writer) int {
	var wait bool
	var targetNames []string
	for _, a := range args {
		switch {
		case a == "--wait" || a == "-w":
			wait = true
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(stderr, "오류: 알 수 없는 옵션입니다: %s\n", a)
			return 2
		default:
			targetNames = append(targetNames, a)
		}
	}
	if len(targetNames) == 0 {
		fmt.Fprintln(stderr, "오류: 깨울 타깃 이름을 하나 이상 지정해야 합니다.")
		return 2
	}

	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "설정 읽기 실패 (%s): %v\n", cfgPath, err)
		return 1
	}

	ifaces := netutil.SystemProvider{}
	lanInfo, err := ifaces.InterfaceByName(cfg.LANInterface)
	if err != nil {
		fmt.Fprintf(stderr, "LAN 인터페이스(%s) 조회 실패: %v\n", cfg.LANInterface, err)
		return 1
	}
	lanPfx, ok := lanInfo.PrimaryPrefix()
	if !ok {
		fmt.Fprintf(stderr, "LAN 인터페이스(%s)에 IPv4 서브넷이 없습니다.\n", cfg.LANInterface)
		return 1
	}
	bcast, err := netutil.BroadcastAddr(lanPfx)
	if err != nil {
		fmt.Fprintf(stderr, "브로드캐스트 주소 계산 실패: %v\n", err)
		return 1
	}

	targetsByName := make(map[string]config.Target, len(cfg.Targets))
	for _, t := range cfg.Targets {
		targetsByName[t.Name] = t
	}

	wakeTargets := make([]wol.CLIWakeTarget, 0, len(targetNames))
	seen := make(map[string]bool, len(targetNames))
	for _, name := range targetNames {
		if seen[name] {
			continue
		}
		seen[name] = true
		t, exists := targetsByName[name]
		if !exists {
			fmt.Fprintf(stderr, "오류: 설정에 없는 타깃입니다: %s\n", name)
			return 1
		}
		ipAddr, err := netutil.ParseIPv4Host(t.IP)
		if err != nil {
			fmt.Fprintf(stderr, "타깃 %s IP 오류: %v\n", name, err)
			return 1
		}
		_, macHW, err := netutil.NormalizeMAC(t.MAC)
		if err != nil {
			fmt.Fprintf(stderr, "타깃 %s MAC 오류: %v\n", name, err)
			return 1
		}
		var ports []int
		for _, pn := range t.Profiles {
			if pr, ok := cfg.Profiles[pn]; ok && pr.Port >= 1 && pr.Port <= 65535 {
				ports = append(ports, pr.Port)
			}
		}
		wakeTargets = append(wakeTargets, wol.CLIWakeTarget{
			Name:  t.Name,
			IP:    ipAddr,
			MAC:   macHW,
			Ports: ports,
		})
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	arpChecker := arp.NewSystemChecker()
	arpProbe := func(pCtx context.Context, ip netip.Addr) (bool, error) {
		return arpChecker.IsAwake(pCtx, lanInfo, ip)
	}

	err = wol.WakeTargets(
		ctx,
		wol.UDPSender{},
		wol.NewLANDialer(lanPfx.Addr()),
		arpProbe,
		bcast,
		wakeTargets,
		wait,
		cfg.WakeTimeout.Std(),
		cfg.WakeCooldown.Std(),
		cfg.PollInterval.Std(),
	)
	if err != nil {
		fmt.Fprintf(stderr, "깨우기 실패: %v\n", err)
		return 1
	}
	return 0
}

func isSystemdManaged() bool {
	return strings.TrimSpace(os.Getenv("NOTIFY_SOCKET")) != "" ||
		strings.TrimSpace(os.Getenv("INVOCATION_ID")) != ""
}

func runReload(cfgPath string, cfgPathExplicit bool, stderr io.Writer) int {
	rtDir := daemon.RuntimeDir()
	st, ok, err := daemon.ReadRuntimeState(rtDir)
	if err != nil {
		fmt.Fprintf(stderr, "재적재 실패: 런타임 상태 읽기 오류: %v\n", err)
		return 1
	}
	if cfgPathExplicit {
		if ok && strings.TrimSpace(st.ConfigPath) != "" {
			if !daemon.SameConfigPath(cfgPath, st.ConfigPath) {
				fmt.Fprintf(stderr, "재적재 실패: 지정한 설정 경로(%s)가 실행 중인 데몬의 설정 경로(%s)와 다릅니다.\n", cfgPath, st.ConfigPath)
				return 1
			}
		} else if !ok && daemon.HasControlSocket(rtDir) && !daemon.SameConfigPath(cfgPath, config.DefaultConfigPath) {
			fmt.Fprintf(stderr, "재적재 실패: 지정한 설정 경로(%s)가 기본 서비스 설정 경로(%s)와 다릅니다.\n", cfgPath, config.DefaultConfigPath)
			return 1
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := daemon.RequestReload(ctx, rtDir); err != nil {
		fmt.Fprintf(stderr, "재적재 실패: %v\n", err)
		return 1
	}
	return 0
}

func runServe(cfgPath string, stderr io.Writer) int {
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigCh)

	return serveWithOptions(cfgPath, stderr, proxy.Options{
		ConfigPath: cfgPath,
		Interfaces: netutil.SystemProvider{},
		NFT:        nft.CLIManager{},
		WoLSender:  wol.UDPSender{},
	}, sigCh)
}

func serveWithOptions(cfgPath string, stderr io.Writer, opts proxy.Options, sigCh <-chan os.Signal) int {
	logger := opts.Logger
	if logger == nil {
		logger = newDaemonLogger(stderr)
		opts.Logger = logger
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = cfgPath
	}

	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		logger.Error("설정 파일 읽기 실패", "path", cfgPath, "error", err)
		return 1
	}

	srv := proxy.NewServer(opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx, cfg); err != nil {
		var valErrs config.ValidationErrorList
		if errors.As(err, &valErrs) {
			for _, ve := range valErrs {
				logger.Error("설정 검증 오류", "detail", ve.Error())
			}
		} else {
			logger.Error("데몬 시작 실패", "error", err)
		}
		return 1
	}

	managed := isSystemdManaged()
	startedAt := time.Now().UTC()
	rtDir := daemon.RuntimeDir()
	publishState := func() error {
		snap, ok := srv.Snapshot()
		if !ok {
			return errors.New("서버 런타임 스냅샷을 가져올 수 없습니다")
		}
		return daemon.WriteRuntimeState(rtDir, daemon.NewRuntimeState(cfgPath, snap, startedAt))
	}

	if stateErr := publishState(); stateErr != nil {
		if managed {
			logger.Error("런타임 상태 파일 기록 실패 (systemd 관리 모드)", "dir", rtDir, "error", stateErr)
			shutCtx, sCancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = srv.Shutdown(shutCtx)
			sCancel()
			return 1
		}
		logger.Warn("런타임 상태 파일 기록 불가 (비관리 실행 모드)", "dir", rtDir, "error", stateErr)
	}

	doReload := func(rCtx context.Context) error {
		_ = daemon.NotifyReloading()
		err := srv.ReloadFromFile(rCtx)
		if err == nil {
			if stateErr := publishState(); stateErr != nil {
				logger.Warn("재적재 후 런타임 상태 파일 갱신 실패", "dir", rtDir, "error", stateErr)
			}
		}
		_ = daemon.NotifyReady()
		return err
	}

	ctrlSrv, ctrlErr := daemon.StartControlServer(rtDir, doReload)
	if ctrlErr != nil {
		if managed {
			logger.Error("제어 소켓 생성 실패 (systemd 관리 모드)", "dir", rtDir, "error", ctrlErr)
			daemon.RemoveRuntimeState(rtDir)
			shutCtx, sCancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = srv.Shutdown(shutCtx)
			sCancel()
			return 1
		}
		logger.Warn("제어 소켓 생성 불가 (비관리 실행 모드)", "dir", rtDir, "error", ctrlErr)
	}
	defer func() {
		if ctrlSrv != nil {
			_ = ctrlSrv.Close()
		}
		daemon.RemoveRuntimeState(rtDir)
	}()

	if err := daemon.NotifyReady(); err != nil {
		logger.Warn("systemd READY 알림 실패", "error", err)
	}

	for sig := range sigCh {
		if sig == syscall.SIGHUP {
			reloadCtx, rCancel := context.WithTimeout(ctx, 10*time.Second)
			_ = doReload(reloadCtx)
			rCancel()
			continue
		}

		logger.Info("종료 시그널 수신, 정리 중...", "signal", sig.String())
		_ = daemon.NotifyStopping()
		// Close control socket before Shutdown so no new control reload requests can enter.
		if ctrlSrv != nil {
			_ = ctrlSrv.Close()
			ctrlSrv = nil
		}
		daemon.RemoveRuntimeState(rtDir)
		cancel()
		shutCtx, sCancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := srv.Shutdown(shutCtx)
		sCancel()
		if err != nil {
			return 1
		}
		return 0
	}
	return 0
}
