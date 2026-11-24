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
			i++
		case strings.HasPrefix(arg, "-c="):
			cfgPath = strings.TrimPrefix(arg, "-c=")
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
	if errs := config.Validate(cfg, netutil.SystemProvider{}); len(errs) > 0 {
		fmt.Fprintf(stderr, "설정 검증 실패 (%d건):\n%s\n", len(errs), errs.Error())
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
		wol.DefaultDialFunc,
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

func runServe(cfgPath string, stderr io.Writer) int {
	logger := newDaemonLogger(stderr)

	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		logger.Error("설정 파일 읽기 실패", "path", cfgPath, "error", err)
		return 1
	}

	srv := proxy.NewServer(proxy.Options{
		ConfigPath: cfgPath,
		Interfaces: netutil.SystemProvider{},
		NFT:        nft.CLIManager{},
		WoLSender:  wol.UDPSender{},
		Dial:       wol.DefaultDialFunc,
		Logger:     logger,
	})

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

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigCh)

	for sig := range sigCh {
		if sig == syscall.SIGHUP {
			reloadCtx, rCancel := context.WithTimeout(ctx, 10*time.Second)
			_ = srv.ReloadFromFile(reloadCtx)
			rCancel()
			continue
		}

		logger.Info("종료 시그널 수신, 정리 중...", "signal", sig.String())
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
