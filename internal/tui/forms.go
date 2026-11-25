package tui

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/MoonSunMoor/wakeupProxy/internal/config"
	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/huh"
)

type targetDraft struct {
	origIdx  int // -1 when adding new target
	name     string
	ip       string
	mac      string
	alias    string
	profiles []string
	allow    []string
	note     string
}

type clientDraft struct {
	isNew    bool
	origName string
	name     string
	cidr     string
	note     string
}

type profileDraft struct {
	isNew       bool
	origName    string
	name        string
	port        string
	wake        string
	idleTimeout string
	idleBytes   string
	note        string
}

type globalDraft struct {
	lanInterface      string
	ingressInterfaces []string
	proxyPort         string
	wakeTimeout       string
	wakeCooldown      string
	pollInterval      string
}

func newFormKeyMap() *huh.KeyMap {
	km := huh.NewDefaultKeyMap()
	// Esc is handled by our outer TUI model so it cleanly cancels the form without quitting tea.Program.
	km.Quit = key.NewBinding(key.WithDisabled())
	// Ensure Tab / Shift+Tab move between fields uniformly across Input, Select, and MultiSelect.
	km.Input.Next = key.NewBinding(key.WithKeys("enter", "tab"))
	km.Input.Prev = key.NewBinding(key.WithKeys("shift+tab"))
	km.Select.Next = key.NewBinding(key.WithKeys("enter", "tab"))
	km.Select.Prev = key.NewBinding(key.WithKeys("shift+tab"))
	km.MultiSelect.Next = key.NewBinding(key.WithKeys("enter", "tab"))
	km.MultiSelect.Prev = key.NewBinding(key.WithKeys("shift+tab"))
	return km
}

func validateRequiredName(label string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s 이름을 입력해 주세요", label)
		}
		return nil
	}
}

func validatePortStr(s string) error {
	s = strings.TrimSpace(s)
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > config.MaxPort {
		return fmt.Errorf("포트는 1~%d 사이의 숫자여야 합니다", config.MaxPort)
	}
	return nil
}

func validateProxyPortStr(s string) error {
	s = strings.TrimSpace(s)
	n, err := strconv.Atoi(s)
	if err != nil || n < config.MinProxyPort || n > config.MaxPort {
		return fmt.Errorf("proxy_port는 %d~%d 사이의 숫자여야 합니다", config.MinProxyPort, config.MaxPort)
	}
	return nil
}

func validatePositiveDurationStr(s string) error {
	d, err := config.ParseDurationInput(s)
	if err != nil {
		return err
	}
	if d <= 0 {
		return errors.New("0보다 큰 시간을 입력해 주세요 (예: 10s, 120s)")
	}
	return nil
}

func validateOptionalDurationStr(s string) error {
	d, err := config.ParseDurationInput(s)
	if err != nil {
		return err
	}
	if d < 0 {
		return errors.New("시간은 음수일 수 없습니다")
	}
	return nil
}

func validateOptionalNonNegIntStr(s string) error {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return errors.New("0 이상의 정수를 입력해 주세요")
	}
	return nil
}

func (m *Model) buildTargetForm() *huh.Form {
	profNames := config.SortedKeys(m.cfg.Profiles)
	profOpts := make([]huh.Option[string], 0, len(profNames))
	for _, pn := range profNames {
		pr := m.cfg.Profiles[pn]
		label := fmt.Sprintf("%s (port %d, wake=%s)", pn, pr.Port, pr.Wake)
		profOpts = append(profOpts, huh.NewOption(label, pn))
	}

	clientNames := config.SortedKeys(m.cfg.Clients)
	clientOpts := make([]huh.Option[string], 0, len(clientNames))
	for _, cn := range clientNames {
		cl := m.cfg.Clients[cn]
		label := fmt.Sprintf("%s (%s)", cn, cl.CIDR)
		clientOpts = append(clientOpts, huh.NewOption(label, cn))
	}

	scanHint := "Ctrl+L: LAN 검색"
	if !m.deps.IsRoot {
		scanHint = "Ctrl+L: LAN 검색 (비활성 - root 필요)"
	}

	fields := []huh.Field{
		huh.NewInput().
			Key("name").
			Title("타깃 이름").
			Value(&m.tDraft.name).
			Validate(validateRequiredName("타깃")),
		huh.NewInput().
			Key("ip").
			Title("IP 주소 (" + scanHint + ")").
			Placeholder("192.168.0.21").
			Value(&m.tDraft.ip).
			Validate(func(s string) error {
				_, err := netutil.ParseIPv4Host(s)
				return err
			}),
		huh.NewInput().
			Key("mac").
			Title("MAC 주소").
			Placeholder("aa:bb:cc:dd:ee:01").
			DescriptionFunc(func() string {
				if m.macAutoNote != "" {
					return m.macAutoNote
				}
				return "IP 입력 후 이동하면 시스템 ARP 기록에서 자동으로 채웁니다"
			}, &m.macAutoNote).
			Value(&m.tDraft.mac).
			Validate(func(s string) error {
				_, _, err := netutil.NormalizeMAC(s)
				return err
			}),
		huh.NewInput().
			Key("alias").
			Title("별칭 IP (선택)").
			Placeholder("10.66.1.12").
			Value(&m.tDraft.alias).
			Validate(func(s string) error {
				if strings.TrimSpace(s) == "" {
					return nil
				}
				_, err := netutil.ParseIPv4Host(s)
				return err
			}),
	}

	if len(profOpts) > 0 {
		fields = append(fields,
			huh.NewMultiSelect[string]().
				Key("profiles").
				Title("프로파일 (스페이스로 선택/해제)").
				Options(profOpts...).
				Filterable(false).
				Value(&m.tDraft.profiles),
		)
	} else {
		fields = append(fields,
			huh.NewNote().
				Title("프로파일").
				Description("등록된 프로파일이 없어 선택할 수 없습니다. '3. 프로파일' 탭에서 먼저 추가해 주세요."),
		)
	}
	if len(clientOpts) > 0 {
		fields = append(fields,
			huh.NewMultiSelect[string]().
				Key("allow").
				Title("허용 클라이언트 (스페이스로 선택/해제)").
				Options(clientOpts...).
				Filterable(false).
				Value(&m.tDraft.allow),
		)
	} else {
		fields = append(fields,
			huh.NewNote().
				Title("허용 클라이언트").
				Description("등록된 클라이언트가 없어 허용 클라이언트를 선택할 수 없습니다. '2. 클라이언트' 탭에서 먼저 추가해 주세요."),
		)
	}

	fields = append(fields,
		huh.NewInput().
			Key("note").
			Title("메모 (note, 선택)").
			Value(&m.tDraft.note),
	)

	form := huh.NewForm(huh.NewGroup(fields...)).
		WithKeyMap(newFormKeyMap()).
		WithShowHelp(false)
	if m.width > 10 {
		form = form.WithWidth(min(m.width-6, 90))
	}
	return form
}

func (m *Model) commitTargetDraft() error {
	normMAC, _, err := netutil.NormalizeMAC(m.tDraft.mac)
	if err != nil {
		return err
	}
	ipAddr, err := netutil.ParseIPv4Host(m.tDraft.ip)
	if err != nil {
		return err
	}
	var aliasStr string
	if strings.TrimSpace(m.tDraft.alias) != "" {
		aliasAddr, err := netutil.ParseIPv4Host(m.tDraft.alias)
		if err != nil {
			return err
		}
		aliasStr = aliasAddr.String()
	}

	t := config.Target{
		Name:     strings.TrimSpace(m.tDraft.name),
		Note:     strings.TrimSpace(m.tDraft.note),
		IP:       ipAddr.String(),
		Alias:    aliasStr,
		MAC:      normMAC,
		Profiles: append([]string(nil), m.tDraft.profiles...),
		Allow:    append([]string(nil), m.tDraft.allow...),
	}

	if m.tDraft.origIdx >= 0 && m.tDraft.origIdx < len(m.cfg.Targets) {
		m.cfg.Targets[m.tDraft.origIdx] = t
		m.targetCursor = m.tDraft.origIdx
	} else {
		m.cfg.Targets = append(m.cfg.Targets, t)
		m.targetCursor = len(m.cfg.Targets) - 1
	}
	return nil
}

func (m *Model) buildClientForm() *huh.Form {
	fields := []huh.Field{
		huh.NewInput().
			Key("name").
			Title("클라이언트 이름").
			Value(&m.cDraft.name).
			Validate(func(s string) error {
				name := strings.TrimSpace(s)
				if name == "" {
					return errors.New("클라이언트 이름을 입력해 주세요")
				}
				if (m.cDraft.isNew || name != m.cDraft.origName) && m.hasClient(name) {
					return fmt.Errorf("이미 존재하는 클라이언트 이름입니다: %s", name)
				}
				return nil
			}),
		huh.NewInput().
			Key("cidr").
			Title("IP/CIDR").
			Placeholder("10.66.0.2/32").
			Value(&m.cDraft.cidr).
			Validate(func(s string) error {
				_, err := netutil.ParseIPv4OrCIDR(s)
				return err
			}),
		huh.NewInput().
			Key("note").
			Title("메모 (note, 선택)").
			Value(&m.cDraft.note),
	}

	form := huh.NewForm(huh.NewGroup(fields...)).
		WithKeyMap(newFormKeyMap()).
		WithShowHelp(false)
	if m.width > 10 {
		form = form.WithWidth(min(m.width-6, 80))
	}
	return form
}

func (m *Model) hasClient(name string) bool {
	_, ok := m.cfg.Clients[name]
	return ok
}

func (m *Model) commitClientDraft() error {
	name := strings.TrimSpace(m.cDraft.name)
	pfx, err := netutil.ParseIPv4OrCIDR(m.cDraft.cidr)
	if err != nil {
		return err
	}
	cl := config.Client{
		CIDR: pfx.String(),
		Note: strings.TrimSpace(m.cDraft.note),
	}
	if !m.cDraft.isNew && m.cDraft.origName != name {
		m.cfg.RenameClient(m.cDraft.origName, name)
	}
	m.cfg.Clients[name] = cl

	keys := config.SortedKeys(m.cfg.Clients)
	if idx := slices.Index(keys, name); idx >= 0 {
		m.clientCursor = idx
	}
	return nil
}

func (m *Model) buildProfileForm() *huh.Form {
	fields := []huh.Field{
		huh.NewInput().
			Key("name").
			Title("프로파일 이름").
			Value(&m.pDraft.name).
			Validate(func(s string) error {
				name := strings.TrimSpace(s)
				if name == "" {
					return errors.New("프로파일 이름을 입력해 주세요")
				}
				if (m.pDraft.isNew || name != m.pDraft.origName) && m.hasProfile(name) {
					return fmt.Errorf("이미 존재하는 프로파일 이름입니다: %s", name)
				}
				return nil
			}),
		huh.NewInput().
			Key("port").
			Title("포트 (1~65535)").
			Placeholder("3389").
			Value(&m.pDraft.port).
			Validate(validatePortStr),
		huh.NewSelect[string]().
			Key("wake").
			Title("깨우기 정책 (wake)").
			Options(
				huh.NewOption("auto (연결 시 자동으로 매직 패킷 송신)", config.WakeAuto),
				huh.NewOption("never (깨어 있을 때만 연결)", config.WakeNever),
			).
			Filtering(false).
			Value(&m.pDraft.wake),
		huh.NewInput().
			Key("idle_timeout").
			Title("유휴 제한 시간 (idle_timeout, 0=사용 안 함)").
			Placeholder("0").
			Value(&m.pDraft.idleTimeout).
			Validate(validateOptionalDurationStr),
		huh.NewInput().
			Key("idle_bytes").
			Title("유휴 판정 전송량 이하 기준 바이트 (idle_bytes)").
			Placeholder("0").
			Value(&m.pDraft.idleBytes).
			Validate(validateOptionalNonNegIntStr),
		huh.NewInput().
			Key("note").
			Title("메모 (note, 선택)").
			Value(&m.pDraft.note),
	}

	form := huh.NewForm(huh.NewGroup(fields...)).
		WithKeyMap(newFormKeyMap()).
		WithShowHelp(false)
	if m.width > 10 {
		form = form.WithWidth(min(m.width-6, 80))
	}
	return form
}

func (m *Model) hasProfile(name string) bool {
	_, ok := m.cfg.Profiles[name]
	return ok
}

func (m *Model) commitProfileDraft() error {
	name := strings.TrimSpace(m.pDraft.name)
	port, err := strconv.Atoi(strings.TrimSpace(m.pDraft.port))
	if err != nil {
		return err
	}
	idleTimeout, err := config.ParseDurationInput(m.pDraft.idleTimeout)
	if err != nil {
		return err
	}
	var idleBytes int64
	if strings.TrimSpace(m.pDraft.idleBytes) != "" {
		idleBytes, err = strconv.ParseInt(strings.TrimSpace(m.pDraft.idleBytes), 10, 64)
		if err != nil {
			return err
		}
	}

	pr := config.Profile{
		Port:        port,
		Wake:        m.pDraft.wake,
		IdleTimeout: idleTimeout,
		IdleBytes:   idleBytes,
		Note:        strings.TrimSpace(m.pDraft.note),
	}
	if !m.pDraft.isNew && m.pDraft.origName != name {
		m.cfg.RenameProfile(m.pDraft.origName, name)
	}
	m.cfg.Profiles[name] = pr

	keys := config.SortedKeys(m.cfg.Profiles)
	if idx := slices.Index(keys, name); idx >= 0 {
		m.profileCursor = idx
	}
	return nil
}

func (m *Model) buildGlobalForm() *huh.Form {
	ifaces, _ := m.deps.Interfaces.Interfaces()
	seenNames := make(map[string]bool)
	var lanOpts []huh.Option[string]
	var ingOpts []huh.Option[string]

	addOption := func(name, desc string) {
		if name == "" || seenNames[name] {
			return
		}
		seenNames[name] = true
		label := name
		if desc != "" {
			label = fmt.Sprintf("%s (%s)", name, desc)
		}
		lanOpts = append(lanOpts, huh.NewOption(label, name))
		ingOpts = append(ingOpts, huh.NewOption(label, name))
	}

	for _, info := range ifaces {
		if info.Loopback {
			continue
		}
		var pfxStrs []string
		for _, p := range info.Prefixes {
			pfxStrs = append(pfxStrs, p.String())
		}
		addOption(info.Name, strings.Join(pfxStrs, ", "))
	}
	// Preserve currently configured interface names in options if absent on host so user can see/replace them.
	if m.gDraft.lanInterface != "" && !seenNames[m.gDraft.lanInterface] {
		addOption(m.gDraft.lanInterface, "시스템에 없음")
	}
	for _, ing := range m.gDraft.ingressInterfaces {
		if !seenNames[ing] {
			addOption(ing, "시스템에 없음")
		}
	}
	if len(lanOpts) == 0 {
		addOption("eth0", "기본값")
		addOption("wg0", "기본값")
	}

	fields := []huh.Field{
		huh.NewSelect[string]().
			Key("lan_interface").
			Title("LAN 인터페이스").
			Options(lanOpts...).
			Filtering(false).
			Value(&m.gDraft.lanInterface),
		huh.NewMultiSelect[string]().
			Key("ingress_interfaces").
			Title("유입 인터페이스 (스페이스로 다중 선택)").
			Options(ingOpts...).
			Filterable(false).
			Value(&m.gDraft.ingressInterfaces).
			Validate(func(sel []string) error {
				if len(sel) == 0 {
					return errors.New("유입 인터페이스를 하나 이상 선택해 주세요")
				}
				lanName := strings.TrimSpace(m.gDraft.lanInterface)
				for _, s := range sel {
					if lanName != "" && strings.TrimSpace(s) == lanName {
						return fmt.Errorf("유입 인터페이스(%s)는 LAN 인터페이스와 같을 수 없습니다", lanName)
					}
				}
				return nil
			}),
		huh.NewInput().
			Key("proxy_port").
			Title("프록시 리슨 포트 (proxy_port, 1024~65535)").
			Value(&m.gDraft.proxyPort).
			Validate(validateProxyPortStr),
		huh.NewInput().
			Key("wake_timeout").
			Title("깨우기 대기 제한 시간 (wake_timeout)").
			Value(&m.gDraft.wakeTimeout).
			Validate(validatePositiveDurationStr),
		huh.NewInput().
			Key("wake_cooldown").
			Title("매직 패킷 재송신 간격 (wake_cooldown)").
			Value(&m.gDraft.wakeCooldown).
			Validate(validatePositiveDurationStr),
		huh.NewInput().
			Key("poll_interval").
			Title("포트 확인 간격 (poll_interval)").
			Value(&m.gDraft.pollInterval).
			Validate(validatePositiveDurationStr),
	}

	form := huh.NewForm(huh.NewGroup(fields...)).
		WithKeyMap(newFormKeyMap()).
		WithShowHelp(false)
	if m.width > 10 {
		form = form.WithWidth(min(m.width-6, 85))
	}
	return form
}

func (m *Model) commitGlobalDraft() error {
	port, err := strconv.Atoi(strings.TrimSpace(m.gDraft.proxyPort))
	if err != nil {
		return err
	}
	wt, err := config.ParseDurationInput(m.gDraft.wakeTimeout)
	if err != nil {
		return err
	}
	wc, err := config.ParseDurationInput(m.gDraft.wakeCooldown)
	if err != nil {
		return err
	}
	pi, err := config.ParseDurationInput(m.gDraft.pollInterval)
	if err != nil {
		return err
	}

	m.cfg.LANInterface = m.gDraft.lanInterface
	m.cfg.IngressInterfaces = append([]string(nil), m.gDraft.ingressInterfaces...)
	m.cfg.ProxyPort = port
	m.cfg.WakeTimeout = wt
	m.cfg.WakeCooldown = wc
	m.cfg.PollInterval = pi
	return nil
}
