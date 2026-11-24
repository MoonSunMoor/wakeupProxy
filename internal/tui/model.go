package tui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MoonSunMoor/wakeupProxy/internal/arp"
	"github.com/MoonSunMoor/wakeupProxy/internal/config"
	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
	"github.com/MoonSunMoor/wakeupProxy/internal/wol"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
)

type tabIndex int

const (
	tabTargets tabIndex = iota
	tabClients
	tabProfiles
	tabGlobal
	tabCount = 4
)

type screenKind int

const (
	screenList screenKind = iota
	screenTargetForm
	screenClientForm
	screenProfileForm
	screenGlobalForm
	screenPresetPicker
	screenLANScan
	screenValidationErrors
	screenSaveSummary
	screenConfirmDelete
	screenConfirmExternalOverwrite
	screenConfirmRestart
	screenConfirmQuit
	screenHelp
	screenNotice
)

type targetStateKind int

const (
	statusUnknown targetStateKind = iota
	statusAwake
	statusAsleep
	statusWaking
)

type targetRuntimeStatus struct {
	state        targetStateKind
	wakeDeadline time.Time
}

type presetChoice struct {
	name    string
	label   string
	profile config.Profile
	isBlank bool
}

// Dependencies bundles external system services used by the TUI so all behaviors
// can be tested deterministically.
type Dependencies struct {
	ConfigPath   string
	IsRoot       bool
	Interfaces   netutil.Provider
	ARP          arp.Checker
	WoLSender    wol.Sender
	Dial         wol.DialFunc
	Service      ServiceManager
	StatusPeriod time.Duration
}

func DefaultDependencies(configPath string) Dependencies {
	if configPath == "" {
		configPath = config.DefaultConfigPath
	}
	return Dependencies{
		ConfigPath:   configPath,
		IsRoot:       os.Geteuid() == 0,
		Interfaces:   netutil.SystemProvider{},
		ARP:          arp.NewSystemChecker(),
		WoLSender:    wol.UDPSender{},
		Dial:         wol.DefaultDialFunc,
		Service:      SystemdManager{},
		StatusPeriod: 10 * time.Second,
	}
}

// Async tea messages
type arpPeriodicTickMsg struct{}
type wakingPollTickMsg struct{}

type arpResultsMsg struct {
	awake map[string]bool
}

type macLookupResultMsg struct {
	forIP  string
	mac    string
	reason string
}

type lanScanResultMsg struct {
	hosts []arp.DiscoveredHost
	err   error
}

type wakeSentMsg struct {
	targetName string
	err        error
}

type portTestResultMsg struct {
	targetName string
	lines      []string
}

type applyDoneMsg struct {
	action string // "reload" or "restart"
	err    error
	logs   string
}

// Model is the root Bubble Tea state machine for the wolproxy TUI.
type Model struct {
	deps Dependencies

	cfg        *config.Config // Working in-memory configuration
	savedCfg   *config.Config // Snapshot last loaded from or written to disk
	appliedCfg *config.Config // Snapshot currently active in daemon (for reload vs restart)
	meta       config.LoadMeta

	width  int
	height int

	tab           tabIndex
	screen        screenKind
	prevScreen    screenKind
	targetCursor  int
	clientCursor  int
	profileCursor int
	modalCursor   int

	form        *huh.Form
	tDraft      targetDraft
	cDraft      clientDraft
	pDraft      profileDraft
	gDraft      globalDraft
	macAutoNote string

	targetStatus map[string]targetRuntimeStatus
	scanningLAN  bool
	scanResults  []arp.DiscoveredHost
	valErrors    config.ValidationErrorList
	pendingDiff  config.DiffResult

	deleteSection tabIndex
	deleteName    string
	deleteIdx     int

	noticeTitle string
	noticeBody  string
	noticeIsErr bool
	statusLine  string
}

// NewModel loads (or initializes) configuration from deps.ConfigPath and prepares the TUI.
func NewModel(deps Dependencies) (*Model, error) {
	if deps.ConfigPath == "" {
		deps.ConfigPath = config.DefaultConfigPath
	}
	if deps.Interfaces == nil {
		deps.Interfaces = netutil.SystemProvider{}
	}
	if deps.ARP == nil {
		deps.ARP = arp.NewSystemChecker()
	}
	if deps.WoLSender == nil {
		deps.WoLSender = wol.UDPSender{}
	}
	if deps.Dial == nil {
		deps.Dial = wol.DefaultDialFunc
	}
	if deps.Service == nil {
		deps.Service = SystemdManager{}
	}
	if deps.StatusPeriod <= 0 {
		deps.StatusPeriod = 10 * time.Second
	}

	cfg, meta, err := config.Load(deps.ConfigPath)
	var initStatus string
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg = config.DefaultConfig()
			meta = config.LoadMeta{Exists: false}
			initStatus = "설정 파일이 없어 기본 프리셋(rdp, ssh)으로 새 설정을 시작합니다."
		} else {
			return nil, fmt.Errorf("설정 파일(%s) 불러오기 실패: %w", deps.ConfigPath, err)
		}
	}

	m := &Model{
		deps:         deps,
		cfg:          cfg.Clone(),
		savedCfg:     cfg.Clone(),
		appliedCfg:   cfg.Clone(),
		meta:         meta,
		tab:          tabTargets,
		screen:       screenList,
		targetStatus: make(map[string]targetRuntimeStatus),
		statusLine:   initStatus,
	}
	return m, nil
}

func (m *Model) isDirty() bool {
	if !m.meta.Exists {
		return true
	}
	return config.Diff(m.savedCfg, m.cfg).HasChanges()
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		m.checkTargetsARPCmd(),
		m.scheduleARPTickCmd(),
	)
}

func (m *Model) scheduleARPTickCmd() tea.Cmd {
	period := m.deps.StatusPeriod
	return tea.Tick(period, func(time.Time) tea.Msg {
		return arpPeriodicTickMsg{}
	})
}

func (m *Model) scheduleWakingTickCmd() tea.Cmd {
	return tea.Tick(2*time.Second, func(time.Time) tea.Msg {
		return wakingPollTickMsg{}
	})
}

func (m *Model) hasWakingTargets() bool {
	now := time.Now()
	for _, st := range m.targetStatus {
		if st.state == statusWaking && now.Before(st.wakeDeadline) {
			return true
		}
	}
	return false
}

func (m *Model) checkTargetsARPCmd() tea.Cmd {
	if len(m.cfg.Targets) == 0 {
		return nil
	}
	lanName := m.cfg.LANInterface
	targetsCopy := append([]config.Target(nil), m.cfg.Targets...)
	ifaces := m.deps.Interfaces
	arpChecker := m.deps.ARP

	return func() tea.Msg {
		lanInfo, err := ifaces.InterfaceByName(lanName)
		if err != nil {
			return arpResultsMsg{awake: nil}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		res := make(map[string]bool, len(targetsCopy))
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, t := range targetsCopy {
			ipAddr, ipErr := netutil.ParseIPv4Host(t.IP)
			if ipErr != nil {
				continue
			}
			tName := t.Name
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, err := arpChecker.IsAwake(ctx, lanInfo, ipAddr)
				if err == nil {
					mu.Lock()
					res[tName] = ok
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		return arpResultsMsg{awake: res}
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if m.form != nil && m.width > 10 {
			m.form = m.form.WithWidth(min(m.width-6, 90))
		}
		return m, nil

	case arpPeriodicTickMsg:
		var cmds []tea.Cmd
		cmds = append(cmds, m.scheduleARPTickCmd())
		if m.tab == tabTargets && m.screen == screenList {
			cmds = append(cmds, m.checkTargetsARPCmd())
		}
		return m, tea.Batch(cmds...)

	case wakingPollTickMsg:
		if !m.hasWakingTargets() {
			// Expire any timed-out waking statuses
			now := time.Now()
			for name, st := range m.targetStatus {
				if st.state == statusWaking && !now.Before(st.wakeDeadline) {
					m.targetStatus[name] = targetRuntimeStatus{state: statusAsleep}
				}
			}
			return m, nil
		}
		return m, tea.Batch(m.checkTargetsARPCmd(), m.scheduleWakingTickCmd())

	case arpResultsMsg:
		now := time.Now()
		for _, t := range m.cfg.Targets {
			awake, hasResult := msg.awake[t.Name]
			prev := m.targetStatus[t.Name]
			if hasResult && awake {
				m.targetStatus[t.Name] = targetRuntimeStatus{state: statusAwake}
				continue
			}
			if prev.state == statusWaking && now.Before(prev.wakeDeadline) {
				// Keep "깨우는 중" until wake_timeout expires or ARP succeeds.
				continue
			}
			if hasResult {
				m.targetStatus[t.Name] = targetRuntimeStatus{state: statusAsleep}
			} else if prev.state == statusWaking {
				m.targetStatus[t.Name] = targetRuntimeStatus{state: statusAsleep}
			}
		}
		return m, nil

	case macLookupResultMsg:
		if m.screen == screenTargetForm && strings.TrimSpace(m.tDraft.ip) == msg.forIP {
			if msg.mac != "" && strings.TrimSpace(m.tDraft.mac) == "" {
				curKey := focusedFieldKey(m.form)
				m.tDraft.mac = msg.mac
				m.macAutoNote = "시스템 ARP 기록에서 자동 입력됨: " + msg.mac
				m.rebuildTargetFormFocusing(curKey)
			} else if msg.mac == "" {
				m.macAutoNote = msg.reason
			}
		}
		return m, nil

	case lanScanResultMsg:
		m.scanningLAN = false
		if msg.err != nil {
			m.screen = screenTargetForm
			m.showNotice("LAN 검색 실패", msg.err.Error(), true, screenTargetForm)
			return m, nil
		}
		m.scanResults = msg.hosts
		m.modalCursor = 0
		return m, nil

	case wakeSentMsg:
		if msg.err != nil {
			m.showNotice("매직 패킷 송신 실패", msg.err.Error(), true, screenList)
			return m, nil
		}
		m.targetStatus[msg.targetName] = targetRuntimeStatus{
			state:        statusWaking,
			wakeDeadline: time.Now().Add(m.cfg.WakeTimeout.Std()),
		}
		m.statusLine = fmt.Sprintf("타깃 %q에 매직 패킷을 보냈습니다.", msg.targetName)
		return m, m.scheduleWakingTickCmd()

	case portTestResultMsg:
		body := strings.Join(msg.lines, "\n")
		m.showNotice(fmt.Sprintf("타깃 %s 포트 테스트 결과", msg.targetName), body, false, screenList)
		return m, nil

	case applyDoneMsg:
		if msg.err != nil {
			detail := msg.err.Error()
			if msg.logs != "" {
				detail += "\n\n[journald 최근 로그]\n" + msg.logs
			}
			m.showNotice("서비스 적용 실패", detail, true, screenList)
			return m, nil
		}
		m.appliedCfg = m.cfg.Clone()
		actionKor := "재적재(reload)"
		if msg.action == "restart" {
			actionKor = "재시작(restart)"
		}
		m.statusLine = fmt.Sprintf("설정 저장 및 서비스 %s 완료", actionKor)
		m.showNotice("저장 및 적용 완료", fmt.Sprintf("설정 파일을 저장하고 wolproxy 서비스를 %s했습니다.", actionKor), false, screenList)
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	if m.isFormScreen() && m.form != nil {
		return m.updateActiveForm(msg)
	}
	return m, nil
}

func (m *Model) isFormScreen() bool {
	switch m.screen {
	case screenTargetForm, screenClientForm, screenProfileForm, screenGlobalForm:
		return true
	default:
		return false
	}
}

func focusedFieldKey(f *huh.Form) string {
	if f == nil {
		return ""
	}
	field := f.GetFocusedField()
	if field == nil {
		return ""
	}
	return field.GetKey()
}

func isTextInputFocused(f *huh.Form) bool {
	if f == nil {
		return false
	}
	_, ok := f.GetFocusedField().(*huh.Input)
	return ok
}

func (m *Model) rebuildTargetFormFocusing(targetKey string) {
	m.form = m.buildTargetForm()
	_ = m.form.Init()
	if targetKey == "" {
		return
	}
	for i := 0; i < 8; i++ {
		if focusedFieldKey(m.form) == targetKey {
			break
		}
		_ = m.form.NextField()
	}
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	keyStr := msg.String()
	if keyStr == "ctrl+c" {
		return m.requestQuit()
	}

	// Global help toggle (`?`) when not typing inside a text input
	if keyStr == "?" && (!m.isFormScreen() || !isTextInputFocused(m.form)) {
		if m.screen == screenHelp {
			m.screen = m.prevScreen
		} else {
			m.prevScreen = m.screen
			m.screen = screenHelp
		}
		return m, nil
	}

	switch m.screen {
	case screenHelp:
		if keyStr == "esc" || keyStr == "?" || keyStr == "enter" || keyStr == "q" {
			m.screen = m.prevScreen
		}
		return m, nil

	case screenNotice:
		if keyStr == "esc" || keyStr == "enter" || keyStr == " " {
			m.screen = m.prevScreen
		}
		return m, nil

	case screenList:
		return m.handleListKey(keyStr)

	case screenTargetForm, screenClientForm, screenProfileForm, screenGlobalForm:
		return m.handleFormKey(msg)

	case screenPresetPicker:
		return m.handlePresetPickerKey(keyStr)

	case screenLANScan:
		return m.handleLANScanKey(keyStr)

	case screenValidationErrors:
		return m.handleValidationErrorsKey(keyStr)

	case screenSaveSummary:
		return m.handleSaveSummaryKey(keyStr)

	case screenConfirmDelete:
		return m.handleConfirmDeleteKey(keyStr)

	case screenConfirmExternalOverwrite:
		return m.handleConfirmExternalOverwriteKey(keyStr)

	case screenConfirmRestart:
		return m.handleConfirmRestartKey(keyStr)

	case screenConfirmQuit:
		if keyStr == "y" || keyStr == "Y" || keyStr == "enter" {
			return m, tea.Quit
		}
		if keyStr == "n" || keyStr == "N" || keyStr == "esc" {
			m.screen = screenList
		}
		return m, nil
	}

	return m, nil
}

func (m *Model) handleListKey(keyStr string) (tea.Model, tea.Cmd) {
	switch keyStr {
	case "tab":
		m.tab = (m.tab + 1) % tabCount
		if m.tab == tabTargets {
			return m, m.checkTargetsARPCmd()
		}
		return m, nil
	case "shift+tab":
		m.tab = (m.tab - 1 + tabCount) % tabCount
		if m.tab == tabTargets {
			return m, m.checkTargetsARPCmd()
		}
		return m, nil
	case "1":
		m.tab = tabTargets
		return m, m.checkTargetsARPCmd()
	case "2":
		m.tab = tabClients
		return m, nil
	case "3":
		m.tab = tabProfiles
		return m, nil
	case "4":
		m.tab = tabGlobal
		return m, nil

	case "up", "k":
		m.moveListCursor(-1)
		return m, nil
	case "down", "j":
		m.moveListCursor(1)
		return m, nil

	case "s", "ctrl+s":
		return m.startSaveFlow()

	case "q":
		return m.requestQuit()

	case "enter":
		if !m.deps.IsRoot {
			m.showReadOnlyNotice()
			return m, nil
		}
		return m.openEditForCurrentTab()

	case "a":
		if m.tab == tabGlobal {
			return m, nil
		}
		if !m.deps.IsRoot {
			m.showReadOnlyNotice()
			return m, nil
		}
		return m.openAddForCurrentTab()

	case "d":
		if m.tab == tabGlobal {
			return m, nil
		}
		if !m.deps.IsRoot {
			m.showReadOnlyNotice()
			return m, nil
		}
		return m.requestDeleteCurrentItem()

	case "w":
		if m.tab == tabTargets {
			return m.sendWakeForSelectedTarget()
		}
	case "t":
		if m.tab == tabTargets {
			return m.testPortsForSelectedTarget()
		}
	}
	return m, nil
}

func (m *Model) moveListCursor(delta int) {
	switch m.tab {
	case tabTargets:
		n := len(m.cfg.Targets)
		if n > 0 {
			m.targetCursor = clampIndex(m.targetCursor+delta, n)
		}
	case tabClients:
		n := len(m.cfg.Clients)
		if n > 0 {
			m.clientCursor = clampIndex(m.clientCursor+delta, n)
		}
	case tabProfiles:
		n := len(m.cfg.Profiles)
		if n > 0 {
			m.profileCursor = clampIndex(m.profileCursor+delta, n)
		}
	}
}

func clampIndex(idx, length int) int {
	if length <= 0 {
		return 0
	}
	if idx < 0 {
		return 0
	}
	if idx >= length {
		return length - 1
	}
	return idx
}

func (m *Model) showReadOnlyNotice() {
	m.showNotice("읽기 전용 모드", "현재 읽기 전용으로 열려 있습니다.\n설정을 편집하거나 저장하려면 sudo로 실행해 주세요.", true, screenList)
}

func (m *Model) showNotice(title, body string, isErr bool, returnTo screenKind) {
	m.prevScreen = returnTo
	m.noticeTitle = title
	m.noticeBody = body
	m.noticeIsErr = isErr
	m.screen = screenNotice
}

func (m *Model) openAddForCurrentTab() (tea.Model, tea.Cmd) {
	switch m.tab {
	case tabTargets:
		m.tDraft = targetDraft{origIdx: -1}
		m.macAutoNote = ""
		m.form = m.buildTargetForm()
		m.screen = screenTargetForm
		return m, m.form.Init()

	case tabClients:
		m.cDraft = clientDraft{isNew: true}
		m.form = m.buildClientForm()
		m.screen = screenClientForm
		return m, m.form.Init()

	case tabProfiles:
		m.modalCursor = 0
		m.screen = screenPresetPicker
		return m, nil
	}
	return m, nil
}

func (m *Model) openEditForCurrentTab() (tea.Model, tea.Cmd) {
	switch m.tab {
	case tabTargets:
		if len(m.cfg.Targets) == 0 {
			return m, nil
		}
		idx := clampIndex(m.targetCursor, len(m.cfg.Targets))
		t := m.cfg.Targets[idx]
		m.tDraft = targetDraft{
			origIdx:  idx,
			name:     t.Name,
			ip:       t.IP,
			mac:      t.MAC,
			alias:    t.Alias,
			profiles: append([]string(nil), t.Profiles...),
			allow:    append([]string(nil), t.Allow...),
			note:     t.Note,
		}
		m.macAutoNote = ""
		m.form = m.buildTargetForm()
		m.screen = screenTargetForm
		return m, m.form.Init()

	case tabClients:
		names := config.SortedKeys(m.cfg.Clients)
		if len(names) == 0 {
			return m, nil
		}
		idx := clampIndex(m.clientCursor, len(names))
		name := names[idx]
		cl := m.cfg.Clients[name]
		m.cDraft = clientDraft{
			isNew:    false,
			origName: name,
			name:     name,
			cidr:     cl.CIDR,
			note:     cl.Note,
		}
		m.form = m.buildClientForm()
		m.screen = screenClientForm
		return m, m.form.Init()

	case tabProfiles:
		names := config.SortedKeys(m.cfg.Profiles)
		if len(names) == 0 {
			return m, nil
		}
		idx := clampIndex(m.profileCursor, len(names))
		name := names[idx]
		pr := m.cfg.Profiles[name]
		idleStr := "0"
		if pr.IdleTimeout > 0 {
			idleStr = pr.IdleTimeout.String()
		}
		idleBytesStr := "0"
		if pr.IdleBytes > 0 {
			idleBytesStr = strconv.FormatInt(pr.IdleBytes, 10)
		}
		m.pDraft = profileDraft{
			isNew:       false,
			origName:    name,
			name:        name,
			port:        strconv.Itoa(pr.Port),
			wake:        pr.Wake,
			idleTimeout: idleStr,
			idleBytes:   idleBytesStr,
			note:        pr.Note,
		}
		m.form = m.buildProfileForm()
		m.screen = screenProfileForm
		return m, m.form.Init()

	case tabGlobal:
		m.gDraft = globalDraft{
			lanInterface:      m.cfg.LANInterface,
			ingressInterfaces: append([]string(nil), m.cfg.IngressInterfaces...),
			proxyPort:         strconv.Itoa(m.cfg.ProxyPort),
			wakeTimeout:       m.cfg.WakeTimeout.String(),
			wakeCooldown:      m.cfg.WakeCooldown.String(),
			pollInterval:      m.cfg.PollInterval.String(),
		}
		m.form = m.buildGlobalForm()
		m.screen = screenGlobalForm
		return m, m.form.Init()
	}
	return m, nil
}

func (m *Model) handleFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	keyStr := msg.String()

	if keyStr == "esc" {
		m.form = nil
		m.screen = screenList
		m.statusLine = "편집을 취소했습니다."
		return m, nil
	}

	if m.screen == screenTargetForm && keyStr == "ctrl+l" {
		return m.startLANScan()
	}

	// Support saving directly from forms via Ctrl+S (or 's' when on non-text-input field)
	if keyStr == "ctrl+s" || (keyStr == "s" && !isTextInputFocused(m.form)) {
		if err := m.commitCurrentFormIfValid(); err != nil {
			m.showNotice("폼 입력 오류", err.Error(), true, m.screen)
			return m, nil
		}
		m.form = nil
		m.screen = screenList
		return m.startSaveFlow()
	}

	if keyStr == "q" && !isTextInputFocused(m.form) {
		return m.requestQuit()
	}

	return m.updateActiveForm(msg)
}

func (m *Model) updateActiveForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	prevKey := focusedFieldKey(m.form)

	nextModel, cmd := m.form.Update(msg)
	if f, ok := nextModel.(*huh.Form); ok {
		m.form = f
	}

	if m.form.State == huh.StateCompleted {
		if err := m.commitCurrentForm(); err != nil {
			m.showNotice("입력 값 오류", err.Error(), true, m.screen)
			return m, nil
		}
		m.form = nil
		m.screen = screenList
		m.statusLine = "메모리 설정에 반영되었습니다. 파일에 저장하려면 's'를 누르세요."
		if m.tab == tabTargets {
			return m, m.checkTargetsARPCmd()
		}
		return m, nil
	}
	if m.form.State == huh.StateAborted {
		m.form = nil
		m.screen = screenList
		return m, nil
	}

	// MAC auto-fill when user leaves the IP field in Target Form
	curKey := focusedFieldKey(m.form)
	if m.screen == screenTargetForm && prevKey == "ip" && curKey != "ip" && strings.TrimSpace(m.tDraft.mac) == "" {
		ipStr := strings.TrimSpace(m.tDraft.ip)
		if ipAddr, err := netutil.ParseIPv4Host(ipStr); err == nil {
			m.macAutoNote = "시스템 ARP 기록에서 MAC 주소를 조회하는 중..."
			return m, tea.Batch(cmd, m.lookupMACCmd(ipStr, ipAddr))
		}
	}

	return m, cmd
}

func (m *Model) commitCurrentForm() error {
	switch m.screen {
	case screenTargetForm:
		return m.commitTargetDraft()
	case screenClientForm:
		return m.commitClientDraft()
	case screenProfileForm:
		return m.commitProfileDraft()
	case screenGlobalForm:
		return m.commitGlobalDraft()
	}
	return nil
}

func (m *Model) commitCurrentFormIfValid() error {
	if m.form != nil {
		if errs := m.form.Errors(); len(errs) > 0 {
			return errs[0]
		}
	}
	return m.commitCurrentForm()
}

func (m *Model) lookupMACCmd(rawIP string, ipAddr netip.Addr) tea.Cmd {
	lanName := m.cfg.LANInterface
	ifaces := m.deps.Interfaces
	arpChecker := m.deps.ARP
	return func() tea.Msg {
		lanInfo, err := ifaces.InterfaceByName(lanName)
		if err != nil {
			return macLookupResultMsg{
				forIP:  rawIP,
				reason: fmt.Sprintf("LAN 인터페이스(%s)를 찾을 수 없어 MAC을 조회할 수 없습니다", lanName),
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
		defer cancel()
		mac, reason := arpChecker.LookupMAC(ctx, lanInfo, ipAddr)
		return macLookupResultMsg{
			forIP:  rawIP,
			mac:    mac,
			reason: reason,
		}
	}
}

func (m *Model) startLANScan() (tea.Model, tea.Cmd) {
	if !m.deps.IsRoot {
		m.showNotice("권한 필요", arp.ErrRootRequired.Error(), true, screenTargetForm)
		return m, nil
	}
	lanInfo, err := m.deps.Interfaces.InterfaceByName(m.cfg.LANInterface)
	if err != nil {
		m.showNotice("LAN 검색 불가", fmt.Sprintf("LAN 인터페이스(%s)를 찾을 수 없습니다: %v", m.cfg.LANInterface, err), true, screenTargetForm)
		return m, nil
	}
	pfx, ok := lanInfo.PrimaryPrefix()
	if !ok {
		m.showNotice("LAN 검색 불가", fmt.Sprintf("LAN 인터페이스(%s)에 IPv4 서브넷이 없습니다.", m.cfg.LANInterface), true, screenTargetForm)
		return m, nil
	}
	if pfx.Bits() < arp.MaxScanPrefixBits {
		m.showNotice("LAN 검색 제한", arp.ErrSubnetTooLarge.Error(), true, screenTargetForm)
		return m, nil
	}

	m.scanningLAN = true
	m.scanResults = nil
	m.modalCursor = 0
	m.screen = screenLANScan

	arpChecker := m.deps.ARP
	return m, func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		hosts, err := arpChecker.ScanSubnet(ctx, lanInfo)
		return lanScanResultMsg{hosts: hosts, err: err}
	}
}

func (m *Model) handleLANScanKey(keyStr string) (tea.Model, tea.Cmd) {
	if keyStr == "esc" {
		m.screen = screenTargetForm
		return m, nil
	}
	if m.scanningLAN || len(m.scanResults) == 0 {
		return m, nil
	}
	switch keyStr {
	case "up", "k":
		m.modalCursor = clampIndex(m.modalCursor-1, len(m.scanResults))
	case "down", "j":
		m.modalCursor = clampIndex(m.modalCursor+1, len(m.scanResults))
	case "enter":
		chosen := m.scanResults[m.modalCursor]
		m.tDraft.ip = chosen.IP.String()
		m.tDraft.mac = chosen.MAC
		if strings.TrimSpace(m.tDraft.name) == "" && chosen.Hostname != "" {
			short := strings.Split(chosen.Hostname, ".")[0]
			m.tDraft.name = short
		}
		m.macAutoNote = "LAN 검색에서 선택됨"
		m.form = m.buildTargetForm()
		m.screen = screenTargetForm
		return m, m.form.Init()
	}
	return m, nil
}

func (m *Model) presetChoices() []presetChoice {
	builtins := config.BuiltinPresets()
	choices := make([]presetChoice, 0, len(builtins)+1)
	for _, b := range builtins {
		choices = append(choices, presetChoice{
			name:    b.Name,
			label:   b.Label,
			profile: b.Profile,
		})
	}
	choices = append(choices, presetChoice{
		label:   "빈 프로파일 (직접 입력)",
		profile: config.Profile{Wake: config.WakeAuto},
		isBlank: true,
	})
	return choices
}

func (m *Model) handlePresetPickerKey(keyStr string) (tea.Model, tea.Cmd) {
	choices := m.presetChoices()
	switch keyStr {
	case "esc":
		m.screen = screenList
		return m, nil
	case "up", "k":
		m.modalCursor = clampIndex(m.modalCursor-1, len(choices))
	case "down", "j":
		m.modalCursor = clampIndex(m.modalCursor+1, len(choices))
	case "enter":
		chosen := choices[m.modalCursor]
		defaultName := chosen.name
		if m.hasProfile(defaultName) {
			defaultName = ""
		}
		portStr := ""
		if chosen.profile.Port > 0 {
			portStr = strconv.Itoa(chosen.profile.Port)
		}
		m.pDraft = profileDraft{
			isNew:       true,
			name:        defaultName,
			port:        portStr,
			wake:        chosen.profile.Wake,
			idleTimeout: "0",
			idleBytes:   "0",
		}
		m.form = m.buildProfileForm()
		m.screen = screenProfileForm
		return m, m.form.Init()
	}
	return m, nil
}

func (m *Model) requestDeleteCurrentItem() (tea.Model, tea.Cmd) {
	switch m.tab {
	case tabTargets:
		if len(m.cfg.Targets) == 0 {
			return m, nil
		}
		idx := clampIndex(m.targetCursor, len(m.cfg.Targets))
		m.deleteSection = tabTargets
		m.deleteIdx = idx
		m.deleteName = m.cfg.Targets[idx].Name
		m.screen = screenConfirmDelete
		return m, nil

	case tabClients:
		names := config.SortedKeys(m.cfg.Clients)
		if len(names) == 0 {
			return m, nil
		}
		name := names[clampIndex(m.clientCursor, len(names))]
		if refs := m.cfg.TargetsUsingClient(name); len(refs) > 0 {
			m.showNotice(
				"클라이언트 삭제 불가",
				fmt.Sprintf("클라이언트 %q는 다음 타깃에서 사용 중이므로 삭제할 수 없습니다:\n  • %s", name, strings.Join(refs, "\n  • ")),
				true,
				screenList,
			)
			return m, nil
		}
		m.deleteSection = tabClients
		m.deleteName = name
		m.screen = screenConfirmDelete
		return m, nil

	case tabProfiles:
		names := config.SortedKeys(m.cfg.Profiles)
		if len(names) == 0 {
			return m, nil
		}
		name := names[clampIndex(m.profileCursor, len(names))]
		if refs := m.cfg.TargetsUsingProfile(name); len(refs) > 0 {
			m.showNotice(
				"프로파일 삭제 불가",
				fmt.Sprintf("프로파일 %q는 다음 타깃에서 사용 중이므로 삭제할 수 없습니다:\n  • %s", name, strings.Join(refs, "\n  • ")),
				true,
				screenList,
			)
			return m, nil
		}
		m.deleteSection = tabProfiles
		m.deleteName = name
		m.screen = screenConfirmDelete
		return m, nil
	}
	return m, nil
}

func (m *Model) handleConfirmDeleteKey(keyStr string) (tea.Model, tea.Cmd) {
	if keyStr == "n" || keyStr == "N" || keyStr == "esc" {
		m.screen = screenList
		return m, nil
	}
	if keyStr != "y" && keyStr != "Y" && keyStr != "enter" {
		return m, nil
	}

	switch m.deleteSection {
	case tabTargets:
		if m.deleteIdx >= 0 && m.deleteIdx < len(m.cfg.Targets) {
			m.cfg.Targets = append(m.cfg.Targets[:m.deleteIdx], m.cfg.Targets[m.deleteIdx+1:]...)
			m.targetCursor = clampIndex(m.targetCursor, len(m.cfg.Targets))
		}
	case tabClients:
		delete(m.cfg.Clients, m.deleteName)
		m.clientCursor = clampIndex(m.clientCursor, len(m.cfg.Clients))
	case tabProfiles:
		delete(m.cfg.Profiles, m.deleteName)
		m.profileCursor = clampIndex(m.profileCursor, len(m.cfg.Profiles))
	}
	m.statusLine = fmt.Sprintf("%q 항목을 삭제했습니다 (파일 저장은 's').", m.deleteName)
	m.screen = screenList
	return m, nil
}

func (m *Model) sendWakeForSelectedTarget() (tea.Model, tea.Cmd) {
	if len(m.cfg.Targets) == 0 {
		return m, nil
	}
	t := m.cfg.Targets[clampIndex(m.targetCursor, len(m.cfg.Targets))]
	_, macHW, err := netutil.NormalizeMAC(t.MAC)
	if err != nil {
		m.showNotice("매직 패킷 송신 불가", err.Error(), true, screenList)
		return m, nil
	}
	lanInfo, err := m.deps.Interfaces.InterfaceByName(m.cfg.LANInterface)
	if err != nil {
		m.showNotice("매직 패킷 송신 불가", fmt.Sprintf("LAN 인터페이스(%s) 조회 실패: %v", m.cfg.LANInterface, err), true, screenList)
		return m, nil
	}
	pfx, ok := lanInfo.PrimaryPrefix()
	if !ok {
		m.showNotice("매직 패킷 송신 불가", fmt.Sprintf("LAN 인터페이스(%s)에 IPv4 서브넷이 없습니다", m.cfg.LANInterface), true, screenList)
		return m, nil
	}
	bcast, err := netutil.BroadcastAddr(pfx)
	if err != nil {
		m.showNotice("매직 패킷 송신 불가", err.Error(), true, screenList)
		return m, nil
	}

	sender := m.deps.WoLSender
	targetName := t.Name
	return m, func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := sender.SendMagicPacket(ctx, bcast, macHW)
		return wakeSentMsg{targetName: targetName, err: err}
	}
}

func (m *Model) testPortsForSelectedTarget() (tea.Model, tea.Cmd) {
	if len(m.cfg.Targets) == 0 {
		return m, nil
	}
	t := m.cfg.Targets[clampIndex(m.targetCursor, len(m.cfg.Targets))]
	if len(t.Profiles) == 0 {
		m.showNotice("포트 테스트 비활성", fmt.Sprintf("타깃 %q에는 연결된 프로파일이 없어 포트 테스트를 실행할 수 없습니다.", t.Name), true, screenList)
		return m, nil
	}

	type profCheck struct {
		name string
		port int
	}
	var checks []profCheck
	for _, pn := range t.Profiles {
		if pr, ok := m.cfg.Profiles[pn]; ok {
			checks = append(checks, profCheck{name: pn, port: pr.Port})
		}
	}
	dialFn := m.deps.Dial
	targetIP := t.IP
	targetName := t.Name
	m.statusLine = fmt.Sprintf("타깃 %q의 프로파일 포트를 테스트하는 중...", targetName)

	return m, func() tea.Msg {
		lines := make([]string, len(checks))
		var wg sync.WaitGroup
		for i, ch := range checks {
			i, ch := i, ch
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				addr := net.JoinHostPort(targetIP, strconv.Itoa(ch.port))
				conn, err := dialFn(ctx, addr)
				if err == nil {
					_ = conn.Close()
					lines[i] = fmt.Sprintf("  • %s (TCP %d): 열림", ch.name, ch.port)
				} else {
					lines[i] = fmt.Sprintf("  • %s (TCP %d): 닫힘 (%v)", ch.name, ch.port, err)
				}
			}()
		}
		wg.Wait()
		return portTestResultMsg{targetName: targetName, lines: lines}
	}
}

// Save & Apply 4-step pipeline (`s`):
// 1. Validate -> error list with form jump
// 2. Change summary (+ comment loss warning) -> user confirmation
// 3. External modification check -> backup (.bak) + atomic write
// 4. systemctl reload (or confirm + systemctl restart if listener/interface settings changed)
func (m *Model) startSaveFlow() (tea.Model, tea.Cmd) {
	if !m.deps.IsRoot {
		m.showNotice("권한 필요", "저장하려면 sudo로 실행해 주세요.", true, screenList)
		return m, nil
	}

	errs := config.Validate(m.cfg, m.deps.Interfaces)
	if len(errs) > 0 {
		m.valErrors = errs
		m.modalCursor = 0
		m.screen = screenValidationErrors
		return m, nil
	}

	m.pendingDiff = config.Diff(m.savedCfg, m.cfg)
	m.screen = screenSaveSummary
	return m, nil
}

func (m *Model) handleValidationErrorsKey(keyStr string) (tea.Model, tea.Cmd) {
	switch keyStr {
	case "esc":
		m.screen = screenList
		return m, nil
	case "up", "k":
		m.modalCursor = clampIndex(m.modalCursor-1, len(m.valErrors))
	case "down", "j":
		m.modalCursor = clampIndex(m.modalCursor+1, len(m.valErrors))
	case "enter":
		if m.modalCursor >= 0 && m.modalCursor < len(m.valErrors) {
			return m.jumpToValidationError(m.valErrors[m.modalCursor])
		}
	}
	return m, nil
}

func (m *Model) jumpToValidationError(ve config.ValidationError) (tea.Model, tea.Cmd) {
	switch ve.Section {
	case config.SectionGlobal:
		m.tab = tabGlobal
		return m.openEditForCurrentTab()

	case config.SectionTarget:
		m.tab = tabTargets
		for i, t := range m.cfg.Targets {
			if t.Name == ve.ItemName {
				m.targetCursor = i
				break
			}
		}
		return m.openEditForCurrentTab()

	case config.SectionClient:
		m.tab = tabClients
		names := config.SortedKeys(m.cfg.Clients)
		if idx := slices.Index(names, ve.ItemName); idx >= 0 {
			m.clientCursor = idx
		}
		return m.openEditForCurrentTab()

	case config.SectionProfile:
		m.tab = tabProfiles
		names := config.SortedKeys(m.cfg.Profiles)
		if idx := slices.Index(names, ve.ItemName); idx >= 0 {
			m.profileCursor = idx
		}
		return m.openEditForCurrentTab()
	}
	m.screen = screenList
	return m, nil
}

func (m *Model) handleSaveSummaryKey(keyStr string) (tea.Model, tea.Cmd) {
	if keyStr == "n" || keyStr == "N" || keyStr == "esc" {
		m.screen = screenList
		return m, nil
	}
	if keyStr == "y" || keyStr == "Y" || keyStr == "enter" {
		changedExternally, err := config.CheckExternalModification(m.deps.ConfigPath, m.meta)
		if err != nil {
			m.showNotice("파일 상태 확인 실패", err.Error(), true, screenList)
			return m, nil
		}
		if changedExternally {
			m.screen = screenConfirmExternalOverwrite
			return m, nil
		}
		return m.writeFileAndProceedToApply()
	}
	return m, nil
}

func (m *Model) handleConfirmExternalOverwriteKey(keyStr string) (tea.Model, tea.Cmd) {
	if keyStr == "n" || keyStr == "N" || keyStr == "esc" {
		m.screen = screenList
		return m, nil
	}
	if keyStr == "y" || keyStr == "Y" || keyStr == "enter" {
		return m.writeFileAndProceedToApply()
	}
	return m, nil
}

func (m *Model) writeFileAndProceedToApply() (tea.Model, tea.Cmd) {
	newModTime, err := config.SaveAtomic(m.deps.ConfigPath, m.cfg)
	if err != nil {
		m.showNotice("설정 파일 저장 실패", err.Error(), true, screenList)
		return m, nil
	}
	m.savedCfg = m.cfg.Clone()
	m.meta = config.LoadMeta{
		ModTime:         newModTime,
		Exists:          true,
		HasUserComments: false,
	}

	applyDiff := config.Diff(m.appliedCfg, m.cfg)
	if applyDiff.RequiresRestart {
		m.screen = screenConfirmRestart
		return m, nil
	}
	m.screen = screenList
	m.statusLine = "설정 파일 저장 완료. systemctl reload wolproxy 실행 중..."
	return m, m.runServiceActionCmd("reload")
}

func (m *Model) handleConfirmRestartKey(keyStr string) (tea.Model, tea.Cmd) {
	if keyStr == "n" || keyStr == "N" || keyStr == "esc" {
		m.screen = screenList
		m.showNotice("설정 파일만 저장됨", "설정 파일은 저장되었으나 서비스 재시작을 취소했습니다.\n변경 사항을 반영하려면 추후 systemctl restart wolproxy를 실행하세요.", false, screenList)
		return m, nil
	}
	if keyStr == "y" || keyStr == "Y" || keyStr == "enter" {
		m.screen = screenList
		m.statusLine = "systemctl restart wolproxy 실행 중..."
		return m, m.runServiceActionCmd("restart")
	}
	return m, nil
}

func (m *Model) runServiceActionCmd(action string) tea.Cmd {
	svc := m.deps.Service
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var err error
		if action == "restart" {
			err = svc.Restart(ctx)
		} else {
			err = svc.Reload(ctx)
		}
		if err != nil {
			logs := svc.RecentLogs(ctx, 10)
			return applyDoneMsg{action: action, err: err, logs: logs}
		}
		return applyDoneMsg{action: action}
	}
}

func (m *Model) requestQuit() (tea.Model, tea.Cmd) {
	if m.deps.IsRoot && m.isDirty() {
		m.screen = screenConfirmQuit
		return m, nil
	}
	return m, tea.Quit
}

func (m *Model) View() string {
	var b strings.Builder
	b.WriteString(m.renderHeader())
	b.WriteString("\n\n")

	switch m.screen {
	case screenList:
		switch m.tab {
		case tabTargets:
			b.WriteString(m.renderTargetsList())
		case tabClients:
			b.WriteString(m.renderClientsList())
		case tabProfiles:
			b.WriteString(m.renderProfilesList())
		case tabGlobal:
			b.WriteString(m.renderGlobalSummary())
		}

	case screenTargetForm, screenClientForm, screenProfileForm, screenGlobalForm:
		if m.form != nil {
			b.WriteString(boxStyle.Render(m.form.View()))
		}

	case screenPresetPicker:
		b.WriteString(m.renderPresetPicker())

	case screenLANScan:
		b.WriteString(m.renderLANScanModal())

	case screenValidationErrors:
		b.WriteString(m.renderValidationErrorsModal())

	case screenSaveSummary:
		b.WriteString(m.renderSaveSummaryModal())

	case screenConfirmDelete:
		b.WriteString(m.renderConfirmModal(
			"삭제 확인",
			fmt.Sprintf("%q 항목을 삭제하시겠습니까?", m.deleteName),
		))

	case screenConfirmExternalOverwrite:
		b.WriteString(m.renderConfirmModal(
			"외부 파일 변경 감지",
			"TUI를 연 뒤 다른 곳에서 설정 파일이 수정되었습니다.\n현재 편집 내용으로 덮어쓰시겠습니까?",
		))

	case screenConfirmRestart:
		applyDiff := config.Diff(m.appliedCfg, m.cfg)
		b.WriteString(m.renderConfirmModal(
			"서비스 재시작 필요",
			fmt.Sprintf(
				"변경된 항목(%s)을 적용하려면 서비스를 재시작해야 합니다.\n재시작하면 현재 연결된 프록시 연결이 끊깁니다. 지금 재시작하시겠습니까?",
				strings.Join(applyDiff.RestartReasons, ", "),
			),
		))

	case screenConfirmQuit:
		b.WriteString(m.renderConfirmModal(
			"저장하지 않은 변경 사항",
			"저장하지 않은 변경 사항이 있습니다. 저장하지 않고 종료하시겠습니까?",
		))

	case screenHelp:
		b.WriteString(m.renderHelpModal())

	case screenNotice:
		b.WriteString(m.renderNoticeModal(m.noticeTitle, m.noticeBody, m.noticeIsErr))
	}

	b.WriteString("\n\n")
	if m.statusLine != "" {
		b.WriteString(mutedStyle.Render("상태: "+m.statusLine) + "\n")
	}
	b.WriteString(m.renderFooter())
	b.WriteByte('\n')
	return b.String()
}
