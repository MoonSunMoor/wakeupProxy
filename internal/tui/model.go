package tui

import (
	"errors"
	"fmt"
	"os"
	"strings"
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
	screenTargetDetail
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

	targetStatus   map[string]targetRuntimeStatus
	scanningLAN    bool
	scanResults    []arp.DiscoveredHost
	valErrors      config.ValidationErrorList
	valWarnings    config.ValidationErrorList
	pendingDiff    config.DiffResult
	restartReasons []string
	saveSyncWarn   string

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

func (m *Model) consumeSaveSyncWarn() string {
	w := m.saveSyncWarn
	m.saveSyncWarn = ""
	return w
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
		if m.tab == tabTargets && (m.screen == screenList || m.screen == screenTargetDetail) {
			cmds = append(cmds, m.checkTargetsARPCmd())
		}
		return m, tea.Batch(cmds...)

	case wakingPollTickMsg:
		now := time.Now()
		for name, st := range m.targetStatus {
			if st.state == statusWaking && !now.Before(st.wakeDeadline) {
				m.targetStatus[name] = targetRuntimeStatus{state: statusAsleep}
			}
		}
		if !m.hasWakingTargets() {
			return m, nil
		}
		return m, tea.Batch(m.checkWakingTargetsARPCmd(), m.scheduleWakingTickCmd())

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
				return m, m.rebuildTargetFormFocusing(curKey)
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
			if warn := m.consumeSaveSyncWarn(); warn != "" {
				detail += "\n\n⚠ 경고: " + warn
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
		body := fmt.Sprintf("설정 파일을 저장하고 wolproxy 서비스를 %s했습니다.", actionKor)
		if warn := m.consumeSaveSyncWarn(); warn != "" {
			body += "\n\n⚠ 경고: " + warn
		}
		m.showNotice("저장 및 적용 완료", body, false, screenList)
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	if m.isFormScreen() && m.form != nil {
		return m.updateActiveForm(msg)
	}
	return m, nil
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

	case screenTargetDetail:
		b.WriteString(m.renderTargetDetailModal())

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
		reasons := m.restartReasons
		if len(reasons) == 0 {
			reasons = config.Diff(m.appliedCfg, m.cfg).RestartReasons
		}
		b.WriteString(m.renderConfirmModal(
			"서비스 재시작 필요",
			fmt.Sprintf(
				"변경된 항목(%s)을 적용하려면 서비스를 재시작해야 합니다.\n재시작하면 현재 연결된 프록시 연결이 끊깁니다. 지금 재시작하시겠습니까?",
				strings.Join(reasons, ", "),
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
