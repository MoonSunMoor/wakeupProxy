package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/MoonSunMoor/wakeupProxy/internal/config"
	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
)

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

func (m *Model) rebuildTargetFormFocusing(targetKey string) tea.Cmd {
	m.form = m.buildTargetForm()
	initCmd := m.form.Init()
	if targetKey == "" {
		return initCmd
	}
	cmds := []tea.Cmd{initCmd}
	for i := 0; i < 12; i++ {
		if focusedFieldKey(m.form) == targetKey {
			break
		}
		if c := m.form.NextField(); c != nil {
			cmds = append(cmds, c)
		}
	}
	return tea.Batch(cmds...)
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

	// Support saving directly from forms only via Ctrl+S (never bare 's')
	if keyStr == "ctrl+s" {
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

func (m *Model) requestQuit() (tea.Model, tea.Cmd) {
	if m.deps.IsRoot && m.isDirty() {
		m.screen = screenConfirmQuit
		return m, nil
	}
	return m, tea.Quit
}
