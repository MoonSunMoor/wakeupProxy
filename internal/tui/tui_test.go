package tui

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MoonSunMoor/wakeupProxy/internal/arp"
	"github.com/MoonSunMoor/wakeupProxy/internal/config"
	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
	tea "github.com/charmbracelet/bubbletea"
)

type fakeService struct {
	reloads  int
	restarts int
	failErr  error
	logs     string
	status   DaemonStatus
}

func (s *fakeService) Status(_ context.Context) DaemonStatus {
	return s.status
}

func (s *fakeService) Reload(_ context.Context) error {
	s.reloads++
	return s.failErr
}

func (s *fakeService) Restart(_ context.Context) error {
	s.restarts++
	return s.failErr
}

func (s *fakeService) RecentLogs(_ context.Context, _ int) string {
	return s.logs
}

type fakeARP struct {
	awake map[netip.Addr]bool
	macs  map[netip.Addr]string
	hosts []arp.DiscoveredHost
}

func (a *fakeARP) IsAwake(_ context.Context, _ netutil.InterfaceInfo, ip netip.Addr) (bool, error) {
	return a.awake[ip], nil
}

func (a *fakeARP) LookupMAC(_ context.Context, _ netutil.InterfaceInfo, ip netip.Addr) (string, string) {
	if m, ok := a.macs[ip]; ok {
		return m, ""
	}
	return "", "ARP 기록 없음"
}

func (a *fakeARP) ScanSubnet(_ context.Context, _ netutil.InterfaceInfo) ([]arp.DiscoveredHost, error) {
	return a.hosts, nil
}

type fakeWoL struct {
	sent      int
	lastBcast netip.Addr
}

func (w *fakeWoL) SendMagicPacket(_ context.Context, bcast netip.Addr, _ net.HardwareAddr) error {
	w.sent++
	w.lastBcast = bcast
	return nil
}

func setupTestModel(t *testing.T, isRoot bool) (*Model, string, *fakeService, *fakeARP, *fakeWoL) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	sample := `# 이 파일은 wolproxy TUI가 관리한다. 주석은 저장 시 사라지므로 메모는 note에 쓴다.
# 추가 사용자 주석
lan_interface: eth0
ingress_interfaces: [wg0]
proxy_port: 13389
wake_timeout: 120s
wake_cooldown: 10s
poll_interval: 2s

clients:
  laptop: { cidr: 10.66.0.2/32 }
  unused: { cidr: 10.66.0.9/32 }

profiles:
  rdp: { port: 3389, wake: auto }
  unused-prof: { port: 8080, wake: never }

targets:
  - name: pc1
    ip: 192.168.0.21
    mac: "aa:bb:cc:dd:ee:01"
    profiles: [rdp]
    allow: [laptop]
`
	if err := os.WriteFile(cfgPath, []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}

	svc := &fakeService{
		logs: "systemd error line 1\nsystemd error line 2",
		status: DaemonStatus{
			Active:            true,
			HasRuntimeState:   true,
			ConfigPath:        cfgPath,
			LANInterface:      "eth0",
			IngressInterfaces: []string{"wg0"},
			ProxyPort:         13389,
		},
	}
	arpMock := &fakeARP{
		awake: map[netip.Addr]bool{netip.MustParseAddr("192.168.0.21"): false},
		macs:  map[netip.Addr]string{netip.MustParseAddr("192.168.0.55"): "aa:bb:cc:dd:ee:55"},
		hosts: []arp.DiscoveredHost{
			{IP: netip.MustParseAddr("192.168.0.21"), MAC: "aa:bb:cc:dd:ee:01", Hostname: "pc1.lan"},
			{IP: netip.MustParseAddr("192.168.0.55"), MAC: "aa:bb:cc:dd:ee:55", Hostname: "desktop.lan"},
		},
	}
	wolMock := &fakeWoL{}

	ifaces := netutil.StaticProvider{
		Items: []netutil.InterfaceInfo{
			{
				Name:         "eth0",
				Index:        2,
				HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
				Prefixes:     []netip.Prefix{netip.MustParsePrefix("192.168.0.10/24")},
				Up:           true,
			},
			{
				Name:     "wg0",
				Index:    3,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("10.66.0.1/24")},
				Up:       true,
			},
		},
	}

	m, err := NewModel(Dependencies{
		ConfigPath:   cfgPath,
		IsRoot:       isRoot,
		Interfaces:   ifaces,
		ARP:          arpMock,
		WoLSender:    wolMock,
		Service:      svc,
		StatusPeriod: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewModel failed: %v", err)
	}
	return m, cfgPath, svc, arpMock, wolMock
}

func sendKey(m *Model, k string) (*Model, tea.Cmd) {
	var msg tea.KeyMsg
	switch k {
	case "tab":
		msg = tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		msg = tea.KeyMsg{Type: tea.KeyShiftTab}
	case "enter":
		msg = tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		msg = tea.KeyMsg{Type: tea.KeyEsc}
	case "up":
		msg = tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		msg = tea.KeyMsg{Type: tea.KeyDown}
	case "ctrl+l":
		msg = tea.KeyMsg{Type: tea.KeyCtrlL}
	case "ctrl+s":
		msg = tea.KeyMsg{Type: tea.KeyCtrlS}
	default:
		msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
	}
	next, cmd := m.Update(msg)
	return next.(*Model), cmd
}

func TestReadOnlyModeBlocksSaveWithSudoNotice(t *testing.T) {
	m, _, svc, _, _ := setupTestModel(t, false)
	m, _ = sendKey(m, "s")
	if m.screen != screenNotice || !strings.Contains(m.noticeBody, "sudo") {
		t.Fatalf("expected non-root 's' to show sudo notice, got screen=%v body=%q", m.screen, m.noticeBody)
	}
	if svc.reloads != 0 || svc.restarts != 0 {
		t.Fatal("non-root must never reload or restart service")
	}
}

func TestDeleteProtectionForReferencedItemsAndAllowedForUnused(t *testing.T) {
	m, _, _, _, _ := setupTestModel(t, true)

	// Switch to Clients tab ("laptop" is at index 0, referenced by pc1)
	m, _ = sendKey(m, "tab")
	if m.tab != tabClients {
		t.Fatalf("expected tabClients, got %v", m.tab)
	}
	m, _ = sendKey(m, "d")
	if m.screen != screenNotice || !strings.Contains(m.noticeBody, "pc1") {
		t.Fatalf("expected deletion of referenced client 'laptop' to be blocked mentioning pc1, got screen=%v body=%q", m.screen, m.noticeBody)
	}
	m, _ = sendKey(m, "esc")

	// Move down to "unused" client and delete it
	m, _ = sendKey(m, "j")
	m, _ = sendKey(m, "d")
	if m.screen != screenConfirmDelete {
		t.Fatalf("expected confirm delete for unused client, got %v", m.screen)
	}
	m, _ = sendKey(m, "y")
	if _, exists := m.cfg.Clients["unused"]; exists {
		t.Fatal("expected 'unused' client to be deleted")
	}
}

func TestValidationJumpSaveBackupReloadAndRestartFlow(t *testing.T) {
	m, cfgPath, svc, _, _ := setupTestModel(t, true)

	// Introduce a validation error (alias overlapping LAN subnet) and press 's'
	m.cfg.Targets[0].Alias = "192.168.0.200"
	m, _ = sendKey(m, "s")
	if m.screen != screenValidationErrors || len(m.valErrors) != 1 {
		t.Fatalf("expected validation error list with 1 error, got screen=%v errs=%v", m.screen, m.valErrors)
	}

	// Press Enter on the error -> must jump directly to pc1's Target Form!
	m, _ = sendKey(m, "enter")
	if m.screen != screenTargetForm || m.tDraft.name != "pc1" {
		t.Fatalf("expected Enter on validation error to open pc1 target form, got screen=%v draft=%+v", m.screen, m.tDraft)
	}
	// Cancel form and fix alias to a valid non-LAN IP
	m, _ = sendKey(m, "esc")
	m.cfg.Targets[0].Alias = "10.66.1.21"

	// Press 's' -> shows Save Summary (including warning about user comment!)
	m, _ = sendKey(m, "s")
	if m.screen != screenSaveSummary {
		t.Fatalf("expected screenSaveSummary, got %v", m.screen)
	}
	viewOut := m.View()
	if !strings.Contains(viewOut, "주석이 사라집니다") {
		t.Fatalf("expected comment loss warning in save summary, got:\n%s", viewOut)
	}

	// Confirm save -> writes file + .bak and runs systemctl reload
	m, cmd := sendKey(m, "y")
	if cmd == nil {
		t.Fatal("expected reload tea.Cmd after confirming save")
	}
	msg := cmd()
	next, _ := m.Update(msg)
	m = next.(*Model)
	if svc.reloads != 1 || svc.restarts != 0 {
		t.Fatalf("expected 1 reload and 0 restarts, got reloads=%d restarts=%d", svc.reloads, svc.restarts)
	}
	if _, err := os.Stat(cfgPath + ".bak"); err != nil {
		t.Fatalf("expected .bak backup file created: %v", err)
	}
	m, _ = sendKey(m, "enter") // close completion notice

	// Now change proxy_port -> requires restart confirmation!
	m.cfg.ProxyPort = 14400
	m, _ = sendKey(m, "s")
	m, _ = sendKey(m, "y")
	if m.screen != screenConfirmRestart {
		t.Fatalf("expected screenConfirmRestart when proxy_port changed, got %v", m.screen)
	}
	svc.failErr = errors.New("unit failed to start")
	m, restartCmd := sendKey(m, "y")
	resMsg := restartCmd()
	next, _ = m.Update(resMsg)
	m = next.(*Model)
	if svc.restarts != 1 {
		t.Fatalf("expected 1 restart attempt, got %d", svc.restarts)
	}
	if m.screen != screenNotice || !strings.Contains(m.noticeBody, "systemd error line 1") {
		t.Fatalf("expected failure notice to include journald lines, got: %q", m.noticeBody)
	}
}

func TestWakeStatusAndLANScanPopulateForm(t *testing.T) {
	m, _, _, arpMock, wolMock := setupTestModel(t, true)

	// Press 'w' on pc1 -> sends magic packet and sets status to "깨우는 중"
	m, cmd := sendKey(m, "w")
	next, _ := m.Update(cmd())
	m = next.(*Model)
	if wolMock.sent != 1 {
		t.Fatalf("expected 1 magic packet sent, got %d", wolMock.sent)
	}
	if got := m.formatTargetStatus("pc1"); got != "깨우는 중" {
		t.Fatalf("expected status '깨우는 중' after 'w', got %q", got)
	}

	// Simulate ARP reporting pc1 awake -> transitions to "깨어 있음"
	arpMock.awake[netip.MustParseAddr("192.168.0.21")] = true
	arpMsg := m.checkTargetsARPCmd()()
	next, _ = m.Update(arpMsg)
	m = next.(*Model)
	if got := m.formatTargetStatus("pc1"); got != "깨어 있음" {
		t.Fatalf("expected status '깨어 있음' once ARP responds, got %q", got)
	}

	// Open Add Target form ('a'), press Ctrl+L for LAN scan, select second host (192.168.0.55)
	m, _ = sendKey(m, "a")
	if m.screen != screenTargetForm {
		t.Fatalf("expected screenTargetForm, got %v", m.screen)
	}
	m, scanCmd := sendKey(m, "ctrl+l")
	next, _ = m.Update(scanCmd())
	m = next.(*Model)
	if m.screen != screenLANScan {
		t.Fatalf("expected screenLANScan, got %v", m.screen)
	}
	scanView := m.View()
	if !strings.Contains(scanView, "[등록됨: pc1]") {
		t.Fatalf("expected existing target pc1 to be marked in LAN scan view:\n%s", scanView)
	}
	m, _ = sendKey(m, "j")
	m, _ = sendKey(m, "enter")
	if m.screen != screenTargetForm || m.tDraft.ip != "192.168.0.55" || m.tDraft.mac != "aa:bb:cc:dd:ee:55" {
		t.Fatalf("expected LAN scan selection to populate IP and MAC, got %+v", m.tDraft)
	}
	if m.tDraft.name != "" {
		t.Fatalf("expected LAN scan selection NOT to auto-fill target name from reverse DNS hostname, got %q", m.tDraft.name)
	}
}

func TestProfilePresetPickerAndMACAutoFill(t *testing.T) {
	m, _, _, _, _ := setupTestModel(t, true)

	// Switch to Profiles tab (key '3'), press 'a' -> Preset Picker opens
	m, _ = sendKey(m, "3")
	m, _ = sendKey(m, "a")
	if m.screen != screenPresetPicker {
		t.Fatalf("expected screenPresetPicker, got %v", m.screen)
	}
	// Move down to "ssh" preset (index 1) and press Enter
	m, _ = sendKey(m, "j")
	m, _ = sendKey(m, "enter")
	if m.screen != screenProfileForm {
		t.Fatalf("expected screenProfileForm, got %v", m.screen)
	}
	if m.pDraft.name != "ssh" || m.pDraft.port != "22" || m.pDraft.wake != config.WakeAuto {
		t.Fatalf("unexpected ssh preset prefill: %+v", m.pDraft)
	}
	m, _ = sendKey(m, "esc")

	// Test MAC auto-fill when user types name + IP and tabs to MAC field -> preserves focus on "mac"
	m = sendFormKey(m, "1")
	m = sendFormKey(m, "a")
	m = sendFormKey(m, "pc2")
	m = sendFormKey(m, "tab") // name -> ip
	m = sendFormKey(m, "192.168.0.55")
	m = sendFormKey(m, "tab") // ip -> mac (triggers lookupMACCmd -> macLookupResultMsg -> rebuildTargetFormFocusing)
	if m.tDraft.mac != "aa:bb:cc:dd:ee:55" {
		t.Fatalf("expected MAC auto-fill to populate aa:bb:cc:dd:ee:55, got %q", m.tDraft.mac)
	}
	if focusedFieldKey(m.form) != "mac" {
		t.Fatalf("expected focus preserved on 'mac' after rebuildTargetFormFocusing, got %q", focusedFieldKey(m.form))
	}
}

func TestRunningDaemonStateDiffAndFailedReloadHandling(t *testing.T) {
	m, _, svc, _, _ := setupTestModel(t, true)

	// Case 1: Reload failure displays journald logs and does NOT update appliedCfg
	m.cfg.WakeTimeout = config.Duration(90 * time.Second)
	svc.failErr = errors.New("reload rejected by daemon")
	m, _ = sendKey(m, "s")
	m, cmd := sendKey(m, "y")
	next, _ := m.Update(cmd())
	m = next.(*Model)
	if m.screen != screenNotice || !strings.Contains(m.noticeBody, "systemd error line 1") {
		t.Fatalf("expected reload failure notice with journald logs, got screen=%v body=%q", m.screen, m.noticeBody)
	}
	if m.appliedCfg.WakeTimeout == config.Duration(90*time.Second) {
		t.Fatal("failed reload must not mark appliedCfg as updated")
	}
	m, _ = sendKey(m, "enter") // close notice
	svc.failErr = nil

	// Case 2: Disk config has proxy_port=13389, but live running daemon is actually bound to 12000
	// (e.g. config.yaml was edited outside TUI without restarting daemon).
	// Pressing 's' -> 'y' must compare against live DaemonStatus and prompt for restart!
	svc.status.ProxyPort = 12000
	m, _ = sendKey(m, "s")
	m, _ = sendKey(m, "y")
	if m.screen != screenConfirmRestart {
		t.Fatalf("expected screenConfirmRestart when live daemon port(12000) differs from config(13389), got %v", m.screen)
	}
	if !strings.Contains(m.View(), "proxy_port") {
		t.Fatalf("expected proxy_port listed in restart confirmation:\n%s", m.View())
	}
}

func TestSaveAllowsMissingIngressInterfaceWithWarning(t *testing.T) {
	m, _, svc, _, _ := setupTestModel(t, true)
	// Simulate wg0 down (only eth0 exists on system)
	m.deps.Interfaces = netutil.StaticProvider{
		Items: []netutil.InterfaceInfo{
			{
				Name:         "eth0",
				Index:        2,
				HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
				Prefixes:     []netip.Prefix{netip.MustParsePrefix("192.168.0.10/24")},
				Up:           true,
			},
		},
	}

	m, _ = sendKey(m, "s")
	if m.screen != screenSaveSummary {
		t.Fatalf("expected missing wg0 to proceed to screenSaveSummary with warning, got %v (errs=%v)", m.screen, m.valErrors)
	}
	if !strings.Contains(m.View(), "존재하지 않는 유입 인터페이스") {
		t.Fatalf("expected missing ingress interface warning in save summary:\n%s", m.View())
	}
	m, cmd := sendKey(m, "y")
	next, _ := m.Update(cmd())
	m = next.(*Model)
	if svc.reloads != 1 {
		t.Fatalf("expected save+reload to succeed while wg0 is down, got reloads=%d", svc.reloads)
	}
}

func TestSaveSkipsServiceApplyWhenConfigPathDiffersFromDaemonOrDefault(t *testing.T) {
	// 1. Active daemon running with /etc/wolproxy/config.yaml while TUI edits a custom -c path
	m, cfgPath, svc, _, _ := setupTestModel(t, true)
	svc.status.ConfigPath = config.DefaultConfigPath
	m.cfg.ProxyPort = 14500 // Even changing restart-required field must NOT trigger restart prompt!

	m, _ = sendKey(m, "s")
	if m.screen != screenSaveSummary {
		t.Fatalf("expected screenSaveSummary, got %v", m.screen)
	}
	m, cmd := sendKey(m, "y")
	if cmd != nil {
		t.Fatal("expected nil service command when editing non-service config path")
	}
	if svc.reloads != 0 || svc.restarts != 0 {
		t.Fatalf("expected 0 service calls for mismatched -c path, got reloads=%d restarts=%d", svc.reloads, svc.restarts)
	}
	if m.screen != screenNotice || !strings.Contains(m.noticeBody, "생략") {
		t.Fatalf("expected notice explaining service apply was skipped, got screen=%v body=%q", m.screen, m.noticeBody)
	}
	loaded, _, err := config.Load(cfgPath)
	if err != nil || loaded.ProxyPort != 14500 {
		t.Fatalf("expected custom config file saved with ProxyPort=14500, got %+v err=%v", loaded, err)
	}
	m, _ = sendKey(m, "enter")

	// 2. Stopped daemon (or missing state.json) while TUI edits non-default path -> still skips systemctl start/reload!
	svc.status = DaemonStatus{Active: false}
	m.cfg.WakeTimeout = config.Duration(45 * time.Second)
	m, _ = sendKey(m, "s")
	m, cmd = sendKey(m, "y")
	if cmd != nil || svc.reloads != 0 || svc.restarts != 0 {
		t.Fatalf("expected stopped service with non-default -c path to skip systemctl apply, cmd=%v reloads=%d", cmd, svc.reloads)
	}
	m, _ = sendKey(m, "enter")

	// 3. Relative path pointing to the SAME file as active daemon's ConfigPath -> applies via reload!
	subDir := filepath.Join(filepath.Dir(cfgPath), "sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	m.deps.ConfigPath = filepath.Join(subDir, "..", filepath.Base(cfgPath))
	svc.status = DaemonStatus{
		Active:            true,
		HasRuntimeState:   true,
		ConfigPath:        cfgPath,
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         14500,
	}
	m.cfg.WakeTimeout = config.Duration(60 * time.Second)
	m, _ = sendKey(m, "s")
	m, cmd = sendKey(m, "y")
	if cmd == nil {
		t.Fatal("expected reload command when normalized ConfigPath matches running daemon")
	}
	next, _ := m.Update(cmd())
	m = next.(*Model)
	if svc.reloads != 1 {
		t.Fatalf("expected 1 reload when normalized ConfigPath matches, got %d", svc.reloads)
	}
}

func runImmediateCmd(m *Model, cmd tea.Cmd, depth int) *Model {
	if cmd == nil || depth > 8 {
		return m
	}
	msgCh := make(chan tea.Msg, 1)
	go func() {
		msgCh <- cmd()
	}()
	var msg tea.Msg
	select {
	case msg = <-msgCh:
	case <-time.After(25 * time.Millisecond):
		// Skip long-lived timers such as cursor blink or periodic ARP ticks.
		return m
	}
	if msg == nil {
		return m
	}
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, sub := range batch {
			m = runImmediateCmd(m, sub, depth+1)
		}
		return m
	}
	next, nextCmd := m.Update(msg)
	m = next.(*Model)
	return runImmediateCmd(m, nextCmd, depth+1)
}

func sendFormKey(m *Model, k string) *Model {
	m, cmd := sendKey(m, k)
	return runImmediateCmd(m, cmd, 0)
}

func TestFormBareSKeyDoesNotSaveWhileCtrlSSavesAcrossFieldTypes(t *testing.T) {
	m, _, _, _, _ := setupTestModel(t, true)

	// 1. Target Form MultiSelect ('profiles' and 'allow'): pressing 's' must NOT leave form or start save
	m = sendFormKey(m, "enter") // edit pc1
	if m.screen != screenTargetForm {
		t.Fatalf("expected screenTargetForm, got %v", m.screen)
	}
	// Advance focus to MultiSelect 'profiles' (name -> ip -> mac -> alias -> profiles)
	for i := 0; i < 4; i++ {
		m = sendFormKey(m, "tab")
	}
	if got := focusedFieldKey(m.form); got != "profiles" {
		t.Fatalf("expected focus on profiles MultiSelect, got %q", got)
	}
	m = sendFormKey(m, "s")
	if m.screen != screenTargetForm {
		t.Fatalf("expected bare 's' on MultiSelect to stay in screenTargetForm, got %v", m.screen)
	}
	m = sendFormKey(m, "tab")
	if got := focusedFieldKey(m.form); got != "allow" {
		t.Fatalf("expected focus on allow MultiSelect, got %q", got)
	}
	m = sendFormKey(m, "s")
	if m.screen != screenTargetForm {
		t.Fatalf("expected bare 's' on allow MultiSelect to stay in screenTargetForm, got %v", m.screen)
	}

	// 2. Global Form Select ('lan_interface'): pressing 's' must NOT start save; Ctrl+S MUST start save!
	m = sendFormKey(m, "esc")
	m = sendFormKey(m, "4")
	m = sendFormKey(m, "enter")
	if m.screen != screenGlobalForm || focusedFieldKey(m.form) != "lan_interface" {
		t.Fatalf("expected screenGlobalForm focused on lan_interface Select, got screen=%v key=%q", m.screen, focusedFieldKey(m.form))
	}
	m = sendFormKey(m, "s")
	if m.screen != screenGlobalForm {
		t.Fatalf("expected bare 's' on Select field to stay in screenGlobalForm, got %v", m.screen)
	}
	m, _ = sendKey(m, "ctrl+s")
	if m.screen != screenSaveSummary {
		t.Fatalf("expected Ctrl+S inside form to commit form and open screenSaveSummary, got %v", m.screen)
	}
}

func TestEmptyClientsTargetFormNoteAndBlackholeWarningInSaveSummary(t *testing.T) {
	m, _, _, _, _ := setupTestModel(t, true)
	// Clear all clients so starter/empty-clients state is active
	m.cfg.Targets = nil
	m.cfg.Clients = map[string]config.Client{}

	m = sendFormKey(m, "a")
	if m.screen != screenTargetForm {
		t.Fatalf("expected screenTargetForm, got %v", m.screen)
	}
	view := m.View()
	if !strings.Contains(view, "허용 클라이언트") || !strings.Contains(view, "등록된 클라이언트가 없어") {
		t.Fatalf("expected target form to display empty-clients guidance note, got:\n%s", view)
	}

	// Fill valid target fields and step through all fields with Enter to verify Note does not block completion
	m.tDraft.name = "pc-new"
	m.tDraft.ip = "192.168.0.30"
	m.tDraft.mac = "aa:bb:cc:dd:ee:30"
	m.tDraft.profiles = []string{"rdp"}
	m.form = m.buildTargetForm()
	m = runImmediateCmd(m, m.form.Init(), 0)

	// Fields: name -> ip -> mac -> alias -> profiles (MultiSelect) -> [allow Note skipped] -> note -> submit!
	for step := 0; step < 8 && m.screen == screenTargetForm; step++ {
		m = sendFormKey(m, "enter")
	}
	if m.screen != screenList {
		t.Fatalf("expected target form with empty-clients Note to complete cleanly, stuck on screen=%v (focused=%q)", m.screen, focusedFieldKey(m.form))
	}
	if len(m.cfg.Targets) != 1 || m.cfg.Targets[0].Name != "pc-new" {
		t.Fatalf("expected pc-new committed to memory config, got %+v", m.cfg.Targets)
	}

	// Press 's' -> Save Summary must warn about profiles with empty allow without blocking save!
	m, _ = sendKey(m, "s")
	if m.screen != screenSaveSummary {
		t.Fatalf("expected screenSaveSummary (warning, not blocking error), got %v (errs=%v)", m.screen, m.valErrors)
	}
	if !strings.Contains(m.View(), "허용 클라이언트(allow)가 비어 있어") {
		t.Fatalf("expected blackhole target warning in save summary, got:\n%s", m.View())
	}
}

func TestGlobalFormRejectsLowProxyPortAndLANIngressOverlap(t *testing.T) {
	if err := validateProxyPortStr("1023"); err == nil {
		t.Fatal("expected proxy_port 1023 to be rejected by form validator")
	}
	if err := validateProxyPortStr("80"); err == nil {
		t.Fatal("expected proxy_port 80 to be rejected by form validator")
	}
	if err := validateProxyPortStr("1024"); err != nil {
		t.Fatalf("expected proxy_port 1024 to be accepted, got %v", err)
	}

	m, _, _, _, _ := setupTestModel(t, true)
	m = sendFormKey(m, "4")
	m = sendFormKey(m, "enter")
	m.gDraft.lanInterface = "eth0"
	m.gDraft.ingressInterfaces = []string{"eth0"}
	m.form = m.buildGlobalForm()
	m = runImmediateCmd(m, m.form.Init(), 0)
	m = sendFormKey(m, "tab")   // focus ingress_interfaces
	m = sendFormKey(m, "enter") // attempt to advance with lan_interface selected in ingress_interfaces
	if len(m.form.Errors()) == 0 {
		t.Fatal("expected Global Form ingress_interfaces validator to reject selecting lan_interface")
	}

	// Verify single-interface host does NOT inject synthetic wg0/eth0 options not in system or draft
	m.deps.Interfaces = netutil.StaticProvider{
		Items: []netutil.InterfaceInfo{
			{Name: "enp1s0", Index: 2, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.10/24")}, Up: true},
		},
	}
	m.gDraft.lanInterface = "enp1s0"
	m.gDraft.ingressInterfaces = []string{"enp1s0"}
	m.form = m.buildGlobalForm()
	_ = m.form.Init()
	gView := m.View()
	if strings.Contains(gView, "wg0") || strings.Contains(gView, "eth0") {
		t.Fatalf("expected Global Form not to inject synthetic wg0/eth0 when host has enp1s0, got:\n%s", gView)
	}
}

func TestTUILANScanChecksAllSubnetsForSizeLimit(t *testing.T) {
	m, _, _, _, _ := setupTestModel(t, true)
	m.deps.Interfaces = netutil.StaticProvider{
		Items: []netutil.InterfaceInfo{
			{
				Name:         "eth0",
				Index:        2,
				HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
				Prefixes: []netip.Prefix{
					netip.MustParsePrefix("192.168.0.10/24"),
					netip.MustParsePrefix("10.0.0.10/16"), // secondary prefix > /22!
				},
				Up: true,
			},
		},
	}
	m = sendFormKey(m, "a")
	m, _ = sendKey(m, "ctrl+l")
	if m.screen != screenNotice || m.noticeTitle != "LAN 검색 제한" {
		t.Fatalf("expected LAN scan blocked when secondary subnet exceeds /22, got screen=%v title=%q", m.screen, m.noticeTitle)
	}
}

func TestTUIMultiSubnetWakeBroadcastSelection(t *testing.T) {
	m, _, _, _, wolMock := setupTestModel(t, true)
	m.deps.Interfaces = netutil.StaticProvider{
		Items: []netutil.InterfaceInfo{
			{
				Name:         "eth0",
				Index:        2,
				HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
				Prefixes: []netip.Prefix{
					netip.MustParsePrefix("192.168.0.10/24"),
					netip.MustParsePrefix("192.168.10.10/24"),
				},
				Up: true,
			},
			{
				Name:     "wg0",
				Index:    3,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("10.66.0.1/24")},
				Up:       true,
			},
		},
	}
	m.cfg.Targets = append(m.cfg.Targets, config.Target{
		Name:     "pc-sub2",
		IP:       "192.168.10.50",
		MAC:      "aa:bb:cc:dd:ee:50",
		Profiles: []string{"rdp"},
		Allow:    []string{"laptop"},
	})
	m.targetCursor = 1

	m, cmd := sendKey(m, "w")
	next, _ := m.Update(cmd())
	m = next.(*Model)
	if wolMock.lastBcast != netip.MustParseAddr("192.168.10.255") {
		t.Fatalf("expected TUI 'w' on second-subnet target to send magic packet to 192.168.10.255, got %v", wolMock.lastBcast)
	}

	// Also verify TUI 't' port test binds matching second loopback subnet source IP when deps.Dial is nil
	lnSub2, err := net.Listen("tcp4", "127.0.2.20:0")
	if err == nil {
		defer lnSub2.Close()
		sub2Port := lnSub2.Addr().(*net.TCPAddr).Port
		srcCh := make(chan string, 1)
		go func() {
			c, err := lnSub2.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			srcCh <- host
		}()
		m.deps.Interfaces = netutil.StaticProvider{
			Items: []netutil.InterfaceInfo{
				{
					Name:  "eth0",
					Index: 2,
					Prefixes: []netip.Prefix{
						netip.MustParsePrefix("127.0.1.10/24"),
						netip.MustParsePrefix("127.0.2.10/24"),
					},
					Up: true,
				},
			},
		}
		m.cfg.Profiles["loop-prof"] = config.Profile{Port: sub2Port, Wake: config.WakeNever}
		m.cfg.Targets = []config.Target{{
			Name:     "loop-sub2",
			IP:       "127.0.2.20",
			MAC:      "aa:bb:cc:dd:ee:60",
			Profiles: []string{"loop-prof"},
			Allow:    []string{"laptop"},
		}}
		m.targetCursor = 0
		_, tCmd := sendKey(m, "t")
		tRes := tCmd().(portTestResultMsg)
		if len(tRes.lines) != 1 || !strings.Contains(tRes.lines[0], "열림") {
			t.Fatalf("expected port test open on 127.0.2.20:%d, got %v", sub2Port, tRes.lines)
		}
		if gotSrc := <-srcCh; gotSrc != "127.0.2.10" {
			t.Fatalf("expected TUI 't' to bind second subnet source 127.0.2.10, got %s", gotSrc)
		}
	}
}
