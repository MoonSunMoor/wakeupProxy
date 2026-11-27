package tui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/MoonSunMoor/wakeupProxy/internal/arp"
	"github.com/MoonSunMoor/wakeupProxy/internal/config"
	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
	"github.com/MoonSunMoor/wakeupProxy/internal/wol"
	tea "github.com/charmbracelet/bubbletea"
)

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
	now := time.Now()
	wakingSet := make(map[string]bool)
	for name, st := range m.targetStatus {
		if st.state == statusWaking && now.Before(st.wakeDeadline) {
			wakingSet[name] = true
		}
	}
	return m.runTargetsARPCheckCmd(m.cfg.Targets, wakingSet)
}

func (m *Model) checkWakingTargetsARPCmd() tea.Cmd {
	if len(m.cfg.Targets) == 0 {
		return nil
	}
	now := time.Now()
	wakingSet := make(map[string]bool)
	var targets []config.Target
	for _, t := range m.cfg.Targets {
		if st, ok := m.targetStatus[t.Name]; ok && st.state == statusWaking && now.Before(st.wakeDeadline) {
			wakingSet[t.Name] = true
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return nil
	}
	return m.runTargetsARPCheckCmd(targets, wakingSet)
}

func (m *Model) runTargetsARPCheckCmd(targets []config.Target, probeSet map[string]bool) tea.Cmd {
	lanName := m.cfg.LANInterface
	targetsCopy := append([]config.Target(nil), targets...)
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
			useProbe := probeSet[tName]
			wg.Add(1)
			go func() {
				defer wg.Done()
				var ok bool
				var err error
				if useProbe {
					ok, err = arpChecker.ProbeAwake(ctx, lanInfo, ipAddr)
				} else {
					ok, err = arpChecker.IsAwake(ctx, lanInfo, ipAddr)
				}
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
	if _, err := arp.CollectScanTargets(lanInfo); err != nil {
		title := "LAN 검색 불가"
		if errors.Is(err, arp.ErrSubnetTooLarge) {
			title = "LAN 검색 제한"
		}
		m.showNotice(title, err.Error(), true, screenTargetForm)
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
		m.macAutoNote = "LAN 검색에서 선택됨"
		m.form = m.buildTargetForm()
		m.screen = screenTargetForm
		return m, m.form.Init()
	}
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
	targetIP, _ := netutil.ParseIPv4Host(t.IP)
	pfx, ok := lanInfo.ResolvePrefix(targetIP)
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
	if dialFn == nil {
		var lanIP netip.Addr
		targetIP, _ := netutil.ParseIPv4Host(t.IP)
		if lanInfo, err := m.deps.Interfaces.InterfaceByName(m.cfg.LANInterface); err == nil {
			if pfx, ok := lanInfo.ResolvePrefix(targetIP); ok {
				lanIP = pfx.Addr()
			}
		}
		dialFn = wol.NewLANDialer(lanIP)
	}

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
