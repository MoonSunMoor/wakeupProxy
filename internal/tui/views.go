package tui

import (
	"fmt"
	"strings"

	"github.com/MoonSunMoor/wakeupProxy/internal/config"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("230")).
			Background(lipgloss.Color("62")).
			Padding(0, 1)

	readOnlyBadgeStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("230")).
				Background(lipgloss.Color("166")).
				Padding(0, 1)

	dirtyBadgeStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("232")).
			Background(lipgloss.Color("220")).
			Padding(0, 1)

	activeTabStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("229")).
			Background(lipgloss.Color("57")).
			Padding(0, 2)

	inactiveTabStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("250")).
				Background(lipgloss.Color("236")).
				Padding(0, 2)

	headerRowStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("111")).
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(lipgloss.Color("240"))

	selectedRowStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("255")).
				Background(lipgloss.Color("237"))

	selectedOptionCursorStyle = lipgloss.NewStyle().
					Bold(true).
					Foreground(lipgloss.Color("78")).
					Background(lipgloss.Color("237"))

	normalOptionStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("252"))

	blurredUnselectedSelectStyle = lipgloss.NewStyle().
					Foreground(lipgloss.Color("244"))

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62")).
			Padding(1, 2)

	warnStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("214"))

	errStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("203"))

	okStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("78"))

	mutedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("244"))

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252")).
			Background(lipgloss.Color("235")).
			Padding(0, 1)
)

func isASCIIProfile() bool {
	return lipgloss.ColorProfile() == termenv.Ascii
}

func padRight(s string, width int) string {
	w := lipgloss.Width(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

func renderSelectableRow(row string, minWidth int, selected bool) string {
	padded := padRight(row, minWidth)
	if !selected {
		return padded
	}
	if isASCIIProfile() {
		return padded + " ←"
	}
	return selectedRowStyle.Render(padded)
}

func truncateDisplay(s string, maxWidth int) string {
	if maxWidth <= 0 || lipgloss.Width(s) <= maxWidth {
		return s
	}
	var b strings.Builder
	cur := 0
	for _, r := range s {
		rw := lipgloss.Width(string(r))
		if cur+rw+1 > maxWidth {
			b.WriteRune('…')
			break
		}
		b.WriteRune(r)
		cur += rw
	}
	return b.String()
}

func formatCell(s string, width int) string {
	return padRight(truncateDisplay(s, width-1), width)
}

func (m *Model) renderHeader() string {
	var parts []string
	parts = append(parts, titleStyle.Render("wolproxy 설정 편집기"))
	parts = append(parts, mutedStyle.Render(m.deps.ConfigPath))
	if !m.deps.IsRoot {
		parts = append(parts, readOnlyBadgeStyle.Render("읽기 전용 (sudo 필요)"))
	}
	if m.isDirty() {
		parts = append(parts, dirtyBadgeStyle.Render("수정됨 *"))
	}
	headerLine := strings.Join(parts, "  ")

	tabNames := []string{"1. 타깃", "2. 클라이언트", "3. 프로파일", "4. 전역 설정"}
	var tabs []string
	for i, name := range tabNames {
		if tabIndex(i) == m.tab {
			tabs = append(tabs, activeTabStyle.Render(name))
		} else {
			tabs = append(tabs, inactiveTabStyle.Render(name))
		}
	}
	tabBar := strings.Join(tabs, " ")
	return headerLine + "\n\n" + tabBar
}

func (m *Model) renderTargetsList() string {
	var b strings.Builder
	hdr := formatCell("이름", 14) +
		formatCell("IP (별칭)", 28) +
		formatCell("프로파일", 20) +
		formatCell("상태", 14) +
		"note"
	hdrWidth := lipgloss.Width(hdr)
	b.WriteString(headerRowStyle.Render(hdr))
	b.WriteByte('\n')

	if len(m.cfg.Targets) == 0 {
		b.WriteString(mutedStyle.Render("등록된 타깃이 없습니다. 'a'를 눌러 타깃을 추가하세요."))
		return b.String()
	}

	for i, t := range m.cfg.Targets {
		ipCol := t.IP
		if t.Alias != "" {
			ipCol = fmt.Sprintf("%s (%s)", t.IP, t.Alias)
		}
		profCol := "-"
		if len(t.Profiles) > 0 {
			profCol = strings.Join(t.Profiles, ",")
		}
		stText := m.formatTargetStatus(t.Name)
		row := formatCell(t.Name, 14) +
			formatCell(ipCol, 28) +
			formatCell(profCol, 20) +
			formatCell(stText, 14) +
			truncateDisplay(t.Note, 30)
		b.WriteString(renderSelectableRow(row, hdrWidth, i == m.targetCursor))
		b.WriteByte('\n')
	}
	return b.String()
}

func (m *Model) formatTargetStatus(name string) string {
	st, ok := m.targetStatus[name]
	if !ok {
		return "확인 전"
	}
	switch st.state {
	case statusWaking:
		return "깨우는 중"
	case statusAwake:
		return "깨어 있음"
	case statusAsleep:
		return "잠듦"
	default:
		return "확인 전"
	}
}

func (m *Model) renderClientsList() string {
	var b strings.Builder
	hdr := formatCell("이름", 18) +
		formatCell("IP/CIDR", 22) +
		formatCell("참조 타깃 수", 14) +
		"note"
	hdrWidth := lipgloss.Width(hdr)
	b.WriteString(headerRowStyle.Render(hdr))
	b.WriteByte('\n')

	names := config.SortedKeys(m.cfg.Clients)
	if len(names) == 0 {
		b.WriteString(mutedStyle.Render("등록된 클라이언트가 없습니다. 'a'를 눌러 추가하세요."))
		return b.String()
	}

	for i, name := range names {
		cl := m.cfg.Clients[name]
		refCount := len(m.cfg.TargetsUsingClient(name))
		row := formatCell(name, 18) +
			formatCell(cl.CIDR, 22) +
			formatCell(fmt.Sprintf("%d", refCount), 14) +
			truncateDisplay(cl.Note, 36)
		b.WriteString(renderSelectableRow(row, hdrWidth, i == m.clientCursor))
		b.WriteByte('\n')
	}
	return b.String()
}

func (m *Model) renderProfilesList() string {
	var b strings.Builder
	hdr := formatCell("이름", 16) +
		formatCell("포트", 8) +
		formatCell("wake", 8) +
		formatCell("idle_timeout", 14) +
		formatCell("참조 타깃 수", 14) +
		"note"
	hdrWidth := lipgloss.Width(hdr)
	b.WriteString(headerRowStyle.Render(hdr))
	b.WriteByte('\n')

	names := config.SortedKeys(m.cfg.Profiles)
	if len(names) == 0 {
		b.WriteString(mutedStyle.Render("등록된 프로파일이 없습니다. 'a'를 눌러 추가하세요."))
		return b.String()
	}

	for i, name := range names {
		pr := m.cfg.Profiles[name]
		idleStr := "0"
		if pr.IdleTimeout > 0 {
			if pr.IdleBytes > 0 {
				idleStr = fmt.Sprintf("%s (<=%dB)", pr.IdleTimeout, pr.IdleBytes)
			} else {
				idleStr = pr.IdleTimeout.String()
			}
		}
		refCount := len(m.cfg.TargetsUsingProfile(name))
		row := formatCell(name, 16) +
			formatCell(fmt.Sprintf("%d", pr.Port), 8) +
			formatCell(pr.Wake, 8) +
			formatCell(idleStr, 14) +
			formatCell(fmt.Sprintf("%d", refCount), 14) +
			truncateDisplay(pr.Note, 30)
		b.WriteString(renderSelectableRow(row, hdrWidth, i == m.profileCursor))
		b.WriteByte('\n')
	}
	return b.String()
}

func (m *Model) renderGlobalSummary() string {
	var b strings.Builder
	if m.deps.IsRoot {
		b.WriteString(headerRowStyle.Render("전역 설정 (Enter를 눌러 편집 폼 열기)"))
	} else {
		b.WriteString(headerRowStyle.Render("전역 설정 (읽기 전용 - 편집하려면 sudo 필요)"))
	}
	b.WriteString("\n\n")
	ing := strings.Join(m.cfg.IngressInterfaces, ", ")
	if ing == "" {
		ing = "(없음)"
	}
	rows := [][2]string{
		{"LAN 인터페이스", m.cfg.LANInterface},
		{"유입 인터페이스", ing},
		{"proxy_port", fmt.Sprintf("%d", m.cfg.ProxyPort)},
		{"wake_timeout", m.cfg.WakeTimeout.String()},
		{"wake_cooldown", m.cfg.WakeCooldown.String()},
		{"poll_interval", m.cfg.PollInterval.String()},
	}
	for _, kv := range rows {
		b.WriteString("  " + formatCell(kv[0], 20) + kv[1] + "\n")
	}
	return b.String()
}

func (m *Model) renderPresetPicker() string {
	var b strings.Builder
	b.WriteString(headerRowStyle.Render("프로파일 프리셋 선택"))
	b.WriteString("\n\n")
	items := m.presetChoices()
	maxW := 0
	for _, item := range items {
		if w := lipgloss.Width(item.label); w > maxW {
			maxW = w
		}
	}
	for i, item := range items {
		b.WriteString(renderSelectableRow(item.label, maxW, i == m.modalCursor))
		b.WriteByte('\n')
	}
	return boxStyle.Render(b.String())
}

func (m *Model) renderLANScanModal() string {
	var b strings.Builder
	b.WriteString(headerRowStyle.Render(fmt.Sprintf("LAN 기기 검색 결과 (%s)", m.cfg.LANInterface)))
	b.WriteString("\n\n")

	if m.scanningLAN {
		b.WriteString("ARP 요청을 보내고 응답을 기다리는 중입니다...")
		return boxStyle.Render(b.String())
	}
	if len(m.scanResults) == 0 {
		b.WriteString(mutedStyle.Render("응답한 켜진 기기가 없습니다. (Esc로 돌아가기)"))
		return boxStyle.Render(b.String())
	}

	existingByIP := make(map[string]string, len(m.cfg.Targets))
	existingByMAC := make(map[string]string, len(m.cfg.Targets))
	for _, t := range m.cfg.Targets {
		existingByIP[t.IP] = t.Name
		existingByMAC[strings.ToLower(t.MAC)] = t.Name
	}

	hdr := formatCell("IP", 18) + formatCell("MAC", 20) + formatCell("호스트 이름", 24) + "등록 여부"
	hdrWidth := lipgloss.Width(hdr)
	b.WriteString(mutedStyle.Render(hdr))
	b.WriteByte('\n')

	for i, h := range m.scanResults {
		host := h.Hostname
		if host == "" {
			host = "-"
		}
		reg := ""
		if tName, ok := existingByIP[h.IP.String()]; ok {
			reg = fmt.Sprintf("[등록됨: %s]", tName)
		} else if tName, ok := existingByMAC[strings.ToLower(h.MAC)]; ok {
			reg = fmt.Sprintf("[등록됨: %s]", tName)
		}
		row := formatCell(h.IP.String(), 18) +
			formatCell(h.MAC, 20) +
			formatCell(host, 24) +
			reg
		b.WriteString(renderSelectableRow(row, hdrWidth, i == m.modalCursor))
		b.WriteByte('\n')
	}
	return boxStyle.Render(b.String())
}

func (m *Model) renderValidationErrorsModal() string {
	var b strings.Builder
	b.WriteString(errStyle.Render(fmt.Sprintf("설정 검증 오류 (%d건) - 항목을 선택하면 해당 편집 폼으로 이동합니다", len(m.valErrors))))
	b.WriteString("\n\n")
	lines := make([]string, len(m.valErrors))
	maxW := 0
	for i, ve := range m.valErrors {
		lines[i] = ve.Error()
		if w := lipgloss.Width(lines[i]); w > maxW {
			maxW = w
		}
	}
	for i, line := range lines {
		b.WriteString(renderSelectableRow(line, maxW, i == m.modalCursor))
		b.WriteByte('\n')
	}
	return boxStyle.Render(b.String())
}

func (m *Model) renderSaveSummaryModal() string {
	var b strings.Builder
	b.WriteString(headerRowStyle.Render("변경 요약 및 저장 확인"))
	b.WriteString("\n\n")

	if !m.pendingDiff.HasChanges() {
		b.WriteString("변경된 항목이 없습니다. 그래도 설정 파일을 다시 저장하고 적용하시겠습니까?\n")
	} else {
		for _, entry := range m.pendingDiff.Entries {
			b.WriteString("  • " + entry.String() + "\n")
		}
	}

	if len(m.valWarnings) > 0 {
		b.WriteString("\n")
		for _, w := range m.valWarnings {
			b.WriteString(warnStyle.Render("⚠ 경고: " + w.Error()))
			b.WriteByte('\n')
		}
	}

	if m.meta.HasUserComments {
		b.WriteString("\n")
		b.WriteString(warnStyle.Render("⚠ 기존 파일에 머리말 밖 주석이 있습니다. 저장하면 주석이 사라집니다 (메모는 note 필드를 사용하세요)."))
		b.WriteByte('\n')
	}

	b.WriteString("\n저장하고 적용하시겠습니까? (y/Enter: 확인, n/Esc: 취소)")
	return boxStyle.Render(b.String())
}

func (m *Model) renderConfirmModal(title, body string) string {
	var b strings.Builder
	b.WriteString(warnStyle.Render(title))
	b.WriteString("\n\n")
	b.WriteString(body)
	b.WriteString("\n\n(y/Enter: 예, n/Esc: 아니요)")
	return boxStyle.Render(b.String())
}

func (m *Model) renderNoticeModal(title, body string, isErr bool) string {
	var b strings.Builder
	if isErr {
		b.WriteString(errStyle.Render(title))
	} else {
		b.WriteString(okStyle.Render(title))
	}
	b.WriteString("\n\n")
	b.WriteString(body)
	b.WriteString("\n\n(Enter 또는 Esc로 닫기)")
	return boxStyle.Render(b.String())
}

func (m *Model) renderTargetDetailModal() string {
	if len(m.cfg.Targets) == 0 {
		return ""
	}
	idx := clampIndex(m.targetCursor, len(m.cfg.Targets))
	t := m.cfg.Targets[idx]

	orNone := func(s string) string {
		if strings.TrimSpace(s) == "" {
			return "(없음)"
		}
		return s
	}
	joinOrNone := func(items []string) string {
		if len(items) == 0 {
			return "(없음)"
		}
		return strings.Join(items, ", ")
	}

	var b strings.Builder
	b.WriteString(headerRowStyle.Render(fmt.Sprintf("타깃 상세 보기: %s", t.Name)))
	b.WriteString("\n\n")
	rows := [][2]string{
		{"이름", t.Name},
		{"IP", t.IP},
		{"별칭", orNone(t.Alias)},
		{"MAC", t.MAC},
		{"프로파일", joinOrNone(t.Profiles)},
		{"허용 클라이언트 (allow)", joinOrNone(t.Allow)},
		{"상태", m.formatTargetStatus(t.Name)},
		{"note", orNone(t.Note)},
	}
	for _, kv := range rows {
		b.WriteString("  " + padRight(kv[0], 26) + kv[1] + "\n")
	}
	b.WriteByte('\n')
	b.WriteString(mutedStyle.Render("설정을 편집하거나 저장하려면 sudo로 실행해 주세요."))
	b.WriteByte('\n')
	b.WriteString(mutedStyle.Render("(Enter, Esc 또는 공백으로 닫기)"))
	return boxStyle.Render(b.String())
}

func (m *Model) renderHelpModal() string {
	helpText := `키 조작 안내

  [탭 및 목록]
  Tab / Shift+Tab  다음·이전 탭 이동 (편집 폼에서는 다음·이전 필드 이동)
  ↑ ↓ / j k        목록 항목 이동
  Enter            선택한 항목 편집 폼 열기 (비-root 타깃 목록에서는 상세 보기)
  a                새 항목 추가 (프로파일은 프리셋 선택 후 열림)
  d                항목 삭제 (다른 타깃이 참조 중이면 차단)

  [타깃 전용]
  w                선택한 타깃에 매직 패킷 송신 ("깨우는 중" 표시)
  t                선택한 타깃의 프로파일 포트 열림 테스트
  Ctrl+L           타깃 폼에서 LAN ARP 기기 검색 (root 전용, /22 이하)

  [공통]
  s / Ctrl+S       설정 검증 → 변경 요약 → 백업·저장 → systemd 적용 (폼 안에서는 Ctrl+S)
  Esc              폼 취소(변경 버림) 또는 대화상자 닫기
  ?                도움말 열기/닫기
  q                종료 (저장하지 않은 변경이 있으면 확인)`
	return boxStyle.Render(helpText)
}

func (m *Model) renderFooter() string {
	var keys string
	switch m.screen {
	case screenList:
		if !m.deps.IsRoot {
			switch m.tab {
			case tabTargets:
				keys = "Tab/Shift+Tab: 탭 이동 | ↑↓/jk: 이동 | Enter: 상세 보기 | w: 깨우기 | t: 포트 테스트 | ?: 도움말 | q: 종료"
			case tabGlobal:
				keys = "Tab/Shift+Tab: 탭 이동 | ?: 도움말 | q: 종료"
			default:
				keys = "Tab/Shift+Tab: 탭 이동 | ↑↓/jk: 이동 | ?: 도움말 | q: 종료"
			}
		} else {
			switch m.tab {
			case tabTargets:
				keys = "Tab/Shift+Tab: 탭 이동 | ↑↓/jk: 이동 | Enter: 편집 | a: 추가 | d: 삭제 | w: 깨우기 | t: 포트 테스트 | s: 저장·적용 | ?: 도움말 | q: 종료"
			case tabGlobal:
				keys = "Tab/Shift+Tab: 탭 이동 | Enter: 편집 폼 열기 | s: 저장·적용 | ?: 도움말 | q: 종료"
			default:
				keys = "Tab/Shift+Tab: 탭 이동 | ↑↓/jk: 이동 | Enter: 편집 | a: 추가 | d: 삭제 | s: 저장·적용 | ?: 도움말 | q: 종료"
			}
		}
	case screenTargetDetail:
		keys = "Enter / Esc / Space: 닫기 | ?: 도움말"
	case screenTargetForm:
		keys = "Tab/Shift+Tab: 필드 이동 | Enter: 다음/완료 | Ctrl+L: LAN 검색 | Esc: 취소 | Ctrl+S: 저장·적용"
	case screenClientForm, screenProfileForm, screenGlobalForm:
		keys = "Tab/Shift+Tab: 필드 이동 | Enter: 다음/완료 | Esc: 취소 | Ctrl+S: 저장·적용"
	case screenPresetPicker, screenLANScan, screenValidationErrors:
		keys = "↑↓/jk: 이동 | Enter: 선택 | Esc: 취소 | ?: 도움말"
	case screenSaveSummary, screenConfirmDelete, screenConfirmExternalOverwrite, screenConfirmRestart, screenConfirmQuit:
		keys = "y/Enter: 확인 | n/Esc: 취소"
	case screenHelp:
		keys = "Esc / ?: 도움말 닫기"
	case screenNotice:
		keys = "Enter / Esc: 닫기"
	}
	return footerStyle.Render(keys)
}
