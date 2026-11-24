package tui

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/MoonSunMoor/wakeupProxy/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

// Save & Apply 4-step pipeline (`s`):
// 1. Validate -> error list with form jump
// 2. Change summary (+ comment loss warning) -> user confirmation
// 3. External modification check -> backup (.bak) + atomic write + directory fsync
// 4. Compare against live running daemon state: systemctl reload (or confirm + systemctl restart)
func (m *Model) startSaveFlow() (tea.Model, tea.Cmd) {
	if !m.deps.IsRoot {
		m.showNotice("권한 필요", "저장하려면 sudo로 실행해 주세요.", true, screenList)
		return m, nil
	}

	rep := config.ValidateWithOptions(m.cfg, m.deps.Interfaces, config.ValidateOptions{
		StrictInterfaces: false,
	})
	if len(rep.Errors) > 0 {
		m.valErrors = rep.Errors
		m.valWarnings = nil
		m.modalCursor = 0
		m.screen = screenValidationErrors
		return m, nil
	}

	m.valErrors = nil
	m.valWarnings = rep.Warnings
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
		return m.writeFileAndProceedToApply(false)
	}
	return m, nil
}

func (m *Model) handleConfirmExternalOverwriteKey(keyStr string) (tea.Model, tea.Cmd) {
	if keyStr == "n" || keyStr == "N" || keyStr == "esc" {
		m.screen = screenList
		return m, nil
	}
	if keyStr == "y" || keyStr == "Y" || keyStr == "enter" {
		return m.writeFileAndProceedToApply(true)
	}
	return m, nil
}

func (m *Model) writeFileAndProceedToApply(forceOverwrite bool) (tea.Model, tea.Cmd) {
	var expected *config.LoadMeta
	if !forceOverwrite {
		metaCopy := m.meta
		expected = &metaCopy
	}
	newModTime, err := config.SaveAtomicChecked(m.deps.ConfigPath, m.cfg, expected)
	if err != nil {
		if errors.Is(err, config.ErrExternalModification) {
			m.screen = screenConfirmExternalOverwrite
			return m, nil
		}
		m.showNotice("설정 파일 저장 실패", err.Error(), true, screenList)
		return m, nil
	}
	m.savedCfg = m.cfg.Clone()
	m.meta = config.LoadMeta{
		ModTime:         newModTime,
		Exists:          true,
		HasUserComments: false,
	}

	reasons := m.computeRestartReasons()
	if len(reasons) > 0 {
		m.restartReasons = reasons
		m.screen = screenConfirmRestart
		return m, nil
	}
	m.restartReasons = nil
	m.screen = screenList
	m.statusLine = "설정 파일 저장 완료. systemctl reload wolproxy 실행 중..."
	return m, m.runServiceActionCmd("reload")
}

// computeRestartReasons checks whether an active running daemon has bound different
// lan_interface, ingress_interfaces, or proxy_port values from m.cfg.
func (m *Model) computeRestartReasons() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	st := m.deps.Service.Status(ctx)

	if !st.Active {
		// Service is stopped: Reload() will start it fresh without dropping existing connections.
		return nil
	}
	if st.HasRuntimeState {
		var reasons []string
		if st.LANInterface != m.cfg.LANInterface {
			reasons = append(reasons, "lan_interface")
		}
		if !slices.Equal(st.IngressInterfaces, m.cfg.IngressInterfaces) {
			reasons = append(reasons, "ingress_interfaces")
		}
		if st.ProxyPort != m.cfg.ProxyPort {
			reasons = append(reasons, "proxy_port")
		}
		return reasons
	}

	applyDiff := config.Diff(m.appliedCfg, m.cfg)
	if applyDiff.RequiresRestart {
		return applyDiff.RestartReasons
	}
	return nil
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
