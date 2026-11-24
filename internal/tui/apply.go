package tui

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// ServiceManager abstracts systemd reload/restart and journald log inspection.
type ServiceManager interface {
	Reload(ctx context.Context) error
	Restart(ctx context.Context) error
	RecentLogs(ctx context.Context, lines int) string
}

// SystemdManager invokes systemctl and journalctl for the wolproxy unit.
type SystemdManager struct {
	UnitName string
}

func (m SystemdManager) unit() string {
	if m.UnitName != "" {
		return m.UnitName
	}
	return "wolproxy"
}

func (m SystemdManager) Reload(ctx context.Context) error {
	unit := m.unit()
	// If the service is not yet running (e.g. initial setup), start it; otherwise reload (SIGHUP).
	checkCmd := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit)
	if err := checkCmd.Run(); err != nil {
		return runSystemctl(ctx, "start", unit)
	}
	return runSystemctl(ctx, "reload", unit)
}

func (m SystemdManager) Restart(ctx context.Context) error {
	return runSystemctl(ctx, "restart", m.unit())
}

func (m SystemdManager) RecentLogs(ctx context.Context, lines int) string {
	if lines <= 0 {
		lines = 10
	}
	cmd := exec.CommandContext(ctx, "journalctl", "-u", m.unit(), "-n", strconv.Itoa(lines), "--no-pager", "-o", "short")
	out, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(out))
	if err != nil && trimmed == "" {
		return fmt.Sprintf("(journalctl 조회 실패: %v)", err)
	}
	return trimmed
}

func runSystemctl(ctx context.Context, action, unit string) error {
	cmd := exec.CommandContext(ctx, "systemctl", action, unit)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("systemctl %s %s 실패: %w (%s)", action, unit, err, msg)
		}
		return fmt.Errorf("systemctl %s %s 실패: %w", action, unit, err)
	}
	return nil
}
