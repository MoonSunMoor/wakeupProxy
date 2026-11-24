package nft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/MoonSunMoor/wakeupProxy/internal/config"
)

const TableName = "wolproxy"

// Manager applies and removes the dedicated inet wolproxy nftables table.
type Manager interface {
	Apply(ctx context.Context, ruleset string) error
	Cleanup(ctx context.Context) error
}

// BuildRuleset builds an atomic `nft -f -` script that replaces `table inet wolproxy`
// in a single netlink transaction without touching ip_forward or forward chains.
func BuildRuleset(ingressInterfaces []string, proxyPort int, cfg *config.Config) (string, error) {
	if len(ingressInterfaces) == 0 {
		return "", errors.New("유입 인터페이스가 비어 있습니다")
	}
	if proxyPort < 1 || proxyPort > 65535 {
		return "", fmt.Errorf("잘못된 proxy_port: %d", proxyPort)
	}
	if cfg == nil {
		return "", errors.New("설정이 비어 있습니다")
	}

	quotedIngress := make([]string, 0, len(ingressInterfaces))
	for _, iface := range ingressInterfaces {
		escaped := strings.ReplaceAll(iface, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		quotedIngress = append(quotedIngress, fmt.Sprintf("%q", escaped))
	}

	var captureElems []string
	seenCapture := make(map[string]bool)
	addCapture := func(ip string, port int) {
		elem := fmt.Sprintf("%s . %d", ip, port)
		if !seenCapture[elem] {
			seenCapture[elem] = true
			captureElems = append(captureElems, elem)
		}
	}

	for _, t := range cfg.Targets {
		for _, profName := range t.Profiles {
			pr, ok := cfg.Profiles[profName]
			if !ok {
				continue
			}
			addCapture(t.IP, pr.Port)
			if strings.TrimSpace(t.Alias) != "" {
				addCapture(t.Alias, pr.Port)
			}
		}
	}

	var b strings.Builder
	// `table inet wolproxy` ensures the table exists before `delete table inet wolproxy`,
	// making the entire replacement idempotent and gapless inside a single `nft -f -` transaction.
	fmt.Fprintf(&b, "table inet %s\n", TableName)
	fmt.Fprintf(&b, "delete table inet %s\n", TableName)
	fmt.Fprintf(&b, "table inet %s {\n", TableName)
	fmt.Fprintf(&b, "  set ingress { type ifname; elements = { %s } }\n", strings.Join(quotedIngress, ", "))
	b.WriteString("  set capture {\n")
	b.WriteString("    type ipv4_addr . inet_service\n")
	if len(captureElems) > 0 {
		fmt.Fprintf(&b, "    elements = { %s }\n", strings.Join(captureElems, ", "))
	}
	b.WriteString("  }\n")
	b.WriteString("  chain prerouting {\n")
	b.WriteString("    type nat hook prerouting priority dstnat;\n")
	fmt.Fprintf(&b, "    iifname @ingress ip daddr . tcp dport @capture redirect to :%d\n", proxyPort)
	b.WriteString("  }\n")
	b.WriteString("}\n")

	return b.String(), nil
}

// CLIManager invokes the system `nft` binary.
type CLIManager struct {
	BinaryPath string
}

func (m CLIManager) resolveBinary() (string, error) {
	if m.BinaryPath != "" {
		return m.BinaryPath, nil
	}
	if p, err := exec.LookPath("nft"); err == nil {
		return p, nil
	}
	for _, candidate := range []string{"/usr/sbin/nft", "/sbin/nft"} {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	return "", errors.New("nft 실행 파일을 찾을 수 없습니다 (nftables 설치 확인 필요)")
}

func (m CLIManager) Apply(ctx context.Context, ruleset string) error {
	bin, err := m.resolveBinary()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, bin, "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("nft 규칙 적용 실패: %w: %s", err, msg)
		}
		return fmt.Errorf("nft 규칙 적용 실패: %w", err)
	}
	return nil
}

func (m CLIManager) Cleanup(ctx context.Context) error {
	bin, err := m.resolveBinary()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, bin, "delete", "table", "inet", TableName)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		// Ignore if table does not exist.
		if strings.Contains(strings.ToLower(msg), "no such file or directory") ||
			strings.Contains(strings.ToLower(msg), "does not exist") {
			return nil
		}
		if msg != "" {
			return fmt.Errorf("nft 테이블 정리 실패: %w: %s", err, msg)
		}
		return fmt.Errorf("nft 테이블 정리 실패: %w", err)
	}
	return nil
}
