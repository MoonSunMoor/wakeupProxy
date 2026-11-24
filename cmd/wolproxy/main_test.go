package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
)

func TestNoArgsNonTTYPrintsHelpAndExitsNonZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, strings.NewReader(""), &stdout, &stderr, func() bool { return false })
	if code == 0 {
		t.Fatal("expected non-zero exit code when stdin is not a TTY")
	}
	if !strings.Contains(stderr.String(), "사용법:") {
		t.Fatalf("expected usage help output on non-TTY, got %q", stderr.String())
	}
}

func TestCheckCommandExitCodes(t *testing.T) {
	ifaces, err := netutil.SystemProvider{}.Interfaces()
	if err != nil {
		t.Skipf("cannot list system interfaces: %v", err)
	}
	var usable string
	for _, info := range ifaces {
		if len(info.Prefixes) > 0 {
			usable = info.Name
			break
		}
	}
	if usable == "" {
		t.Skip("no IPv4 interface available on host")
	}

	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid.yaml")
	validYAML := `lan_interface: ` + usable + `
ingress_interfaces: [` + usable + `]
proxy_port: 13389
clients:
  laptop: { cidr: 10.66.0.2/32 }
profiles:
  ssh: { port: 22, wake: auto }
targets: []
`
	if err := os.WriteFile(validPath, []byte(validYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-c", validPath, "check"}, strings.NewReader(""), &stdout, &stderr, func() bool { return false }); code != 0 {
		t.Fatalf("expected valid config check to exit 0, got %d (%s)", code, stderr.String())
	}
	// Also test -c after subcommand
	if code := run([]string{"check", "-c", validPath}, strings.NewReader(""), &stdout, &stderr, func() bool { return false }); code != 0 {
		t.Fatalf("expected check -c <path> to exit 0, got %d (%s)", code, stderr.String())
	}

	invalidPath := filepath.Join(dir, "invalid.yaml")
	_ = os.WriteFile(invalidPath, []byte("lan_interface: nonexistent_iface_xyz\nproxy_port: 99999\n"), 0o644)
	stderr.Reset()
	if code := run([]string{"-c", invalidPath, "check"}, strings.NewReader(""), &stdout, &stderr, func() bool { return false }); code == 0 {
		t.Fatal("expected invalid config check to exit non-zero")
	}
}
