package config

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
)

func testIfaces() netutil.StaticProvider {
	return netutil.StaticProvider{
		Items: []netutil.InterfaceInfo{
			{
				Name:     "eth0",
				Index:    2,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.10/24")},
				Up:       true,
			},
			{
				Name:     "wg0",
				Index:    3,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("10.66.0.1/24")},
				Up:       true,
			},
		},
	}
}

const specExampleYAML = `# 이 파일은 wolproxy TUI가 관리한다. 주석은 저장 시 사라지므로 메모는 note에 쓴다.
lan_interface: eth0
ingress_interfaces: [wg0]
proxy_port: 13389
wake_timeout: 120s
wake_cooldown: 10s
poll_interval: 2s

clients:
  laptop: { cidr: 10.66.0.2/32, note: "업무용 노트북" }
  phone: { cidr: 10.66.0.3/32 }

profiles:
  rdp: { port: 3389, wake: auto }
  ssh: { port: 22, wake: auto }
  ssh-manual: { port: 22, wake: never, note: "깨우지 않는 SSH" }

targets:
  - name: pc1
    note: "거실 데스크톱"
    ip: 192.168.0.21
    mac: "aa:bb:cc:dd:ee:01"
    profiles: [rdp, ssh-manual]
    allow: [laptop, phone]
  - name: pc2
    ip: 192.168.0.22
    alias: 10.66.1.12
    mac: "aa:bb:cc:dd:ee:02"
    profiles: [ssh]
    allow: [laptop]
`

func TestParseAndValidateSpecExample(t *testing.T) {
	cfg, hasComments, err := ParseBytes([]byte(specExampleYAML))
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}
	if hasComments {
		t.Fatalf("expected managed header alone NOT to flag HasUserComments")
	}
	errs := Validate(cfg, testIfaces())
	if len(errs) != 0 {
		t.Fatalf("expected valid spec example, got errors: %v", errs)
	}

	// Round-trip marshal & re-parse
	out, err := Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	cfg2, hasComments2, err := ParseBytes(out)
	if err != nil {
		t.Fatalf("re-parse failed: %v", err)
	}
	if hasComments2 {
		t.Fatalf("expected marshaled output not to flag HasUserComments")
	}
	diff := Diff(cfg, cfg2)
	if diff.HasChanges() {
		t.Fatalf("expected no diff after round-trip, got: %v", diff.Entries)
	}
}

func TestCommentDetectionIgnoresHashesInNotes(t *testing.T) {
	withHashInString := strings.Replace(specExampleYAML, "거실 데스크톱", "방 #2 데스크톱", 1)
	_, hasComments, err := ParseBytes([]byte(withHashInString))
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}
	if hasComments {
		t.Fatal("expected # inside quoted note string not to count as comment")
	}

	withExtraComment := specExampleYAML + "\n# 사용자 메모 주석\n"
	_, hasComments2, err := ParseBytes([]byte(withExtraComment))
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}
	if !hasComments2 {
		t.Fatal("expected extra comment outside managed header to set HasUserComments=true")
	}
}

func TestValidateCatchesAllSpecViolations(t *testing.T) {
	cfg, _, err := ParseBytes([]byte(specExampleYAML))
	if err != nil {
		t.Fatal(err)
	}

	// 1. Duplicate IP/alias, alias overlapping LAN, duplicate port in target, missing client/profile/iface, bad MAC
	cfg.LANInterface = "eth99"
	cfg.IngressInterfaces = []string{"wg99"}
	cfg.Targets[0].Profiles = []string{"ssh", "ssh-manual"} // both port 22!
	cfg.Targets[0].Allow = []string{"unknown-client"}
	cfg.Targets[1].Alias = "192.168.0.21" // collides with pc1 IP AND overlaps eth0 if eth0 were valid
	cfg.Targets[1].MAC = "invalid-mac"
	cfg.Targets[1].Profiles = []string{"missing-prof"}

	errs := Validate(cfg, testIfaces())
	if len(errs) < 6 {
		t.Fatalf("expected at least 6 validation errors, got %d: %v", len(errs), errs)
	}

	// Check alias overlapping LAN specifically when LAN interface is valid
	cfg2, _, _ := ParseBytes([]byte(specExampleYAML))
	cfg2.Targets[1].Alias = "192.168.0.99" // inside 192.168.0.0/24!
	errs2 := Validate(cfg2, testIfaces())
	if len(errs2) != 1 || errs2[0].Section != SectionTarget || errs2[0].ItemName != "pc2" || errs2[0].Field != "alias" {
		t.Fatalf("expected single alias LAN overlap error on pc2, got: %v", errs2)
	}
}

func TestSaveAtomicBackupAndExternalModCheck(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	cfg, _, _ := ParseBytes([]byte(specExampleYAML))
	mod1, err := SaveAtomic(cfgPath, cfg)
	if err != nil {
		t.Fatalf("first SaveAtomic failed: %v", err)
	}

	loaded, meta, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if !meta.ModTime.Equal(mod1) {
		t.Fatalf("ModTime mismatch: %v vs %v", meta.ModTime, mod1)
	}
	changed, err := CheckExternalModification(cfgPath, meta)
	if err != nil || changed {
		t.Fatalf("expected no external modification, got changed=%v err=%v", changed, err)
	}

	// Modify file externally with newer mtime
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(cfgPath, future, future); err != nil {
		t.Fatal(err)
	}
	changed, err = CheckExternalModification(cfgPath, meta)
	if err != nil || !changed {
		t.Fatalf("expected external modification detected, got changed=%v err=%v", changed, err)
	}

	// Save a second revision and verify .bak exists with previous content
	loaded.ProxyPort = 14400
	if _, err := SaveAtomic(cfgPath, loaded); err != nil {
		t.Fatalf("second SaveAtomic failed: %v", err)
	}
	bakData, err := os.ReadFile(cfgPath + ".bak")
	if err != nil {
		t.Fatalf("expected backup file .bak: %v", err)
	}
	bakCfg, _, err := ParseBytes(bakData)
	if err != nil || bakCfg.ProxyPort != 13389 {
		t.Fatalf("backup file did not preserve previous proxy_port=13389: %v, err=%v", bakCfg, err)
	}
}

func TestRenameAndReferenceLookup(t *testing.T) {
	cfg, _, _ := ParseBytes([]byte(specExampleYAML))
	if got := cfg.TargetsUsingClient("laptop"); len(got) != 2 {
		t.Fatalf("expected 2 targets using laptop, got %v", got)
	}
	cfg.RenameClient("laptop", "work-laptop")
	if got := cfg.TargetsUsingClient("work-laptop"); len(got) != 2 {
		t.Fatalf("expected rename to propagate to 2 targets, got %v", got)
	}
	cfg.RenameProfile("ssh", "ssh-auto")
	if got := cfg.TargetsUsingProfile("ssh-auto"); len(got) != 1 || got[0] != "pc2" {
		t.Fatalf("expected profile rename to propagate to pc2, got %v", got)
	}
}

func TestValidateTargetLANSubnetAndLocalCollision(t *testing.T) {
	ifaces := testIfaces() // eth0=192.168.0.10/24, wg0=10.66.0.1/24

	// 1. Target IP outside LAN subnet
	cfg1, _, _ := ParseBytes([]byte(specExampleYAML))
	cfg1.Targets[0].IP = "172.16.0.21"
	if errs := Validate(cfg1, ifaces); len(errs) != 1 || errs[0].Field != "ip" {
		t.Fatalf("expected target IP outside LAN subnet error, got: %v", errs)
	}

	// 2. Target IP equals LAN host's own IP (192.168.0.10)
	cfg2, _, _ := ParseBytes([]byte(specExampleYAML))
	cfg2.Targets[0].IP = "192.168.0.10"
	if errs := Validate(cfg2, ifaces); len(errs) != 1 || !strings.Contains(errs[0].Message, "로컬 주소와 충돌") {
		t.Fatalf("expected target IP local collision error, got: %v", errs)
	}

	// 3. Target IP equals LAN broadcast address (192.168.0.255)
	cfg3, _, _ := ParseBytes([]byte(specExampleYAML))
	cfg3.Targets[0].IP = "192.168.0.255"
	if errs := Validate(cfg3, ifaces); len(errs) != 1 || !strings.Contains(errs[0].Message, "브로드캐스트") {
		t.Fatalf("expected target IP subnet broadcast error, got: %v", errs)
	}

	// 4. Target Alias equals wg0's own IP (10.66.0.1)
	cfg4, _, _ := ParseBytes([]byte(specExampleYAML))
	cfg4.Targets[1].Alias = "10.66.0.1"
	if errs := Validate(cfg4, ifaces); len(errs) != 1 || !strings.Contains(errs[0].Message, "로컬 주소와 충돌") {
		t.Fatalf("expected alias local collision error, got: %v", errs)
	}
}

func TestSaveAtomicCheckedRejectsConcurrentExternalModification(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	cfg, _, _ := ParseBytes([]byte(specExampleYAML))
	if _, err := SaveAtomic(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, meta, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate external edit bumping mtime
	future := time.Now().Add(3 * time.Second)
	if err := os.Chtimes(cfgPath, future, future); err != nil {
		t.Fatal(err)
	}

	loaded.ProxyPort = 14400
	if _, err := SaveAtomicChecked(cfgPath, loaded, &meta); !errors.Is(err, ErrExternalModification) {
		t.Fatalf("expected ErrExternalModification, got: %v", err)
	}
}

func TestProxyPortDefaultAndMissingInterfaceWarnings(t *testing.T) {
	// 1. Omitted proxy_port defaults to 13389; explicit proxy_port: 0 still fails validation
	omittedPortYAML := `lan_interface: eth0
ingress_interfaces: [wg0]
clients:
  laptop: { cidr: 10.66.0.2/32 }
profiles:
  ssh: { port: 22, wake: auto }
targets: []
`
	cfg, _, err := ParseBytes([]byte(omittedPortYAML))
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}
	if cfg.ProxyPort != DefaultProxyPort {
		t.Fatalf("expected omitted proxy_port to default to %d, got %d", DefaultProxyPort, cfg.ProxyPort)
	}
	if errs := Validate(cfg, testIfaces()); len(errs) != 0 {
		t.Fatalf("expected omitted proxy_port config to validate cleanly, got: %v", errs)
	}

	zeroPortYAML := omittedPortYAML + "proxy_port: 0\n"
	cfgZero, _, err := ParseBytes([]byte(zeroPortYAML))
	if err != nil {
		t.Fatal(err)
	}
	if errs := Validate(cfgZero, testIfaces()); len(errs) != 1 || errs[0].Field != "proxy_port" {
		t.Fatalf("expected explicit proxy_port: 0 to fail validation, got: %v", errs)
	}

	// 2. Missing wg0 / eth0 is an error when StrictInterfaces=true, but only a warning when StrictInterfaces=false
	onlyLAN := netutil.StaticProvider{
		Items: []netutil.InterfaceInfo{
			{
				Name:     "eth0",
				Index:    2,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.10/24")},
				Up:       true,
			},
		},
	}
	strictRep := ValidateWithOptions(cfg, onlyLAN, ValidateOptions{StrictInterfaces: true})
	if len(strictRep.Errors) != 1 || strictRep.Errors[0].Field != "ingress_interfaces" {
		t.Fatalf("expected strict validation error for missing wg0, got: %+v", strictRep)
	}
	nonStrictRep := ValidateWithOptions(cfg, onlyLAN, ValidateOptions{StrictInterfaces: false})
	if len(nonStrictRep.Errors) != 0 || len(nonStrictRep.Warnings) != 1 || nonStrictRep.Warnings[0].Field != "ingress_interfaces" {
		t.Fatalf("expected non-strict validation to emit 0 errors and 1 warning for missing wg0, got: %+v", nonStrictRep)
	}
}
