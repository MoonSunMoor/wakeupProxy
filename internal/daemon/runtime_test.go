package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoonSunMoor/wakeupProxy/internal/proxy"
)

func TestRuntimeStateWriteReadRemove(t *testing.T) {
	dir := t.TempDir()
	snap := proxy.RuntimeSnapshot{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         13389,
		ListenAddrs:       []string{"10.66.0.1:13389"},
	}
	st := NewRuntimeState("/etc/wolproxy/config.yaml", snap, time.Time{})
	if err := WriteRuntimeState(dir, st); err != nil {
		t.Fatalf("WriteRuntimeState failed: %v", err)
	}

	got, ok, err := ReadRuntimeState(dir)
	if err != nil || !ok {
		t.Fatalf("ReadRuntimeState failed: ok=%v err=%v", ok, err)
	}
	if got.ProxyPort != 13389 || got.LANInterface != "eth0" || len(got.IngressInterfaces) != 1 {
		t.Fatalf("unexpected RuntimeState: %+v", got)
	}

	RemoveRuntimeState(dir)
	_, ok, err = ReadRuntimeState(dir)
	if err != nil || ok {
		t.Fatalf("expected state removed, got ok=%v err=%v", ok, err)
	}
}

func TestControlServerSynchronousReloadSuccessAndFailure(t *testing.T) {
	// Use a short directory path under os.TempDir() so AF_UNIX sun_path stays well under 108 chars on Windows & Unix.
	dir, err := os.MkdirTemp("", "wpctl-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(filepath.Clean(dir))

	var shouldFail atomic.Bool
	cs, err := StartControlServer(dir, func(_ context.Context) error {
		if shouldFail.Load() {
			return errors.New("validation failed: duplicate IP")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("StartControlServer failed: %v", err)
	}
	defer cs.Close()

	// 1. Successful reload returns nil
	if err := RequestReload(context.Background(), dir); err != nil {
		t.Fatalf("expected RequestReload success, got: %v", err)
	}

	// 2. Failing reload propagates exact daemon error synchronously
	shouldFail.Store(true)
	err = RequestReload(context.Background(), dir)
	if err == nil {
		t.Fatal("expected RequestReload to return error when reloadFn fails")
	}
}

func TestSameConfigPathNormalizesRelativeAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	realCfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(realCfg, []byte("proxy_port: 13389\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	subDir := filepath.Join(dir, "nested")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	relStyle := filepath.Join(subDir, "..", "config.yaml")
	if !SameConfigPath(realCfg, relStyle) {
		t.Fatalf("expected SameConfigPath(%q, %q) == true", realCfg, relStyle)
	}

	otherCfg := filepath.Join(dir, "other.yaml")
	if SameConfigPath(realCfg, otherCfg) {
		t.Fatalf("expected SameConfigPath(%q, %q) == false", realCfg, otherCfg)
	}

	linkCfg := filepath.Join(dir, "linked-config.yaml")
	if err := os.Symlink(realCfg, linkCfg); err == nil {
		if !SameConfigPath(realCfg, linkCfg) {
			t.Fatalf("expected symlink %q to match target %q", linkCfg, realCfg)
		}
	}
}
