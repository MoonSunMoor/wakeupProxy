//go:build linux

package arp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
	"golang.org/x/sys/unix"
)

func TestNonRootIsAwakeAndLookupMACArePassive(t *testing.T) {
	lanIface := netutil.InterfaceInfo{
		Name:         "eth0",
		Index:        2,
		HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		Prefixes:     []netip.Prefix{netip.MustParsePrefix("192.168.0.10/24")},
	}
	targetIP := netip.MustParseAddr("192.168.0.21")

	for _, activeState := range []uint16{unix.NUD_REACHABLE, unix.NUD_DELAY, unix.NUD_PROBE, unix.NUD_PERMANENT} {
		chk := SystemChecker{
			rawQuery: func(context.Context, netutil.InterfaceInfo, []netip.Addr, time.Duration, bool) (map[netip.Addr]string, error) {
				return nil, unix.EPERM
			},
			netlinkLookup: func(int, netip.Addr) (uint16, string, bool, error) {
				return activeState, "aa:bb:cc:dd:ee:01", true, nil
			},
			procLookup: func(string, netip.Addr) string {
				t.Fatal("procLookup should not be called when netlinkLookup succeeds")
				return ""
			},
		}
		awake, err := chk.IsAwake(context.Background(), lanIface, targetIP)
		if err != nil || !awake {
			t.Fatalf("expected state 0x%x to be awake, got awake=%v err=%v", activeState, awake, err)
		}
	}

	for _, inactiveState := range []uint16{unix.NUD_STALE, unix.NUD_FAILED, unix.NUD_INCOMPLETE} {
		chk := SystemChecker{
			rawQuery: func(context.Context, netutil.InterfaceInfo, []netip.Addr, time.Duration, bool) (map[netip.Addr]string, error) {
				return nil, unix.EACCES
			},
			netlinkLookup: func(int, netip.Addr) (uint16, string, bool, error) {
				return inactiveState, "aa:bb:cc:dd:ee:01", true, nil
			},
			procLookup: func(string, netip.Addr) string {
				t.Fatal("procLookup should not override valid netlink inactive state")
				return "aa:bb:cc:dd:ee:01"
			},
		}
		start := time.Now()
		awake, err := chk.IsAwake(context.Background(), lanIface, targetIP)
		if err != nil || awake {
			t.Fatalf("expected state 0x%x to be asleep, got awake=%v err=%v", inactiveState, awake, err)
		}
		if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
			t.Fatalf("expected passive IsAwake to return immediately without polling sleep, took %v", elapsed)
		}
	}

	// Netlink failure falls back to /proc/net/arp passively
	chkFallback := SystemChecker{
		rawQuery: func(context.Context, netutil.InterfaceInfo, []netip.Addr, time.Duration, bool) (map[netip.Addr]string, error) {
			return nil, unix.EPERM
		},
		netlinkLookup: func(int, netip.Addr) (uint16, string, bool, error) {
			return 0, "", false, errors.New("netlink unavailable")
		},
		procLookup: func(string, netip.Addr) string {
			return "aa:bb:cc:dd:ee:01"
		},
	}
	if awake, err := chkFallback.IsAwake(context.Background(), lanIface, targetIP); err != nil || !awake {
		t.Fatalf("expected /proc/net/arp fallback awake=true, got %v err=%v", awake, err)
	}
	if mac, reason := chkFallback.LookupMAC(context.Background(), lanIface, targetIP); mac != "aa:bb:cc:dd:ee:01" || reason != "" {
		t.Fatalf("expected LookupMAC fallback to /proc/net/arp, got mac=%q reason=%q", mac, reason)
	}

	// LookupMAC when uncached and non-root returns immediately without sleeping
	chkMiss := SystemChecker{
		rawQuery: func(context.Context, netutil.InterfaceInfo, []netip.Addr, time.Duration, bool) (map[netip.Addr]string, error) {
			return nil, unix.EPERM
		},
		netlinkLookup: func(int, netip.Addr) (uint16, string, bool, error) {
			return 0, "", false, nil
		},
		procLookup: func(string, netip.Addr) string {
			return ""
		},
	}
	start := time.Now()
	mac, reason := chkMiss.LookupMAC(context.Background(), lanIface, targetIP)
	if mac != "" || reason == "" {
		t.Fatalf("expected empty MAC with reason on non-root cache miss, got mac=%q reason=%q", mac, reason)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("expected passive LookupMAC miss to return immediately, took %v", elapsed)
	}
}
