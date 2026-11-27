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

	// Netlink failure in IsAwake must return (false, nlErr) rather than falling back to /proc/net/arp
	// (because /proc/net/arp exposes NUD_STALE entries as 0x2 ATF_COM and would misclassify sleeping hosts).
	nlBoom := errors.New("netlink unavailable")
	chkNetlinkErr := SystemChecker{
		rawQuery: func(context.Context, netutil.InterfaceInfo, []netip.Addr, time.Duration, bool) (map[netip.Addr]string, error) {
			return nil, unix.EPERM
		},
		netlinkLookup: func(int, netip.Addr) (uint16, string, bool, error) {
			return 0, "", false, nlBoom
		},
		procLookup: func(string, netip.Addr) string {
			return "aa:bb:cc:dd:ee:01"
		},
	}
	if awake, err := chkNetlinkErr.IsAwake(context.Background(), lanIface, targetIP); awake || !errors.Is(err, nlBoom) {
		t.Fatalf("expected IsAwake on netlink failure to return (false, nlBoom) without /proc/net/arp false positive, got awake=%v err=%v", awake, err)
	}
	// LookupMAC still falls back to /proc/net/arp passively for cached MAC discovery
	if mac, reason := chkNetlinkErr.LookupMAC(context.Background(), lanIface, targetIP); mac != "aa:bb:cc:dd:ee:01" || reason != "" {
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

func TestScanSubnetMultiSubnetLinux(t *testing.T) {
	lanIface := netutil.InterfaceInfo{
		Name:         "eth0",
		Index:        2,
		HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		Prefixes: []netip.Prefix{
			netip.MustParsePrefix("192.168.0.10/24"),
			netip.MustParsePrefix("192.168.10.10/24"),
		},
	}

	var gotTargetCount int
	chk := SystemChecker{
		rawQuery: func(_ context.Context, _ netutil.InterfaceInfo, targets []netip.Addr, _ time.Duration, _ bool) (map[netip.Addr]string, error) {
			gotTargetCount = len(targets)
			return map[netip.Addr]string{
				netip.MustParseAddr("192.168.10.22"): "aa:bb:cc:dd:ee:02",
				netip.MustParseAddr("192.168.0.21"):  "aa:bb:cc:dd:ee:01",
			}, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	hosts, err := chk.ScanSubnet(ctx, lanIface)
	if err != nil {
		t.Fatalf("ScanSubnet multi-subnet failed: %v", err)
	}
	if gotTargetCount != 508 {
		t.Fatalf("expected 508 scan targets across two /24 subnets, got %d", gotTargetCount)
	}
	if len(hosts) != 2 || hosts[0].IP != netip.MustParseAddr("192.168.0.21") || hosts[1].IP != netip.MustParseAddr("192.168.10.22") {
		t.Fatalf("unexpected sorted scan results: %+v", hosts)
	}
}

func TestProbeAwakeNonRootUDPTriggerAndConfirmedStatesOnly(t *testing.T) {
	lanIface := netutil.InterfaceInfo{
		Name:         "eth0",
		Index:        2,
		HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		Prefixes: []netip.Prefix{
			netip.MustParsePrefix("192.168.0.10/24"),
			netip.MustParsePrefix("192.168.10.10/24"),
		},
	}
	targetIP := netip.MustParseAddr("192.168.10.22")

	// 1. Root path (rawQuery succeeds): uses raw ARP directly and never calls udpTrigger
	chkRoot := SystemChecker{
		rawQuery: func(_ context.Context, _ netutil.InterfaceInfo, _ []netip.Addr, _ time.Duration, _ bool) (map[netip.Addr]string, error) {
			return map[netip.Addr]string{targetIP: "aa:bb:cc:dd:ee:22"}, nil
		},
		udpTrigger: func(netip.Addr, netip.Addr) error {
			t.Fatal("udpTrigger must not be called when rawQuery succeeds")
			return nil
		},
	}
	if awake, err := chkRoot.ProbeAwake(context.Background(), lanIface, targetIP); err != nil || !awake {
		t.Fatalf("expected root ProbeAwake true, got awake=%v err=%v", awake, err)
	}

	// 2. Non-root when already NUD_REACHABLE or NUD_PERMANENT: returns true immediately without udpTrigger
	for _, st := range []uint16{unix.NUD_REACHABLE, unix.NUD_PERMANENT} {
		chkAlready := SystemChecker{
			rawQuery: func(context.Context, netutil.InterfaceInfo, []netip.Addr, time.Duration, bool) (map[netip.Addr]string, error) {
				return nil, unix.EPERM
			},
			netlinkLookup: func(int, netip.Addr) (uint16, string, bool, error) {
				return st, "aa:bb:cc:dd:ee:22", true, nil
			},
			udpTrigger: func(netip.Addr, netip.Addr) error {
				t.Fatalf("udpTrigger must not be called when already in confirmed state 0x%x", st)
				return nil
			},
		}
		if awake, err := chkAlready.ProbeAwake(context.Background(), lanIface, targetIP); err != nil || !awake {
			t.Fatalf("expected confirmed state 0x%x to return true immediately, got awake=%v err=%v", st, awake, err)
		}
	}

	// 3. Non-root sleeping host with NUD_STALE: UDP send transitions kernel NUD_STALE -> NUD_DELAY -> NUD_PROBE -> NUD_FAILED.
	// ProbeAwake MUST NOT misclassify NUD_DELAY or NUD_PROBE as awake!
	statesSleeping := []uint16{
		unix.NUD_STALE,
		unix.NUD_DELAY,
		unix.NUD_PROBE,
		unix.NUD_FAILED,
	}
	idxSleep := 0
	var gotSrc, gotDst netip.Addr
	udpCalls := 0
	chkSleep := SystemChecker{
		rawQuery: func(context.Context, netutil.InterfaceInfo, []netip.Addr, time.Duration, bool) (map[netip.Addr]string, error) {
			return nil, unix.EPERM
		},
		netlinkLookup: func(int, netip.Addr) (uint16, string, bool, error) {
			st := statesSleeping[min(idxSleep, len(statesSleeping)-1)]
			idxSleep++
			return st, "aa:bb:cc:dd:ee:22", true, nil
		},
		udpTrigger: func(srcIP, dstIP netip.Addr) error {
			udpCalls++
			gotSrc = srcIP
			gotDst = dstIP
			return nil
		},
		probeWait: 30 * time.Millisecond,
		probeStep: 8 * time.Millisecond,
	}
	awake, err := chkSleep.ProbeAwake(context.Background(), lanIface, targetIP)
	if err != nil || awake {
		t.Fatalf("expected sleeping host transitioning STALE->DELAY->PROBE->FAILED to return (false, nil), got awake=%v err=%v", awake, err)
	}
	if udpCalls != 1 || gotSrc != netip.MustParseAddr("192.168.10.10") || gotDst != targetIP {
		t.Fatalf("expected 1 UDP trigger from 192.168.10.10 -> %v, got calls=%d src=%v dst=%v", targetIP, udpCalls, gotSrc, gotDst)
	}

	// 4. Non-root waking host: transitions NUD_STALE -> NUD_DELAY -> NUD_REACHABLE -> returns (true, nil)!
	statesAwake := []uint16{
		unix.NUD_STALE,
		unix.NUD_DELAY,
		unix.NUD_REACHABLE,
	}
	idxAwake := 0
	chkWoke := SystemChecker{
		rawQuery: func(context.Context, netutil.InterfaceInfo, []netip.Addr, time.Duration, bool) (map[netip.Addr]string, error) {
			return nil, unix.EACCES
		},
		netlinkLookup: func(int, netip.Addr) (uint16, string, bool, error) {
			st := statesAwake[min(idxAwake, len(statesAwake)-1)]
			idxAwake++
			return st, "aa:bb:cc:dd:ee:22", true, nil
		},
		udpTrigger: func(netip.Addr, netip.Addr) error {
			return nil
		},
		probeWait: 100 * time.Millisecond,
		probeStep: 8 * time.Millisecond,
	}
	if awake, err := chkWoke.ProbeAwake(context.Background(), lanIface, targetIP); err != nil || !awake {
		t.Fatalf("expected ProbeAwake to return true once NUD_REACHABLE reached, got awake=%v err=%v", awake, err)
	}
}
