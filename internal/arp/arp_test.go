package arp

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
)

func TestBuildAndParseARPFrames(t *testing.T) {
	srcMAC, _ := net.ParseMAC("02:11:22:33:44:55")
	srcIP := netip.MustParseAddr("192.168.0.10")
	dstIP := netip.MustParseAddr("192.168.0.21")

	req, err := BuildEthernetARPRequest(srcMAC, srcIP, dstIP)
	if err != nil {
		t.Fatalf("BuildEthernetARPRequest error: %v", err)
	}
	// Request frame (opcode=1) must not be parsed as a reply.
	if _, _, ok := ParseEthernetARPReply(req[:]); ok {
		t.Fatal("expected ARP request not to parse as ARP reply")
	}

	// Construct a matching ARP Reply frame from 192.168.0.21 (aa:bb:cc:dd:ee:01)
	var reply [arpFrameLen]byte
	copy(reply[:], req[:])
	targetMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	copy(reply[0:6], srcMAC)
	copy(reply[6:12], targetMAC)
	binary.BigEndian.PutUint16(reply[20:22], arpOpReply)
	copy(reply[22:28], targetMAC)
	d4 := dstIP.As4()
	copy(reply[28:32], d4[:])
	copy(reply[32:38], srcMAC)
	s4 := srcIP.As4()
	copy(reply[38:42], s4[:])

	gotIP, gotMAC, ok := ParseEthernetARPReply(reply[:])
	if !ok {
		t.Fatal("expected valid ARP reply to parse")
	}
	if gotIP != dstIP || gotMAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("unexpected parsed reply: ip=%v mac=%q", gotIP, gotMAC)
	}
}

func TestParseProcARP(t *testing.T) {
	sample := `IP address       HW type     Flags       HW address            Mask     Device
192.168.0.21     0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
192.168.0.99     0x1         0x0         00:00:00:00:00:00     *        eth0
`
	entries := ParseProcARP(strings.NewReader(sample))
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].IP.String() != "192.168.0.21" || entries[0].MAC != "aa:bb:cc:dd:ee:01" || entries[0].Flags != 2 {
		t.Fatalf("unexpected first entry: %+v", entries[0])
	}
	if entries[1].MAC != "" || entries[1].Flags != 0 {
		t.Fatalf("expected incomplete entry to have empty MAC and flags=0: %+v", entries[1])
	}
}

func TestSelectSourceIPMultiSubnet(t *testing.T) {
	lanIface := netutil.InterfaceInfo{
		Name:  "eth0",
		Index: 2,
		Prefixes: []netip.Prefix{
			netip.MustParsePrefix("192.168.0.10/24"),
			netip.MustParsePrefix("192.168.10.10/24"),
		},
	}

	ip1, ok := SelectSourceIP(lanIface, netip.MustParseAddr("192.168.0.21"))
	if !ok || ip1 != netip.MustParseAddr("192.168.0.10") {
		t.Fatalf("expected 192.168.0.10 for first subnet target, got %v (ok=%v)", ip1, ok)
	}
	ip2, ok := SelectSourceIP(lanIface, netip.MustParseAddr("192.168.10.22"))
	if !ok || ip2 != netip.MustParseAddr("192.168.10.10") {
		t.Fatalf("expected 192.168.10.10 for second subnet target, got %v (ok=%v)", ip2, ok)
	}
	fallback, ok := SelectSourceIP(lanIface, netip.MustParseAddr("10.0.0.5"))
	if !ok || fallback != netip.MustParseAddr("192.168.0.10") {
		t.Fatalf("expected fallback to primary 192.168.0.10, got %v (ok=%v)", fallback, ok)
	}
}

func TestCollectScanTargetsMultiSubnetAndLimits(t *testing.T) {
	// 1. No IPv4 prefixes -> error (not ErrSubnetTooLarge)
	if _, err := CollectScanTargets(netutil.InterfaceInfo{Name: "eth0"}); err == nil || errors.Is(err, ErrSubnetTooLarge) {
		t.Fatalf("expected missing-subnet error for empty prefixes, got %v", err)
	}

	// 2. Two disjoint /24 subnets -> 508 hosts covering both subnets
	two24 := netutil.InterfaceInfo{
		Name: "eth0",
		Prefixes: []netip.Prefix{
			netip.MustParsePrefix("192.168.0.10/24"),
			netip.MustParsePrefix("192.168.10.10/24"),
		},
	}
	targets, err := CollectScanTargets(two24)
	if err != nil || len(targets) != 508 {
		t.Fatalf("expected 508 targets across two /24 subnets, got len=%d err=%v", len(targets), err)
	}
	if targets[0] != netip.MustParseAddr("192.168.0.1") || targets[len(targets)-1] != netip.MustParseAddr("192.168.10.254") {
		t.Fatalf("unexpected first/last target: %v .. %v", targets[0], targets[len(targets)-1])
	}

	// 3. Overlapping /22 and /24 deduplicates cleanly to 1,022 hosts (within MaxScanHosts)
	overlap := netutil.InterfaceInfo{
		Name: "eth0",
		Prefixes: []netip.Prefix{
			netip.MustParsePrefix("192.168.0.10/22"),
			netip.MustParsePrefix("192.168.1.10/24"),
		},
	}
	deduped, err := CollectScanTargets(overlap)
	if err != nil || len(deduped) != MaxScanHosts {
		t.Fatalf("expected %d deduplicated targets, got len=%d err=%v", MaxScanHosts, len(deduped), err)
	}

	// 4. Secondary prefix larger than /22 (e.g. /21) -> ErrSubnetTooLarge
	secondTooLarge := netutil.InterfaceInfo{
		Name: "eth0",
		Prefixes: []netip.Prefix{
			netip.MustParsePrefix("192.168.0.10/24"),
			netip.MustParsePrefix("10.0.0.1/21"),
		},
	}
	if _, err := CollectScanTargets(secondTooLarge); !errors.Is(err, ErrSubnetTooLarge) {
		t.Fatalf("expected ErrSubnetTooLarge when secondary prefix is /21, got %v", err)
	}

	// 5. Five disjoint /24 prefixes (5 * 254 = 1,270 > 1,022) -> ErrSubnetTooLarge
	five24 := netutil.InterfaceInfo{
		Name: "eth0",
		Prefixes: []netip.Prefix{
			netip.MustParsePrefix("192.168.1.1/24"),
			netip.MustParsePrefix("192.168.2.1/24"),
			netip.MustParsePrefix("192.168.3.1/24"),
			netip.MustParsePrefix("192.168.4.1/24"),
			netip.MustParsePrefix("192.168.5.1/24"),
		},
	}
	if _, err := CollectScanTargets(five24); !errors.Is(err, ErrSubnetTooLarge) {
		t.Fatalf("expected ErrSubnetTooLarge when combined /24 host count exceeds 1022, got %v", err)
	}
}
