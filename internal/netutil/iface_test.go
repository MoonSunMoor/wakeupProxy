package netutil

import (
	"net/netip"
	"testing"
)

func TestBroadcastAddr(t *testing.T) {
	tests := []struct {
		prefix string
		want   string
	}{
		{"192.168.0.10/24", "192.168.0.255"},
		{"192.168.1.45/22", "192.168.3.255"},
		{"10.66.0.2/32", "10.66.0.2"},
		{"172.16.5.1/16", "172.16.255.255"},
	}
	for _, tc := range tests {
		p := netip.MustParsePrefix(tc.prefix)
		got, err := BroadcastAddr(p)
		if err != nil {
			t.Fatalf("BroadcastAddr(%s) error: %v", tc.prefix, err)
		}
		if got.String() != tc.want {
			t.Errorf("BroadcastAddr(%s) = %s, want %s", tc.prefix, got, tc.want)
		}
	}
}

func TestSubnetHosts(t *testing.T) {
	p := netip.MustParsePrefix("192.168.0.10/30")
	hosts := SubnetHosts(p)
	if len(hosts) != 2 || hosts[0].String() != "192.168.0.9" || hosts[1].String() != "192.168.0.10" {
		t.Fatalf("unexpected /30 hosts: %v", hosts)
	}

	p24 := netip.MustParsePrefix("192.168.10.5/24")
	hosts24 := SubnetHosts(p24)
	if len(hosts24) != 254 || hosts24[0].String() != "192.168.10.1" || hosts24[253].String() != "192.168.10.254" {
		t.Fatalf("unexpected /24 hosts len=%d first=%v last=%v", len(hosts24), hosts24[0], hosts24[len(hosts24)-1])
	}
}

func TestParseIPv4OrCIDRAndNormalizeMAC(t *testing.T) {
	p, err := ParseIPv4OrCIDR("10.66.0.2")
	if err != nil || p.String() != "10.66.0.2/32" {
		t.Fatalf("bare IPv4 parse failed: %v, %v", p, err)
	}
	p2, err := ParseIPv4OrCIDR("10.66.0.5/24")
	if err != nil || p2.String() != "10.66.0.0/24" {
		t.Fatalf("CIDR parse failed: %v, %v", p2, err)
	}
	if _, err := ParseIPv4OrCIDR("2001:db8::1/64"); err == nil {
		t.Fatal("expected IPv6 CIDR to be rejected")
	}

	mac, hw, err := NormalizeMAC("AA-BB-CC-DD-EE-01")
	if err != nil || mac != "aa:bb:cc:dd:ee:01" || len(hw) != 6 {
		t.Fatalf("NormalizeMAC failed: %q %v %v", mac, hw, err)
	}
	if _, _, err := NormalizeMAC("00:00:00:00:00:00"); err == nil {
		t.Fatal("expected all-zero MAC to be rejected")
	}
	if _, _, err := NormalizeMAC("ff:ff:ff:ff:ff:ff"); err == nil {
		t.Fatal("expected broadcast MAC to be rejected")
	}
	if _, _, err := NormalizeMAC("01:02:03:04:05:06:07:08"); err == nil {
		t.Fatal("expected 8-byte MAC to be rejected")
	}
}

func TestMatchingAndResolvePrefixMultiSubnet(t *testing.T) {
	info := InterfaceInfo{
		Name:  "eth0",
		Index: 2,
		Prefixes: []netip.Prefix{
			netip.MustParsePrefix("192.168.0.10/24"),
			netip.MustParsePrefix("192.168.10.10/24"),
			netip.MustParsePrefix("10.20.0.5/16"),
			netip.MustParsePrefix("10.20.30.7/24"),
		},
	}

	// Disjoint secondary subnet selects second prefix
	got, ok := info.MatchingPrefix(netip.MustParseAddr("192.168.10.55"))
	if !ok || got.String() != "192.168.10.10/24" {
		t.Fatalf("expected 192.168.10.10/24, got %v (ok=%v)", got, ok)
	}

	// Overlapping prefixes select longest prefix (/24 over /16)
	gotLongest, ok := info.MatchingPrefix(netip.MustParseAddr("10.20.30.99"))
	if !ok || gotLongest.String() != "10.20.30.7/24" {
		t.Fatalf("expected longest prefix 10.20.30.7/24, got %v (ok=%v)", gotLongest, ok)
	}
	gotBroader, ok := info.MatchingPrefix(netip.MustParseAddr("10.20.99.99"))
	if !ok || gotBroader.String() != "10.20.0.5/16" {
		t.Fatalf("expected broader prefix 10.20.0.5/16, got %v (ok=%v)", gotBroader, ok)
	}

	// Unmatched IP returns false from MatchingPrefix and falls back to PrimaryPrefix in ResolvePrefix
	if _, ok := info.MatchingPrefix(netip.MustParseAddr("172.16.0.5")); ok {
		t.Fatal("expected MatchingPrefix false for unrelated subnet")
	}
	fallback, ok := info.ResolvePrefix(netip.MustParseAddr("172.16.0.5"))
	if !ok || fallback.String() != "192.168.0.10/24" {
		t.Fatalf("expected ResolvePrefix fallback to primary 192.168.0.10/24, got %v (ok=%v)", fallback, ok)
	}
}
