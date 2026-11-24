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
