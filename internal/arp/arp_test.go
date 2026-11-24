package arp

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
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
