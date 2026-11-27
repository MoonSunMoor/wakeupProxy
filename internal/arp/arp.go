package arp

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
)

const (
	MaxScanPrefixBits = 22   // /22보다 큰 서브넷(prefix < 22)은 스캔하지 않음
	MaxScanHosts      = 1022 // /22 기준 최대 스캔 호스트 수 (2^(32-22) - 2)

	etherTypeARP      = 0x0806
	etherTypeIP4      = 0x0800
	arpHW        Type = 1 // Ethernet
	arpOpRequest      = 1
	arpOpReply        = 2
	arpFrameLen       = 42 // 14-byte Ethernet header + 28-byte IPv4 ARP payload
)

type Type uint16

var (
	ErrSubnetTooLarge = errors.New("서브넷이 /22보다 커서 스캔하지 않습니다. IP를 직접 입력해 주세요")
	ErrRootRequired   = errors.New("LAN 검색은 root 권한(sudo)이 필요합니다")
)

// DiscoveredHost represents an active LAN device discovered via ARP scan.
type DiscoveredHost struct {
	IP       netip.Addr
	MAC      string
	Hostname string
}

// Checker provides ARP reachability checks, kernel ARP table MAC lookup, and LAN subnet scanning.
type Checker interface {
	IsAwake(ctx context.Context, lanIface netutil.InterfaceInfo, ip netip.Addr) (bool, error)
	ProbeAwake(ctx context.Context, lanIface netutil.InterfaceInfo, ip netip.Addr) (bool, error)
	LookupMAC(ctx context.Context, lanIface netutil.InterfaceInfo, ip netip.Addr) (mac string, reason string)
	ScanSubnet(ctx context.Context, lanIface netutil.InterfaceInfo) ([]DiscoveredHost, error)
}

// SelectSourceIP chooses the local IPv4 address on lanIface whose subnet contains targetIP
// (longest prefix match), falling back to lanIface.PrimaryPrefix() when none matches.
func SelectSourceIP(lanIface netutil.InterfaceInfo, targetIP netip.Addr) (netip.Addr, bool) {
	if pfx, ok := lanIface.ResolvePrefix(targetIP); ok {
		return pfx.Addr(), true
	}
	return netip.Addr{}, false
}

// CollectScanTargets validates all IPv4 prefixes on lanIface and builds the deduplicated
// host IPv4 address list for LAN ARP scanning. It returns ErrSubnetTooLarge if any prefix
// is larger than /22 (Bits < 22) or if deduplicated total hosts exceed MaxScanHosts (1,022).
func CollectScanTargets(lanIface netutil.InterfaceInfo) ([]netip.Addr, error) {
	var validPrefixes []netip.Prefix
	for _, p := range lanIface.Prefixes {
		if !p.IsValid() || !p.Addr().Is4() {
			continue
		}
		if p.Bits() < MaxScanPrefixBits {
			return nil, ErrSubnetTooLarge
		}
		validPrefixes = append(validPrefixes, p)
	}
	if len(validPrefixes) == 0 {
		return nil, fmt.Errorf("LAN 인터페이스(%s)에 IPv4 서브넷이 없습니다", lanIface.Name)
	}

	seen := make(map[netip.Addr]bool)
	var targets []netip.Addr
	for _, p := range validPrefixes {
		for _, ip := range netutil.SubnetHosts(p) {
			if seen[ip] {
				continue
			}
			seen[ip] = true
			if len(targets) >= MaxScanHosts {
				return nil, ErrSubnetTooLarge
			}
			targets = append(targets, ip)
		}
	}
	return targets, nil
}

// BuildEthernetARPRequest constructs a 42-byte Ethernet II + IPv4 ARP Request frame.
func BuildEthernetARPRequest(srcMAC net.HardwareAddr, srcIP, targetIP netip.Addr) ([arpFrameLen]byte, error) {
	var frame [arpFrameLen]byte
	if len(srcMAC) != 6 {
		return frame, errors.New("출발지 MAC은 6바이트여야 합니다")
	}
	if !srcIP.Is4() || !targetIP.Is4() {
		return frame, errors.New("ARP 요청은 IPv4만 지원합니다")
	}

	// Ethernet header: broadcast destination, sender MAC, EtherType 0x0806
	for i := 0; i < 6; i++ {
		frame[i] = 0xff
	}
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeARP)

	// ARP payload
	binary.BigEndian.PutUint16(frame[14:16], uint16(arpHW))
	binary.BigEndian.PutUint16(frame[16:18], etherTypeIP4)
	frame[18] = 6
	frame[19] = 4
	binary.BigEndian.PutUint16(frame[20:22], arpOpRequest)
	copy(frame[22:28], srcMAC)
	s4 := srcIP.As4()
	copy(frame[28:32], s4[:])
	// Target hardware address [32:38] remains 00:00:00:00:00:00
	t4 := targetIP.As4()
	copy(frame[38:42], t4[:])

	return frame, nil
}

// ParseEthernetARPReply parses an Ethernet frame and extracts (senderIP, normalizedMAC, true)
// if it is a valid IPv4 ARP Reply.
func ParseEthernetARPReply(frame []byte) (netip.Addr, string, bool) {
	if len(frame) < arpFrameLen {
		return netip.Addr{}, "", false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != etherTypeARP {
		return netip.Addr{}, "", false
	}
	if binary.BigEndian.Uint16(frame[14:16]) != uint16(arpHW) ||
		binary.BigEndian.Uint16(frame[16:18]) != etherTypeIP4 ||
		frame[18] != 6 || frame[19] != 4 {
		return netip.Addr{}, "", false
	}
	op := binary.BigEndian.Uint16(frame[20:22])
	if op != arpOpReply {
		return netip.Addr{}, "", false
	}
	macStr, _, err := netutil.NormalizeMAC(net.HardwareAddr(frame[22:28]).String())
	if err != nil {
		return netip.Addr{}, "", false
	}
	var ip4 [4]byte
	copy(ip4[:], frame[28:32])
	return netip.AddrFrom4(ip4), macStr, true
}

// ProcARPEntry represents a parsed row from /proc/net/arp.
type ProcARPEntry struct {
	IP     netip.Addr
	Flags  uint64
	MAC    string
	Device string
}

// ParseProcARP parses Linux /proc/net/arp content.
func ParseProcARP(r io.Reader) []ProcARPEntry {
	var entries []ProcARPEntry
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			continue // skip header
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil || !ip.Is4() {
			continue
		}
		var flags uint64
		_, _ = fmt.Sscanf(fields[2], "0x%x", &flags)
		mac, _, macErr := netutil.NormalizeMAC(fields[3])
		if macErr != nil {
			mac = ""
		}
		entries = append(entries, ProcARPEntry{
			IP:     ip,
			Flags:  flags,
			MAC:    mac,
			Device: fields[5],
		})
	}
	return entries
}

// resolveReverseDNS performs bounded-concurrency reverse DNS lookups with a short timeout.
func resolveReverseDNS(ctx context.Context, hosts []DiscoveredHost) {
	if len(hosts) == 0 {
		return
	}
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	resolver := net.DefaultResolver

	for i := range hosts {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			rCtx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
			defer cancel()
			names, err := resolver.LookupAddr(rCtx, hosts[i].IP.String())
			if err == nil && len(names) > 0 {
				hosts[i].Hostname = strings.TrimSuffix(names[0], ".")
			}
		}()
	}
	wg.Wait()
}
