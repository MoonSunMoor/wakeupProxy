//go:build linux

package arp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"syscall"
	"time"
	"unsafe"

	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
	"golang.org/x/sys/unix"
)

const (
	activeNeighborStates = unix.NUD_REACHABLE | unix.NUD_DELAY | unix.NUD_PROBE | unix.NUD_PERMANENT
	arpFlagComplete      = 0x2 // ATF_COM in /proc/net/arp
)

type rawARPQueryFunc func(ctx context.Context, lanIface netutil.InterfaceInfo, targets []netip.Addr, waitAfterSend time.Duration, stopOnFirst bool) (map[netip.Addr]string, error)
type netlinkLookupFunc func(ifIndex int, targetIP netip.Addr) (state uint16, mac string, found bool, err error)
type procARPLookupFunc func(ifaceName string, targetIP netip.Addr) string

// SystemChecker implements Checker on Linux using AF_PACKET raw ARP (when permitted)
// and passive Netlink RTM_GETNEIGH / /proc/net/arp neighbor inspection otherwise.
type SystemChecker struct {
	rawQuery      rawARPQueryFunc
	netlinkLookup netlinkLookupFunc
	procLookup    procARPLookupFunc
}

func NewSystemChecker() Checker {
	return SystemChecker{}
}

func (c SystemChecker) doRawQuery(ctx context.Context, lanIface netutil.InterfaceInfo, targets []netip.Addr, waitAfterSend time.Duration, stopOnFirst bool) (map[netip.Addr]string, error) {
	if c.rawQuery != nil {
		return c.rawQuery(ctx, lanIface, targets, waitAfterSend, stopOnFirst)
	}
	return rawARPQuery(ctx, lanIface, targets, waitAfterSend, stopOnFirst)
}

func (c SystemChecker) doNetlinkLookup(ifIndex int, targetIP netip.Addr) (uint16, string, bool, error) {
	if c.netlinkLookup != nil {
		return c.netlinkLookup(ifIndex, targetIP)
	}
	return lookupNeighborNetlink(ifIndex, targetIP)
}

func (c SystemChecker) doProcLookup(ifaceName string, targetIP netip.Addr) string {
	if c.procLookup != nil {
		return c.procLookup(ifaceName, targetIP)
	}
	return lookupProcARPMAC(ifaceName, targetIP)
}

func isNeighborActive(state uint16) bool {
	return state&activeNeighborStates != 0
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func (c SystemChecker) IsAwake(ctx context.Context, lanIface netutil.InterfaceInfo, ip netip.Addr) (bool, error) {
	if !ip.Is4() {
		return false, errors.New("IPv4 주소만 지원합니다")
	}
	if !lanIface.ContainsIPv4(ip) {
		return false, nil
	}

	// Prefer direct raw ARP request/reply when root / CAP_NET_RAW is available:
	// avoids false positives from STALE neighbor cache entries without touching TCP ports.
	found, err := c.doRawQuery(ctx, lanIface, []netip.Addr{ip}, 350*time.Millisecond, true)
	if err == nil {
		_, ok := found[ip]
		return ok, nil
	}

	// Unprivileged path (EPERM/EACCES) or raw socket unavailable:
	// passively read kernel neighbor table (Netlink RTM_GETNEIGH, falling back to /proc/net/arp).
	st, _, ok, nlErr := c.doNetlinkLookup(lanIface.Index, ip)
	if nlErr == nil {
		return ok && isNeighborActive(st), nil
	}
	return c.doProcLookup(lanIface.Name, ip) != "", nil
}

func (c SystemChecker) LookupMAC(ctx context.Context, lanIface netutil.InterfaceInfo, ip netip.Addr) (string, string) {
	if !ip.IsValid() || !ip.Is4() {
		return "", "유효한 IPv4 주소를 먼저 입력해 주세요"
	}
	if len(lanIface.Prefixes) > 0 && !lanIface.ContainsIPv4(ip) {
		return "", fmt.Sprintf("LAN 인터페이스(%s) 대역 밖의 주소는 ARP 기록을 조회할 수 없습니다", lanIface.Name)
	}

	// 1. Passively check existing kernel neighbor table (Netlink RTM_GETNEIGH)
	if _, mac, ok, err := c.doNetlinkLookup(lanIface.Index, ip); err == nil && ok && mac != "" {
		return mac, ""
	}

	// 2. Fallback passive check via /proc/net/arp
	if mac := c.doProcLookup(lanIface.Name, ip); mac != "" {
		return mac, ""
	}

	// 3. When root / CAP_NET_RAW is available, resolve via raw ARP; when non-root,
	// rawARPQuery returns EPERM/EACCES immediately without sending any active packet.
	if found, err := c.doRawQuery(ctx, lanIface, []netip.Addr{ip}, 250*time.Millisecond, true); err == nil {
		if mac, ok := found[ip]; ok && mac != "" {
			return mac, ""
		}
	}

	return "", "시스템 ARP 기록에서 MAC을 찾지 못했습니다 (기기가 잠들어 있거나 아직 통신 기록이 없음)"
}

func (c SystemChecker) ScanSubnet(ctx context.Context, lanIface netutil.InterfaceInfo) ([]DiscoveredHost, error) {
	if os.Geteuid() != 0 {
		return nil, ErrRootRequired
	}
	prefix, ok := lanIface.PrimaryPrefix()
	if !ok {
		return nil, fmt.Errorf("LAN 인터페이스(%s)에 IPv4 서브넷이 없습니다", lanIface.Name)
	}
	if prefix.Bits() < MaxScanPrefixBits {
		return nil, ErrSubnetTooLarge
	}

	targets := netutil.SubnetHosts(prefix)
	found, err := c.doRawQuery(ctx, lanIface, targets, 750*time.Millisecond, false)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, ErrRootRequired
		}
		return nil, fmt.Errorf("ARP 스캔 실패: %w", err)
	}

	hosts := make([]DiscoveredHost, 0, len(found))
	for ip, mac := range found {
		hosts = append(hosts, DiscoveredHost{
			IP:  ip,
			MAC: mac,
		})
	}
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].IP.Compare(hosts[j].IP) < 0
	})

	resolveReverseDNS(ctx, hosts)
	return hosts, nil
}

func rawARPQuery(
	ctx context.Context,
	lanIface netutil.InterfaceInfo,
	targets []netip.Addr,
	waitAfterSend time.Duration,
	stopOnFirst bool,
) (map[netip.Addr]string, error) {
	if _, ok := lanIface.PrimaryPrefix(); !ok {
		return nil, fmt.Errorf("인터페이스 %s에 IPv4 주소가 없습니다", lanIface.Name)
	}
	if len(lanIface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("인터페이스 %s에 유효한 이더넷 MAC 주소가 없습니다", lanIface.Name)
	}
	selfIPs := make(map[netip.Addr]bool, len(lanIface.Prefixes))
	for _, addr := range lanIface.IPv4Addrs() {
		selfIPs[addr] = true
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(htons(etherTypeARP)))
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	sll := &unix.SockaddrLinklayer{
		Protocol: htons(etherTypeARP),
		Ifindex:  lanIface.Index,
	}
	if err := unix.Bind(fd, sll); err != nil {
		return nil, err
	}

	wanted := make(map[netip.Addr]bool, len(targets))
	for _, ip := range targets {
		if selfIPs[ip] {
			continue
		}
		wanted[ip] = true
	}
	result := make(map[netip.Addr]string)
	if len(wanted) == 0 {
		return result, nil
	}

	dstLL := &unix.SockaddrLinklayer{
		Protocol: htons(etherTypeARP),
		Ifindex:  lanIface.Index,
		Halen:    6,
		Addr:     [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}

	readReplies := func() bool {
		var buf [128]byte
		for {
			n, _, rErr := unix.Recvfrom(fd, buf[:], 0)
			if rErr != nil {
				break
			}
			ip, mac, ok := ParseEthernetARPReply(buf[:n])
			if ok && wanted[ip] {
				result[ip] = mac
				if stopOnFirst && len(result) == len(wanted) {
					return true
				}
			}
		}
		return false
	}

	// Send ARP requests in gentle batches while draining incoming replies.
	for i, targetIP := range targets {
		if selfIPs[targetIP] {
			continue
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		srcIP, ok := SelectSourceIP(lanIface, targetIP)
		if !ok {
			continue
		}
		frame, fErr := BuildEthernetARPRequest(lanIface.HardwareAddr, srcIP, targetIP)
		if fErr != nil {
			continue
		}
		_ = unix.Sendto(fd, frame[:], 0, dstLL)
		if (i+1)%64 == 0 {
			if readReplies() {
				return result, nil
			}
			time.Sleep(4 * time.Millisecond)
		}
	}

	deadline := time.Now().Add(waitAfterSend)
	for time.Now().Before(deadline) {
		if readReplies() {
			return result, nil
		}
		rem := time.Until(deadline)
		timeoutMS := int(rem.Milliseconds())
		if timeoutMS <= 0 {
			break
		}
		if timeoutMS > 50 {
			timeoutMS = 50
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		_, _ = unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, timeoutMS)
	}
	readReplies()
	return result, nil
}

func lookupNeighborNetlink(ifIndex int, targetIP netip.Addr) (state uint16, mac string, found bool, err error) {
	rib, err := syscall.NetlinkRIB(unix.RTM_GETNEIGH, unix.AF_INET)
	if err != nil {
		return 0, "", false, err
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return 0, "", false, err
	}
	const ndmSize = unix.SizeofNdMsg
	for _, m := range msgs {
		if m.Header.Type != unix.RTM_NEWNEIGH || len(m.Data) < ndmSize {
			continue
		}
		ndm := (*unix.NdMsg)(unsafe.Pointer(&m.Data[0]))
		if ifIndex > 0 && int(ndm.Ifindex) != ifIndex {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			continue
		}
		var dstIP netip.Addr
		var llAddr string
		for _, a := range attrs {
			switch a.Attr.Type {
			case unix.NDA_DST:
				if len(a.Value) == 4 {
					dstIP = netip.AddrFrom4([4]byte(a.Value))
				}
			case unix.NDA_LLADDR:
				if norm, _, err := netutil.NormalizeMAC(net.HardwareAddr(a.Value).String()); err == nil {
					llAddr = norm
				}
			}
		}
		if dstIP == targetIP {
			return ndm.State, llAddr, true, nil
		}
	}
	return 0, "", false, nil
}

func lookupProcARPMAC(ifaceName string, targetIP netip.Addr) string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer f.Close()
	for _, e := range ParseProcARP(f) {
		if e.IP == targetIP && (ifaceName == "" || e.Device == ifaceName) && e.MAC != "" && e.Flags&arpFlagComplete != 0 {
			return e.MAC
		}
	}
	return ""
}
