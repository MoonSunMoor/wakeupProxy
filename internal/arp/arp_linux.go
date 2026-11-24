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

// SystemChecker implements Checker on Linux using AF_PACKET raw ARP (when permitted)
// and Netlink RTM_GETNEIGH / /proc/net/arp neighbor inspection.
type SystemChecker struct{}

func NewSystemChecker() Checker {
	return SystemChecker{}
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func (SystemChecker) IsAwake(ctx context.Context, lanIface netutil.InterfaceInfo, ip netip.Addr) (bool, error) {
	if !ip.Is4() {
		return false, errors.New("IPv4 주소만 지원합니다")
	}
	if !lanIface.ContainsIPv4(ip) {
		return false, nil
	}

	// Prefer direct raw ARP request/reply when root / CAP_NET_RAW is available:
	// avoids false positives from STALE neighbor cache entries without touching TCP ports.
	found, err := rawARPQuery(ctx, lanIface, []netip.Addr{ip}, 350*time.Millisecond, true)
	if err == nil {
		_, ok := found[ip]
		return ok, nil
	}
	if !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EACCES) {
		// Fall through to kernel neighbor table check if raw socket failed for another reason.
	}

	// Unprivileged path (`wolproxy wake --wait` or read-only TUI):
	// Check if already NUD_REACHABLE, otherwise trigger kernel ARP resolution via UDP discard probe.
	if st, _, ok := lookupNeighborNetlink(lanIface.Index, ip); ok {
		if st&(unix.NUD_REACHABLE|unix.NUD_PERMANENT) != 0 {
			return true, nil
		}
	}

	triggerKernelARP(ip)

	deadline := time.Now().Add(450 * time.Millisecond)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(90 * time.Millisecond):
		}
		if st, _, ok := lookupNeighborNetlink(lanIface.Index, ip); ok {
			if st&(unix.NUD_REACHABLE|unix.NUD_PERMANENT) != 0 {
				return true, nil
			}
			if st&unix.NUD_FAILED != 0 {
				return false, nil
			}
		}
	}
	return false, nil
}

func (SystemChecker) LookupMAC(ctx context.Context, lanIface netutil.InterfaceInfo, ip netip.Addr) (string, string) {
	if !ip.IsValid() || !ip.Is4() {
		return "", "유효한 IPv4 주소를 먼저 입력해 주세요"
	}
	if len(lanIface.Prefixes) > 0 && !lanIface.ContainsIPv4(ip) {
		return "", fmt.Sprintf("LAN 인터페이스(%s) 대역 밖의 주소는 ARP 기록을 조회할 수 없습니다", lanIface.Name)
	}

	// 1. Check existing kernel neighbor table (Netlink RTM_GETNEIGH)
	if st, mac, ok := lookupNeighborNetlink(lanIface.Index, ip); ok && mac != "" {
		return mac, ""
	} else if ok && (st&(unix.NUD_FAILED|unix.NUD_INCOMPLETE) != 0) {
		// Try triggering once in case host just came online.
	}

	// 2. Fallback check /proc/net/arp
	if mac := lookupProcARPMAC(lanIface.Name, ip); mac != "" {
		return mac, ""
	}

	// 3. Trigger a quick ARP resolution (raw ARP if root, else UDP probe) and re-check
	if found, err := rawARPQuery(ctx, lanIface, []netip.Addr{ip}, 250*time.Millisecond, true); err == nil {
		if mac, ok := found[ip]; ok && mac != "" {
			return mac, ""
		}
	} else {
		triggerKernelARP(ip)
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
		if _, mac, ok := lookupNeighborNetlink(lanIface.Index, ip); ok && mac != "" {
			return mac, ""
		}
		if mac := lookupProcARPMAC(lanIface.Name, ip); mac != "" {
			return mac, ""
		}
	}

	return "", "시스템 ARP 기록에서 MAC을 찾지 못했습니다 (기기가 잠들어 있거나 아직 통신 기록이 없음)"
}

func (SystemChecker) ScanSubnet(ctx context.Context, lanIface netutil.InterfaceInfo) ([]DiscoveredHost, error) {
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
	found, err := rawARPQuery(ctx, lanIface, targets, 750*time.Millisecond, false)
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
	prefix, ok := lanIface.PrimaryPrefix()
	if !ok {
		return nil, fmt.Errorf("인터페이스 %s에 IPv4 주소가 없습니다", lanIface.Name)
	}
	if len(lanIface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("인터페이스 %s에 유효한 이더넷 MAC 주소가 없습니다", lanIface.Name)
	}
	srcIP := prefix.Addr()

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
		if ip == srcIP {
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
		if targetIP == srcIP {
			continue
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
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

func lookupNeighborNetlink(ifIndex int, targetIP netip.Addr) (state uint16, mac string, found bool) {
	rib, err := syscall.NetlinkRIB(unix.RTM_GETNEIGH, unix.AF_INET)
	if err != nil {
		return 0, "", false
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return 0, "", false
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
			return ndm.State, llAddr, true
		}
	}
	return 0, "", false
}

func lookupProcARPMAC(ifaceName string, targetIP netip.Addr) string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer f.Close()
	for _, e := range ParseProcARP(f) {
		if e.IP == targetIP && (ifaceName == "" || e.Device == ifaceName) && e.MAC != "" && e.Flags != 0 {
			return e.MAC
		}
	}
	return ""
}

func triggerKernelARP(ip netip.Addr) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.IP(ip.AsSlice()),
		Port: 9,
	})
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	_, _ = conn.Write([]byte{0})
}
