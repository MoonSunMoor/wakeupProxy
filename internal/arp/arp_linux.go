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
	activeNeighborStates    = unix.NUD_REACHABLE | unix.NUD_DELAY | unix.NUD_PROBE | unix.NUD_PERMANENT
	confirmedNeighborStates = unix.NUD_REACHABLE | unix.NUD_PERMANENT
	arpFlagComplete         = 0x2 // ATF_COM in /proc/net/arp

	defaultNonRootProbeWait = 350 * time.Millisecond
	defaultNonRootProbeStep = 50 * time.Millisecond
)

type rawARPQueryFunc func(ctx context.Context, lanIface netutil.InterfaceInfo, targets []netip.Addr, waitAfterSend time.Duration, stopOnFirst bool) (map[netip.Addr]string, error)
type netlinkLookupFunc func(ifIndex int, targetIP netip.Addr) (state uint16, mac string, found bool, err error)
type procARPLookupFunc func(ifaceName string, targetIP netip.Addr) string
type udpTriggerFunc func(srcIP, targetIP netip.Addr) error

// SystemChecker implements Checker on Linux using AF_PACKET raw ARP (when permitted),
// passive Netlink RTM_GETNEIGH inspection for background checks, and UDP-assisted
// neighbor resolution for explicit non-root wake-wait probes.
type SystemChecker struct {
	rawQuery      rawARPQueryFunc
	netlinkLookup netlinkLookupFunc
	procLookup    procARPLookupFunc
	udpTrigger    udpTriggerFunc
	probeWait     time.Duration
	probeStep     time.Duration
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

func (c SystemChecker) doUDPTrigger(srcIP, targetIP netip.Addr) error {
	if c.udpTrigger != nil {
		return c.udpTrigger(srcIP, targetIP)
	}
	return triggerUDPNeighborProbe(srcIP, targetIP)
}

func isNeighborActive(state uint16) bool {
	return state&activeNeighborStates != 0
}

func isNeighborConfirmed(state uint16) bool {
	return state&confirmedNeighborStates != 0
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
	// passively read kernel neighbor table via Netlink RTM_GETNEIGH only.
	// Never fall back to /proc/net/arp here because NUD_STALE entries still appear as
	// 0x2 (ATF_COM) in /proc/net/arp and would falsely mark sleeping hosts as awake.
	st, _, ok, nlErr := c.doNetlinkLookup(lanIface.Index, ip)
	if nlErr != nil {
		return false, nlErr
	}
	return ok && isNeighborActive(st), nil
}

// ProbeAwake actively checks whether ip is awake during an explicit wake-wait
// (`wolproxy wake --wait` on profile-less targets or TUI `w` waking poll).
// When root / CAP_NET_RAW is available, it uses raw AF_PACKET ARP request/reply.
// When non-root, it first checks RTM_GETNEIGH for NUD_REACHABLE | NUD_PERMANENT;
// otherwise it sends a unicast UDP packet (:9) from the matching LAN source IP to
// trigger kernel ARP resolution and polls RTM_GETNEIGH briefly, accepting ONLY
// NUD_REACHABLE | NUD_PERMANENT so NUD_STALE -> NUD_DELAY -> NUD_PROBE transitions
// never misclassify a sleeping host as awake.
func (c SystemChecker) ProbeAwake(ctx context.Context, lanIface netutil.InterfaceInfo, ip netip.Addr) (bool, error) {
	if !ip.Is4() {
		return false, errors.New("IPv4 주소만 지원합니다")
	}
	if !lanIface.ContainsIPv4(ip) {
		return false, nil
	}

	found, err := c.doRawQuery(ctx, lanIface, []netip.Addr{ip}, 350*time.Millisecond, true)
	if err == nil {
		_, ok := found[ip]
		return ok, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	st, _, ok, nlErr := c.doNetlinkLookup(lanIface.Index, ip)
	if nlErr != nil {
		return false, nlErr
	}
	if ok && isNeighborConfirmed(st) {
		return true, nil
	}

	if srcIP, hasSrc := SelectSourceIP(lanIface, ip); hasSrc {
		_ = c.doUDPTrigger(srcIP, ip)
	}

	waitDur := c.probeWait
	if waitDur <= 0 {
		waitDur = defaultNonRootProbeWait
	}
	stepDur := c.probeStep
	if stepDur <= 0 {
		stepDur = defaultNonRootProbeStep
	}
	if stepDur > waitDur {
		stepDur = waitDur
	}

	deadline := time.Now().Add(waitDur)
	timer := time.NewTimer(stepDur)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-timer.C:
			st, _, ok, nlErr = c.doNetlinkLookup(lanIface.Index, ip)
			if nlErr != nil {
				return false, nlErr
			}
			if ok && isNeighborConfirmed(st) {
				return true, nil
			}
			rem := time.Until(deadline)
			if rem <= 0 {
				return false, nil
			}
			nextStep := stepDur
			if rem < nextStep {
				nextStep = rem
			}
			timer.Reset(nextStep)
		}
	}
}

func triggerUDPNeighborProbe(srcIP, targetIP netip.Addr) error {
	var localAddr *net.UDPAddr
	if srcIP.IsValid() && srcIP.Is4() {
		localAddr = &net.UDPAddr{
			IP:   net.IP(srcIP.AsSlice()),
			Port: 0,
		}
	}
	remoteAddr := &net.UDPAddr{
		IP:   net.IP(targetIP.AsSlice()),
		Port: 9,
	}
	conn, err := net.DialUDP("udp4", localAddr, remoteAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte{0})
	return err
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
	if c.rawQuery == nil && os.Geteuid() != 0 {
		return nil, ErrRootRequired
	}
	targets, err := CollectScanTargets(lanIface)
	if err != nil {
		return nil, err
	}

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
