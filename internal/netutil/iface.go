package netutil

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// InterfaceInfo holds network interface metadata and IPv4 prefixes.
type InterfaceInfo struct {
	Name         string
	Index        int
	HardwareAddr net.HardwareAddr
	Prefixes     []netip.Prefix // host IPv4 address + subnet mask bits
	Loopback     bool
	Up           bool
}

// IPv4Addrs returns the interface's IPv4 host addresses in order.
func (info InterfaceInfo) IPv4Addrs() []netip.Addr {
	addrs := make([]netip.Addr, 0, len(info.Prefixes))
	for _, p := range info.Prefixes {
		if p.Addr().Is4() {
			addrs = append(addrs, p.Addr())
		}
	}
	return addrs
}

// PrimaryPrefix returns the first IPv4 prefix on the interface, if any.
func (info InterfaceInfo) PrimaryPrefix() (netip.Prefix, bool) {
	for _, p := range info.Prefixes {
		if p.Addr().Is4() {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

// ContainsIPv4 reports whether any IPv4 subnet on this interface contains addr.
func (info InterfaceInfo) ContainsIPv4(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	for _, p := range info.Prefixes {
		if p.Masked().Contains(addr) {
			return true
		}
	}
	return false
}

// Provider abstracts system network interface lookups so daemon, CLI, and TUI
// can share validation logic and tests can supply deterministic interfaces.
type Provider interface {
	Interfaces() ([]InterfaceInfo, error)
	InterfaceByName(name string) (InterfaceInfo, error)
}

// SystemProvider queries the OS network stack via the standard net package.
type SystemProvider struct{}

func (SystemProvider) Interfaces() ([]InterfaceInfo, error) {
	raw, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]InterfaceInfo, 0, len(raw))
	for _, iface := range raw {
		info, err := convertInterface(iface)
		if err != nil {
			continue
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (SystemProvider) InterfaceByName(name string) (InterfaceInfo, error) {
	if strings.TrimSpace(name) == "" {
		return InterfaceInfo{}, errors.New("인터페이스 이름이 비어 있습니다")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return InterfaceInfo{}, err
	}
	return convertInterface(*iface)
}

func convertInterface(iface net.Interface) (InterfaceInfo, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return InterfaceInfo{}, err
	}
	var prefixes []netip.Prefix
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			ip4 := v.IP.To4()
			if ip4 == nil {
				continue
			}
			ones, bits := v.Mask.Size()
			if bits != 32 || ones < 0 {
				continue
			}
			addr, ok := netip.AddrFromSlice(ip4)
			if !ok {
				continue
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, ones))
		case *net.IPAddr:
			ip4 := v.IP.To4()
			if ip4 == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(ip4)
			if !ok {
				continue
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, 32))
		}
	}
	hwCopy := make(net.HardwareAddr, len(iface.HardwareAddr))
	copy(hwCopy, iface.HardwareAddr)
	return InterfaceInfo{
		Name:         iface.Name,
		Index:        iface.Index,
		HardwareAddr: hwCopy,
		Prefixes:     prefixes,
		Loopback:     iface.Flags&net.FlagLoopback != 0,
		Up:           iface.Flags&net.FlagUp != 0,
	}, nil
}

// StaticProvider is an in-memory Provider for testing.
type StaticProvider struct {
	Items []InterfaceInfo
}

func (s StaticProvider) Interfaces() ([]InterfaceInfo, error) {
	out := make([]InterfaceInfo, len(s.Items))
	copy(out, s.Items)
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (s StaticProvider) InterfaceByName(name string) (InterfaceInfo, error) {
	for _, it := range s.Items {
		if it.Name == name {
			return it, nil
		}
	}
	return InterfaceInfo{}, fmt.Errorf("인터페이스를 찾을 수 없습니다: %s", name)
}

// BroadcastAddr computes the IPv4 directed subnet broadcast address for p.
func BroadcastAddr(p netip.Prefix) (netip.Addr, error) {
	if !p.IsValid() || !p.Addr().Is4() {
		return netip.Addr{}, fmt.Errorf("유효한 IPv4 서브넷이 아닙니다: %v", p)
	}
	raw := p.Addr().As4()
	bits := p.Bits()
	if bits == 32 {
		return p.Addr(), nil
	}
	hostBits := uint(32 - bits)
	ipUint := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
	bcastUint := ipUint | ((uint32(1) << hostBits) - 1)
	return netip.AddrFrom4([4]byte{
		byte(bcastUint >> 24),
		byte(bcastUint >> 16),
		byte(bcastUint >> 8),
		byte(bcastUint),
	}), nil
}

// SubnetHosts returns all usable host IPv4 addresses inside p.
// Caller should ensure p.Bits() >= 22 before scanning large networks.
func SubnetHosts(p netip.Prefix) []netip.Addr {
	if !p.IsValid() || !p.Addr().Is4() {
		return nil
	}
	masked := p.Masked()
	bits := masked.Bits()
	if bits == 32 {
		return []netip.Addr{masked.Addr()}
	}
	raw := masked.Addr().As4()
	start := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
	count := uint32(1) << uint(32-bits)
	if bits == 31 {
		return []netip.Addr{
			uint32ToAddr4(start),
			uint32ToAddr4(start + 1),
		}
	}
	// Standard subnet: skip network address (start) and broadcast address (start+count-1).
	hosts := make([]netip.Addr, 0, count-2)
	for i := uint32(1); i < count-1; i++ {
		hosts = append(hosts, uint32ToAddr4(start+i))
	}
	return hosts
}

func uint32ToAddr4(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	})
}

// ParseIPv4Host parses a single IPv4 host address (rejecting IPv6, 0.0.0.0, multicast, and 255.255.255.255).
func ParseIPv4Host(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("잘못된 IPv4 주소 형식입니다: %q", s)
	}
	if !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("IPv4 주소만 지원합니다: %q", s)
	}
	if addr.IsUnspecified() || addr.IsMulticast() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Addr{}, fmt.Errorf("사용할 수 없는 IPv4 주소입니다: %q", s)
	}
	return addr, nil
}

// ParseIPv4OrCIDR parses an IPv4 CIDR (e.g. 10.66.0.2/32, 10.66.0.0/24) or bare IPv4 (treated as /32).
func ParseIPv4OrCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, errors.New("IP/CIDR 값이 비어 있습니다")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("잘못된 CIDR 형식입니다: %q", s)
		}
		if !p.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("IPv4 CIDR만 지원합니다: %q", s)
		}
		return p.Masked(), nil
	}
	addr, err := ParseIPv4Host(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, 32), nil
}

// NormalizeMAC validates a 6-byte Ethernet MAC address and formats it as lowercase colon-separated hex.
func NormalizeMAC(s string) (string, net.HardwareAddr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil, errors.New("MAC 주소가 비어 있습니다")
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return "", nil, fmt.Errorf("잘못된 6바이트 MAC 주소입니다: %q", s)
	}
	var isAllZero, isBroadcast = true, true
	for _, b := range hw {
		if b != 0x00 {
			isAllZero = false
		}
		if b != 0xff {
			isBroadcast = false
		}
	}
	if isAllZero || isBroadcast {
		return "", nil, fmt.Errorf("사용할 수 없는 MAC 주소입니다: %q", s)
	}
	formatted := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", hw[0], hw[1], hw[2], hw[3], hw[4], hw[5])
	return formatted, hw, nil
}
