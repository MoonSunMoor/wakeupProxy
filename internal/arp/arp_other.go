//go:build !linux

package arp

import (
	"context"
	"errors"
	"net/netip"

	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
)

// SystemChecker is a non-Linux fallback stub so builds and cross-platform unit tests compile cleanly.
type SystemChecker struct{}

func NewSystemChecker() Checker {
	return SystemChecker{}
}

func (SystemChecker) IsAwake(_ context.Context, _ netutil.InterfaceInfo, _ netip.Addr) (bool, error) {
	return false, errors.New("ARP 조회는 Linux에서만 지원됩니다")
}

func (SystemChecker) LookupMAC(_ context.Context, _ netutil.InterfaceInfo, _ netip.Addr) (string, string) {
	return "", "ARP 기록 조회는 Linux에서만 지원됩니다"
}

func (SystemChecker) ScanSubnet(_ context.Context, lanIface netutil.InterfaceInfo) ([]DiscoveredHost, error) {
	if p, ok := lanIface.PrimaryPrefix(); ok && p.Bits() < MaxScanPrefixBits {
		return nil, ErrSubnetTooLarge
	}
	return nil, errors.New("LAN ARP 검색은 Linux root 환경에서만 지원됩니다")
}
