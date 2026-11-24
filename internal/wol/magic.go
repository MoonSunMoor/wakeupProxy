package wol

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

const (
	MagicPacketSize = 102
	DefaultWoLPort  = 9
)

// BuildMagicPacket constructs a 102-byte Wake-on-LAN magic packet (6x 0xFF + 16x 6-byte MAC).
func BuildMagicPacket(mac net.HardwareAddr) ([MagicPacketSize]byte, error) {
	var pkt [MagicPacketSize]byte
	if len(mac) != 6 {
		return pkt, fmt.Errorf("잘못된 MAC 길이(%d): 6바이트여야 합니다", len(mac))
	}
	for i := 0; i < 6; i++ {
		pkt[i] = 0xff
	}
	for rep := 0; rep < 16; rep++ {
		copy(pkt[6+rep*6:6+(rep+1)*6], mac)
	}
	return pkt, nil
}

// Sender transmits Wake-on-LAN magic packets.
type Sender interface {
	SendMagicPacket(ctx context.Context, broadcastAddr netip.Addr, mac net.HardwareAddr) error
}

// UDPSender sends magic packets over UDP4 to <broadcastAddr>:9 without interface binding,
// allowing unprivileged execution (`wolproxy wake` and non-root systemd daemon).
type UDPSender struct {
	Port int
}

func (s UDPSender) SendMagicPacket(ctx context.Context, broadcastAddr netip.Addr, mac net.HardwareAddr) error {
	pkt, err := BuildMagicPacket(mac)
	if err != nil {
		return err
	}
	if !broadcastAddr.IsValid() || !broadcastAddr.Is4() {
		return fmt.Errorf("잘못된 IPv4 브로드캐스트 주소입니다: %v", broadcastAddr)
	}
	port := s.Port
	if port <= 0 {
		port = DefaultWoLPort
	}

	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp4", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("UDP 소켓 열기 실패: %w", err)
	}
	defer pc.Close()

	dst, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(broadcastAddr.String(), strconv.Itoa(port)))
	if err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = pc.SetWriteDeadline(deadline)
	}
	n, err := pc.WriteTo(pkt[:], dst)
	if err != nil {
		return fmt.Errorf("매직 패킷 송신 실패(%s): %w", dst.String(), err)
	}
	if n != MagicPacketSize {
		return fmt.Errorf("매직 패킷 일부만 송신됨: %d/%d", n, MagicPacketSize)
	}
	return nil
}
