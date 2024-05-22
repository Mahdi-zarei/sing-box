package dialer

import (
	"context"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/timeout"
	"net"
)

type TimeoutDialer struct {
	N.Dialer
}

func NewTimeoutDialer(dialer N.Dialer) *TimeoutDialer {
	return &TimeoutDialer{dialer}
}

func (t *TimeoutDialer) DialContext(ctx context.Context, network string, destination metadata.Socksaddr) (net.Conn, error) {
	conn, err := t.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}

	return timeout.NewNetConnWithTimeout(conn, C.TCPIdleTimeout), nil
}

func (t *TimeoutDialer) ListenPacket(ctx context.Context, destination metadata.Socksaddr) (net.PacketConn, error) {
	packetConn, err := t.Dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}

	return timeout.NewNetPacketConnWithTimeout(packetConn, C.UDPTimeout), nil
}
