//go:build with_quic

package outbound

import (
	"context"
	"github.com/sagernet/sing-box/common/badmap"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"

	"github.com/gofrs/uuid/v5"
)

var (
	_ adapter.Outbound                = (*TUIC)(nil)
	_ adapter.InterfaceUpdateListener = (*TUIC)(nil)
)

type TUIC struct {
	myOutboundAdapter
	ctx            context.Context
	udpStream      bool
	clients        map[string]*tuic.Client
	mapDeleteCount int32
	cltAccess      sync.RWMutex
	options        option.TUICOutboundOptions
	uuid           uuid.UUID
	tlsConf        tls.Config
	udpStreamMode  bool
	uos            bool
}

func NewTUIC(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TUICOutboundOptions) (*TUIC, error) {
	options.UDPFragmentDefault = true
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewClient(ctx, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	userUUID, err := uuid.FromString(options.UUID)
	if err != nil {
		return nil, E.Cause(err, "invalid uuid")
	}
	var tuicUDPStream bool
	if options.UDPOverStream && options.UDPRelayMode != "" {
		return nil, E.New("udp_over_stream is conflict with udp_relay_mode")
	}
	switch options.UDPRelayMode {
	case "native":
	case "quic":
		tuicUDPStream = true
	}
	outboundDialer, err := dialer.New(router, options.DialerOptions)
	if err != nil {
		return nil, err
	}
	client, err := tuic.NewClient(tuic.ClientOptions{
		Context:           ctx,
		Dialer:            outboundDialer,
		ServerAddress:     options.ServerOptions.Build(),
		TLSConfig:         tlsConfig,
		UUID:              userUUID,
		Password:          options.Password,
		CongestionControl: options.CongestionControl,
		UDPStream:         tuicUDPStream,
		ZeroRTTHandshake:  options.ZeroRTTHandshake,
		Heartbeat:         time.Duration(options.Heartbeat),
	})
	if err != nil {
		return nil, err
	}
	T := &TUIC{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeTUIC,
			network:      options.Network.Build(),
			router:       router,
			logger:       logger,
			tag:          tag,
			dependencies: withDialerDependency(options.DialerOptions),
		},
		ctx:           ctx,
		clients:       map[string]*tuic.Client{"": client},
		options:       options,
		uuid:          userUUID,
		tlsConf:       tlsConfig,
		udpStreamMode: tuicUDPStream,
		uos:           options.UDPOverStream,
	}

	go T.watchClients()

	return T, nil
}

func (h *TUIC) watchClients() {
	ticker := time.NewTicker(1 * time.Minute)
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.cltAccess.Lock()
			h.filterClients(false, E.New("client idle limit reached"))
			h.cltAccess.Unlock()
		}
	}
}

func (h *TUIC) filterClients(forceClose bool, err error) {
	for addr, client := range h.clients {
		if client.IdleTime() >= C.ClientIdleTimeout || forceClose {
			_ = client.CloseWithError(err)
			delete(h.clients, addr)
			h.mapDeleteCount++
			h.logger.Warn("Closed client for ", addr, " with err ", err)
		}
	}
	if h.mapDeleteCount >= badmap.DeleteThreshold {
		h.mapDeleteCount = 0
		h.clients = badmap.GetCleanMap(h.clients)
	}
}

func (h *TUIC) getClientForIP(ip string) (*tuic.Client, error) {
	h.cltAccess.RLock()
	client, ok := h.clients[ip]
	h.cltAccess.RUnlock()
	if ok {
		return client, nil
	}

	h.cltAccess.Lock()
	defer h.cltAccess.Unlock()
	client, ok = h.clients[ip]
	if ok {
		return client, nil
	}

	client, err := h.createClient()
	if err != nil {
		return nil, err
	}
	h.clients[ip] = client

	return client, nil
}

func (h *TUIC) createClient() (*tuic.Client, error) {
	outboundDialer, err := dialer.New(h.router, h.options.DialerOptions)
	if err != nil {
		return nil, err
	}
	return tuic.NewClient(tuic.ClientOptions{
		Context:           h.ctx,
		Dialer:            outboundDialer,
		ServerAddress:     h.options.ServerOptions.Build(),
		TLSConfig:         h.tlsConf,
		UUID:              h.uuid,
		Password:          h.options.Password,
		CongestionControl: h.options.CongestionControl,
		UDPStream:         h.udpStreamMode,
		ZeroRTTHandshake:  h.options.ZeroRTTHandshake,
		Heartbeat:         time.Duration(h.options.Heartbeat),
	})
}

func (h *TUIC) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	metadata := adapter.ContextFrom(ctx)
	var srcAddr string
	if metadata != nil {
		srcAddr = metadata.Source.IPAddr().String()
	}
	client, err := h.getClientForIP(srcAddr)
	if err != nil {
		return nil, err
	}

	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return client.DialConn(ctx, destination)
	case N.NetworkUDP:
		if h.udpStream {
			h.logger.InfoContext(ctx, "outbound stream packet connection to ", destination)
			streamConn, err := client.DialConn(ctx, uot.RequestDestination(uot.Version))
			if err != nil {
				return nil, err
			}
			return uot.NewLazyConn(streamConn, uot.Request{
				IsConnect:   true,
				Destination: destination,
			}), nil
		} else {
			conn, err := h.ListenPacket(ctx, destination)
			if err != nil {
				return nil, err
			}
			return bufio.NewBindPacketConn(conn, destination), nil
		}
	default:
		return nil, E.New("unsupported network: ", network)
	}
}

func (h *TUIC) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	metadata := adapter.ContextFrom(ctx)
	var srcAddr string
	if metadata != nil {
		srcAddr = metadata.Source.IPAddr().String()
	}
	client, err := h.getClientForIP(srcAddr)
	if err != nil {
		return nil, err
	}

	if h.uos {
		h.logger.InfoContext(ctx, "outbound stream packet connection to ", destination)
		streamConn, err := client.DialConn(ctx, uot.RequestDestination(uot.Version))
		if err != nil {
			return nil, err
		}
		return uot.NewLazyConn(streamConn, uot.Request{
			IsConnect:   false,
			Destination: destination,
		}), nil
	} else {
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		return client.ListenPacket(ctx)
	}
}

func (h *TUIC) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return NewConnection(ctx, h, conn, metadata)
}

func (h *TUIC) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return NewPacketConnection(ctx, h, conn, metadata)
}

func (h *TUIC) InterfaceUpdated() {
	h.cltAccess.Lock()
	defer h.cltAccess.Unlock()
	h.filterClients(true, E.New("network changed"))
}

func (h *TUIC) Close() error {
	h.cltAccess.Lock()
	defer h.cltAccess.Unlock()
	h.filterClients(true, os.ErrClosed)
	return nil
}
