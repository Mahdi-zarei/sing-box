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
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.Outbound = (*Trojan)(nil)

type Trojan struct {
	myOutboundAdapter
	ctx            context.Context
	dialer         N.Dialer
	serverAddr     M.Socksaddr
	options        option.TrojanOutboundOptions
	key            [56]byte
	muxClients     map[string]*mux.Client
	mapDeleteCount int32
	muxAccess      sync.RWMutex
	muxEnabled     bool
	tlsConfig      tls.Config
	transport      adapter.V2RayClientTransport
}

func NewTrojan(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrojanOutboundOptions) (*Trojan, error) {
	outboundDialer, err := dialer.New(router, options.DialerOptions)
	if err != nil {
		return nil, err
	}
	outbound := &Trojan{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeTrojan,
			network:      options.Network.Build(),
			router:       router,
			logger:       logger,
			tag:          tag,
			dependencies: withDialerDependency(options.DialerOptions),
		},
		ctx:        ctx,
		dialer:     outboundDialer,
		options:    options,
		serverAddr: options.ServerOptions.Build(),
		key:        trojan.Key(options.Password),
		muxClients: make(map[string]*mux.Client),
		muxEnabled: !(options.Multiplex == nil),
	}
	if options.TLS != nil {
		outbound.tlsConfig, err = tls.NewClient(ctx, options.Server, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
	}
	if options.Transport != nil {
		outbound.transport, err = v2ray.NewClientTransport(ctx, outbound.dialer, outbound.serverAddr, common.PtrValueOrDefault(options.Transport), outbound.tlsConfig)
		if err != nil {
			return nil, E.Cause(err, "create client transport: ", options.Transport.Type)
		}
	}
	if options.Multiplex != nil {
		defaultMuxClt, err := mux.NewClientWithOptions((*trojanDialer)(outbound), logger, *options.Multiplex)
		if err != nil {
			return nil, err
		}
		outbound.muxClients[""] = defaultMuxClt
	}

	go outbound.watchForIdleMuxClients()

	return outbound, nil
}

func (h *Trojan) watchForIdleMuxClients() {
	ticker := time.NewTicker(1 * time.Minute)
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.muxAccess.Lock()
			h.filterMuxClients(false, E.New("client idle limit reached"))
			h.muxAccess.Unlock()
		}
	}
}

func (h *Trojan) filterMuxClients(forceClose bool, err error) {
	for addr, client := range h.muxClients {
		if client.GetClientIdleTime() >= C.ClientIdleTimeout || forceClose {
			_ = client.Close()
			delete(h.muxClients, addr)
			h.mapDeleteCount++
			h.logger.Warn("Closed mux client for ", addr, " with err \n", err)
		}
	}
	if h.mapDeleteCount >= badmap.DeleteThreshold {
		h.mapDeleteCount = 0
		h.muxClients = badmap.GetCleanMap(h.muxClients)
	}
}

func (h *Trojan) getMuxClientForIP(ip string) (*mux.Client, error) {
	h.muxAccess.RLock()
	client, ok := h.muxClients[ip]
	h.muxAccess.RUnlock()
	if ok {
		return client, nil
	}

	h.muxAccess.Lock()
	defer h.muxAccess.Unlock()
	client, ok = h.muxClients[ip]
	if ok {
		return client, nil
	}

	client, err := h.createMuxClient()
	if err != nil {
		return nil, err
	}

	h.muxClients[ip] = client
	return client, nil
}

func (h *Trojan) createMuxClient() (*mux.Client, error) {
	return mux.NewClientWithOptions((*trojanDialer)(h), h.logger, *h.options.Multiplex)
}

func (h *Trojan) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !h.muxEnabled {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound connection to ", destination)
		case N.NetworkUDP:
			h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		}
		return (*trojanDialer)(h).DialContext(ctx, network, destination)
	} else {
		metadata := adapter.ContextFrom(ctx)
		var srcAddr string
		if metadata != nil {
			srcAddr = metadata.Source.IPAddr().String()
		}
		client, err := h.getMuxClientForIP(srcAddr)
		if err != nil {
			return nil, err
		}
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound multiplex connection to ", destination)
		case N.NetworkUDP:
			h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		}
		return client.DialContext(ctx, network, destination)
	}
}

func (h *Trojan) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !h.muxEnabled {
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		return (*trojanDialer)(h).ListenPacket(ctx, destination)
	} else {
		metadata := adapter.ContextFrom(ctx)
		var srcAddr string
		if metadata != nil {
			srcAddr = metadata.Source.IPAddr().String()
		}
		client, err := h.getMuxClientForIP(srcAddr)
		if err != nil {
			return nil, err
		}
		h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		return client.ListenPacket(ctx, destination)
	}
}

func (h *Trojan) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return NewConnection(ctx, h, conn, metadata)
}

func (h *Trojan) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return NewPacketConnection(ctx, h, conn, metadata)
}

func (h *Trojan) InterfaceUpdated() {
	if h.transport != nil {
		h.transport.Close()
	}
	h.muxAccess.Lock()
	defer h.muxAccess.Unlock()
	h.filterMuxClients(true, E.New("network changed"))
	return
}

func (h *Trojan) Close() error {
	h.muxAccess.Lock()
	defer h.muxAccess.Unlock()
	h.filterMuxClients(true, os.ErrClosed)
	return common.Close(h.transport)
}

type trojanDialer Trojan

func (h *trojanDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.AppendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	var conn net.Conn
	var err error
	if h.transport != nil {
		conn, err = h.transport.DialContext(ctx)
	} else {
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err == nil && h.tlsConfig != nil {
			conn, err = tls.ClientHandshake(ctx, conn, h.tlsConfig)
		}
	}
	if err != nil {
		common.Close(conn)
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return trojan.NewClientConn(conn, h.key, destination), nil
	case N.NetworkUDP:
		return bufio.NewBindPacketConn(trojan.NewClientPacketConn(conn, h.key), destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *trojanDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := h.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, err
	}
	return conn.(net.PacketConn), nil
}
