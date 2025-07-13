package hysteria2

import (
	"context"
	"github.com/sagernet/sing-box/protocol/tuic"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.Hysteria2OutboundOptions](registry, C.TypeHysteria2, NewOutbound)
}

var (
	_ adapter.Outbound                = (*tuic.Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*tuic.Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	logger    logger.ContextLogger
	ctx       context.Context
	clients   map[string]*hysteria2.Client
	cltAccess sync.RWMutex
	options   option.Hysteria2OutboundOptions
	tlsConf   tls.Config
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.Hysteria2OutboundOptions) (adapter.Outbound, error) {
	options.UDPFragmentDefault = true
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewClient(ctx, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	var salamanderPassword string
	if options.Obfs != nil {
		if options.Obfs.Password == "" {
			return nil, E.New("missing obfs password")
		}
		switch options.Obfs.Type {
		case hysteria2.ObfsTypeSalamander:
			salamanderPassword = options.Obfs.Password
		default:
			return nil, E.New("unknown obfs type: ", options.Obfs.Type)
		}
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	networkList := options.Network.Build()
	client, err := hysteria2.NewClient(hysteria2.ClientOptions{
		Context:            ctx,
		Dialer:             outboundDialer,
		Logger:             logger,
		BrutalDebug:        options.BrutalDebug,
		ServerAddress:      options.ServerOptions.Build(),
		ServerPorts:        options.ServerPorts,
		HopInterval:        time.Duration(options.HopInterval),
		SendBPS:            uint64(options.UpMbps * hysteria.MbpsToBps),
		ReceiveBPS:         uint64(options.DownMbps * hysteria.MbpsToBps),
		SalamanderPassword: salamanderPassword,
		Password:           options.Password,
		TLSConfig:          tlsConfig,
		UDPDisabled:        false,
	})
	if err != nil {
		return nil, err
	}

	H := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeHysteria2, tag, networkList, options.DialerOptions),
		logger:  logger,
		ctx:     ctx,
		clients: map[string]*hysteria2.Client{"": client},
		options: options,
		tlsConf: tlsConfig,
	}

	go H.watchClients()

	return H, nil
}

func (h *Outbound) watchClients() {
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

func (h *Outbound) filterClients(forceClose bool, err error) {
	for addr, client := range h.clients {
		if client.IdleTime() >= C.ClientIdleTimeout || forceClose {
			_ = client.CloseWithError(err)
			delete(h.clients, addr)
			if err.Error() == "client idle limit reached" {
				h.logger.Info("Closed client for ", addr, " with err ", err)
			} else {
				h.logger.Error("Closed client for ", addr, " with err ", err)
			}
		}
	}
}

func (h *Outbound) getClientForIP(ip string) (*hysteria2.Client, error) {
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

func (h *Outbound) createClient() (*hysteria2.Client, error) {
	outboundDialer, err := dialer.New(h.ctx, h.options.DialerOptions, h.options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	return hysteria2.NewClient(hysteria2.ClientOptions{
		Context:            h.ctx,
		Dialer:             outboundDialer,
		Logger:             h.logger,
		BrutalDebug:        h.options.BrutalDebug,
		ServerAddress:      h.options.ServerOptions.Build(),
		ServerPorts:        h.options.ServerPorts,
		HopInterval:        time.Duration(h.options.HopInterval),
		SendBPS:            uint64(h.options.UpMbps * hysteria.MbpsToBps),
		ReceiveBPS:         uint64(h.options.DownMbps * hysteria.MbpsToBps),
		SalamanderPassword: h.options.Obfs.Password,
		Password:           h.options.Password,
		TLSConfig:          h.tlsConf,
		UDPDisabled:        false,
	})

}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		metadata := adapter.ContextFrom(ctx)
		var srcAddr string
		if metadata != nil {
			srcAddr = metadata.Source.IPAddr().String()
		}
		client, err := h.getClientForIP(srcAddr)
		if err != nil {
			return nil, err
		}
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return client.DialConn(ctx, destination)
	case N.NetworkUDP:
		conn, err := h.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, destination), nil
	default:
		return nil, E.New("unsupported network: ", network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	metadata := adapter.ContextFrom(ctx)
	var srcAddr string
	if metadata != nil {
		srcAddr = metadata.Source.IPAddr().String()
	}
	client, err := h.getClientForIP(srcAddr)
	if err != nil {
		return nil, err
	}
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return client.ListenPacket(ctx)
}

func (h *Outbound) InterfaceUpdated() {
	h.cltAccess.Lock()
	defer h.cltAccess.Unlock()
	h.filterClients(true, E.New("network changed"))
}

func (h *Outbound) Close() error {
	h.cltAccess.Lock()
	defer h.cltAccess.Unlock()
	h.filterClients(true, os.ErrClosed)
	return nil
}
