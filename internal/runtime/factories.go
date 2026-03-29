package runtime

import (
	"net"

	"github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/session"
)

func NewHTTPRuntimeFromConfig(cfg config.KernelConfig) (*HTTPRuntime, error) {
	manager, err := NewHTTPManager(cfg)
	if err != nil {
		return nil, err
	}
	return NewHTTPRuntime(manager), nil
}

func NewHTTPRuntimeFromBootstrap(cfg config.KernelConfig, connectionManager *session.ConnectionManager, connectIPManager *session.ConnectIPSessionManager, delegate *net.Dialer) (*HTTPRuntime, error) {
	manager, err := NewHTTPManager(cfg)
	if err != nil {
		return nil, err
	}
	dialer, err := session.NewBootstrapDialer(connectionManager, connectIPManager, delegate)
	if err != nil {
		return nil, err
	}
	manager.SetStreamManager(session.NewPreparedProxyStreamOpener(dialer, dialer.StreamManager()))
	packetDialer, err := session.NewPacketStackDialer(dialer)
	if err != nil {
		return nil, err
	}
	if cfg.HTTP.UpstreamAddress != "" {
		manager.SetHTTPDialer(newUpstreamConnectDialer(packetDialer, cfg.HTTP.UpstreamAddress))
		manager.SetHTTPRoundTripper(newUpstreamHTTPTransport(cfg.HTTP.UpstreamAddress, packetDialer))
	} else {
		manager.SetHTTPDialer(newDNSResolvingDialer(packetDialer))
	}
	return NewHTTPRuntime(manager), nil
}

// NewHTTPRuntimeFromSharedDialer wires an HTTP runtime using a pre-built shared dialer.
func NewHTTPRuntimeFromSharedDialer(cfg config.KernelConfig, d contextDialer, streamMgr HTTPConnectStreamOpener) (*HTTPRuntime, error) {
	manager, err := NewHTTPManager(cfg)
	if err != nil {
		return nil, err
	}
	manager.SetHTTPDialer(d)
	manager.SetStreamManager(streamMgr)
	return NewHTTPRuntime(manager), nil
}

// NewSOCKS5RuntimeFromSharedDialer wires a SOCKS5 runtime using a pre-built shared dialer.
func NewSOCKS5RuntimeFromSharedDialer(cfg *config.KernelConfig, d contextDialer) (*SOCKS5Runtime, error) {
	manager, err := NewSOCKS5Manager(cfg)
	if err != nil {
		return nil, err
	}
	manager.SetDialer(d)
	return NewSOCKS5Runtime(manager), nil
}

func NewSOCKS5RuntimeFromConfig(cfg *config.KernelConfig) (*SOCKS5Runtime, error) {
	manager, err := NewSOCKS5Manager(cfg)
	if err != nil {
		return nil, err
	}
	return NewSOCKS5Runtime(manager), nil
}

func NewSOCKS5RuntimeFromBootstrap(cfg *config.KernelConfig, connectionManager *session.ConnectionManager, connectIPManager *session.ConnectIPSessionManager, delegate *net.Dialer) (*SOCKS5Runtime, error) {
	manager, err := NewSOCKS5Manager(cfg)
	if err != nil {
		return nil, err
	}
	dialer, err := session.NewBootstrapDialer(connectionManager, connectIPManager, delegate)
	if err != nil {
		return nil, err
	}
	packetDialer, err := session.NewPacketStackDialer(dialer)
	if err != nil {
		return nil, err
	}
	manager.SetDialer(newDNSResolvingDialer(packetDialer))
	return NewSOCKS5Runtime(manager), nil
}

func NewTUNRuntimeFromConfig(cfg *config.KernelConfig) (*TUNRuntime, error) {
	runtime, err := NewTunManager(cfg)
	if err != nil {
		return nil, err
	}
	return NewTUNRuntime(runtime), nil
}

func NewTUNRuntimeFromBootstrap(cfg *config.KernelConfig, connectionManager *session.ConnectionManager, connectIPManager *session.ConnectIPSessionManager, delegate *net.Dialer) (*TUNRuntime, error) {
	bootstrap, err := session.NewBootstrapDialer(connectionManager, connectIPManager, delegate)
	if err != nil {
		return nil, err
	}
	manager, err := NewBootstrapTUNManager(cfg, bootstrap)
	if err != nil {
		return nil, err
	}
	return NewTUNRuntimeWithHealth(manager, bootstrap.HealthCheck), nil
}
