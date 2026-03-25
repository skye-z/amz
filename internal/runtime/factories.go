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
	manager.SetHTTPDialer(dialer)
	manager.SetStreamManager(dialer.StreamManager())
	return NewHTTPRuntime(manager), nil
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
	manager.SetStreamManager(dialer.StreamManager())
	return NewSOCKS5Runtime(manager), nil
}

func NewTUNRuntimeFromConfig(cfg *config.KernelConfig) (*TUNRuntime, error) {
	runtime, err := NewTunManager(cfg)
	if err != nil {
		return nil, err
	}
	return NewTUNRuntime(runtime), nil
}
