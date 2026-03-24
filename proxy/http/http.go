package httpproxy

import (
	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
	"github.com/skye-z/amz/session"
)

type StreamDialer = kernel.HTTPStreamDialer
type Snapshot = kernel.HTTPSnapshot
type Manager = kernel.HTTPProxyManager

func NewManager(cfg config.KernelConfig) (*Manager, error) {
	return kernel.NewHTTPProxyManager(cfg)
}

func NewWithBootstrap(cfg config.KernelConfig, connection *session.ConnectionManager, connectIP *session.ConnectIPSessionManager, delegate StreamDialer) (*Manager, error) {
	manager, err := kernel.NewHTTPProxyManager(cfg)
	if err != nil {
		return nil, err
	}
	if err := manager.SetCoreTunnelDialer(connection, connectIP, delegate); err != nil {
		return nil, err
	}
	return manager, nil
}
