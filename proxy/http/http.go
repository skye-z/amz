package httpproxy

import (
	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/session"
)

type HTTPProxyManager = Manager
type HTTPSnapshot = Snapshot
type HTTPStreamDialer = StreamDialer

func NewHTTPProxyManager(cfg config.KernelConfig) (*Manager, error) {
	return New(cfg)
}

func NewManager(cfg config.KernelConfig) (*Manager, error) {
	return New(cfg)
}

func NewWithBootstrap(cfg config.KernelConfig, connection *session.ConnectionManager, connectIP *session.ConnectIPSessionManager, delegate StreamDialer) (*Manager, error) {
	manager, err := New(cfg)
	if err != nil {
		return nil, err
	}
	dialer, err := session.NewBootstrapDialer(connection, connectIP, delegate)
	if err != nil {
		return nil, err
	}
	manager.SetHTTPDialer(dialer)
	manager.SetStreamManager(dialer.StreamManager())
	return manager, nil
}

func BindBootstrap(manager *Manager, connection *session.ConnectionManager, connectIP *session.ConnectIPSessionManager, delegate StreamDialer) error {
	dialer, err := session.NewBootstrapDialer(connection, connectIP, delegate)
	if err != nil {
		return err
	}
	manager.SetHTTPDialer(dialer)
	manager.SetStreamManager(dialer.StreamManager())
	return nil
}
