package socks5

import (
	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/session"
)

type SOCKSManager = Manager
type SOCKSSnapshot = Snapshot

func NewSOCKSManager(cfg *config.KernelConfig) (*Manager, error) {
	return New(cfg)
}

func NewManager(cfg *config.KernelConfig) (*Manager, error) {
	return New(cfg)
}

func NewWithBootstrap(cfg *config.KernelConfig, connection *session.ConnectionManager, connectIP *session.ConnectIPSessionManager, delegate session.HTTPStreamDialer) (*Manager, error) {
	manager, err := New(cfg)
	if err != nil {
		return nil, err
	}
	if err := BindBootstrap(manager, connection, connectIP, delegate); err != nil {
		return nil, err
	}
	return manager, nil
}

func BindBootstrap(manager *Manager, connection *session.ConnectionManager, connectIP *session.ConnectIPSessionManager, delegate session.HTTPStreamDialer) error {
	dialer, err := session.NewBootstrapDialer(connection, connectIP, delegate)
	if err != nil {
		return err
	}
	manager.SetStreamManager(dialer.StreamManager())
	return nil
}
