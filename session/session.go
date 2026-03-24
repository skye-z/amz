package session

import (
	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
)

const (
	ProtocolConnectIP     = kernel.ProtocolConnectIP
	ProtocolConnectStream = kernel.ProtocolConnectStream
	ConnStateIdle         = kernel.ConnStateIdle
	ConnStateConnecting   = kernel.ConnStateConnecting
	ConnStateReady        = kernel.ConnStateReady
	SessionStateIdle      = kernel.SessionStateIdle
	SessionStateReady     = kernel.SessionStateReady
	StreamStateIdle       = kernel.StreamStateIdle
	StreamStateReady      = kernel.StreamStateReady
)

type QUICOptions = kernel.QUICOptions
type HTTP3Options = kernel.HTTP3Options
type ConnectionSnapshot = kernel.ConnectionSnapshot
type ConnectionManager = kernel.ConnectionManager
type ConnectStreamOptions = kernel.ConnectStreamOptions
type ConnectStreamSnapshot = kernel.ConnectStreamSnapshot
type StreamInfo = kernel.StreamInfo
type ConnectStreamManager = kernel.ConnectStreamManager
type StreamRelayEndpoint = kernel.StreamRelayEndpoint
type ConnectIPOptions = kernel.ConnectIPOptions
type ConnectIPSnapshot = kernel.ConnectIPSnapshot
type SessionInfo = kernel.SessionInfo
type ConnectIPSessionManager = kernel.ConnectIPSessionManager
type RetryPolicy = kernel.RetryPolicy
type ConnectionEvent = kernel.ConnectionEvent
type KeepaliveManager = kernel.KeepaliveManager
type CoreTunnelDialer = kernel.CoreTunnelDialer

func BuildQUICOptions(cfg config.KernelConfig) (QUICOptions, error) {
	return kernel.BuildQUICOptions(cfg)
}

func BuildHTTP3Options(quic QUICOptions) HTTP3Options {
	return kernel.BuildHTTP3Options(quic)
}

func BuildConnectStreamOptions(h3 HTTP3Options, targetHost, targetPort string) ConnectStreamOptions {
	return kernel.BuildConnectStreamOptions(h3, targetHost, targetPort)
}

func BuildConnectIPOptions(h3 HTTP3Options) ConnectIPOptions {
	return kernel.BuildConnectIPOptions(h3)
}

func NewConnectionManager(cfg config.KernelConfig) (*ConnectionManager, error) {
	return kernel.NewConnectionManager(cfg)
}

func NewConnectStreamManager(cfg config.KernelConfig) (*ConnectStreamManager, error) {
	return kernel.NewConnectStreamManager(cfg)
}

func NewConnectIPSessionManager(cfg config.KernelConfig) (*ConnectIPSessionManager, error) {
	return kernel.NewConnectIPSessionManager(cfg)
}

func NewKeepaliveManager(policy RetryPolicy) *KeepaliveManager {
	return kernel.NewKeepaliveManager(policy)
}

func NewBootstrapDialer(connection *ConnectionManager, session *ConnectIPSessionManager, delegate kernel.HTTPStreamDialer) (*CoreTunnelDialer, error) {
	return kernel.NewCoreTunnelDialer(connection, session, delegate)
}
